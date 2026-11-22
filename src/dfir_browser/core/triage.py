from __future__ import annotations

import logging
import os
import stat
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .audit import get_correlation_id
from .config import Settings
from .errors import DFIRError
from .filesystem import FilesystemService
from .indexer import FilesystemIndexer
from .index_models import EntryNotFoundError
from .policy import SecurityPolicy
from .triage_analyzers import (
    AnalyzerDeadline,
    derive_findings,
    entropy_analysis,
    hash_file,
    remaining,
    run_exiftool,
    run_file_identification,
    run_pe,
    run_yara,
    scan_strings,
)
from .triage_models import (
    AnalyzerResult,
    TriageError,
    TriageJob,
    TriageNotFoundError,
    TriageQueueFullError,
    TriageRejectedError,
    TriageStringsPage,
    utc_now_iso,
)
from .triage_store import TriageStore, new_job_id

logger = logging.getLogger("dfir_browser.triage")

PHASE_TIMEOUT_ERROR = "triage job deadline exceeded"
MAX_FINDINGS_RETURNED = 200


class FileTriageService:
    def __init__(
        self,
        *,
        settings: Settings,
        policy: SecurityPolicy,
        filesystem: FilesystemService,
        evidence,
        indexer: FilesystemIndexer,
        audit,
        store: TriageStore,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.audit = audit
        self.store = store
        self._lock = threading.Lock()
        self._futures: dict[str, Future[None]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(settings.triage_max_concurrent_jobs)),
            thread_name_prefix="dfir-triage",
        )
        self.store.ensure_schema()
        interrupted = self.store.recover_interrupted()
        if interrupted:
            logger.warning(
                "marked %s triage job(s) interrupted after restart", interrupted
            )

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def _active_count(self) -> int:
        return int(self.store.counts()["active"])

    def start(
        self,
        record,
        entry_id: int,
        *,
        case_id: str = "case01",
        force: bool = False,
    ) -> TriageJob:
        case_id = self.policy.validate_case_id(case_id)
        entry = self.indexer.tree_entry(record, entry_id)
        if entry.entry_type != "file":
            raise TriageRejectedError(
                "static triage only accepts files, not directories",
                code="triage_directory_rejected",
                details={"entry_id": entry.id},
            )
        limit = (
            max(1, int(self.settings.triage_max_concurrent_jobs))
            + max(0, int(self.settings.triage_max_queued_jobs))
        )
        with self._lock:
            if self._active_count() >= limit:
                raise TriageQueueFullError(
                    "too many triage jobs are queued or running",
                    code="triage_queue_full",
                    details={"limit": limit},
                )
            job = TriageJob(
                job_id=new_job_id(),
                evidence_id=record.evidence_id,
                entry_id=entry.id,
                inode=entry.inode,
                case_id=case_id,
                profile_version=self.settings.triage_profile_version,
                status="queued",
                phase="queued",
                created_at=utc_now_iso(),
            )
            self.store.create_job(job)
            deadline = time.monotonic() + float(self.settings.triage_job_timeout)
            future = self._executor.submit(
                self._run_job,
                job.job_id,
                record.evidence_id,
                entry.id,
                case_id,
                bool(force),
                deadline,
            )
            self._futures[job.job_id] = future
            future.add_done_callback(
                lambda _future, job_id=job.job_id: self._forget(job_id)
            )
        self.audit.event(
            "triage_start",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "job_id": job.job_id,
                "entry_id": entry.id,
                "inode": entry.inode,
                "case_id": case_id,
                "force": bool(force),
                "profile_version": job.profile_version,
            },
        )
        return job

    def _forget(self, job_id: str) -> None:
        with self._lock:
            self._futures.pop(job_id, None)

    def get_job(self, job_id: str) -> TriageJob:
        return self.store.get_job(job_id)

    def latest_for_entry(self, evidence_id: str, entry_id: int) -> TriageJob | None:
        return self.store.latest_for_entry(evidence_id, entry_id)

    def latest_for_entries(
        self, evidence_id: str, entry_ids: list[int]
    ) -> dict[int, dict[str, Any]]:
        return self.store.latest_for_entries(evidence_id, entry_ids)

    def strings(
        self,
        job_id: str,
        *,
        page: int = 1,
        page_size: int = 100,
        encoding: str | None = None,
        query: str | None = None,
    ) -> TriageStringsPage:
        from .index_models import validate_page, validate_page_size

        job = self.store.get_job(job_id)
        page = validate_page(page)
        page_size = validate_page_size(
            page_size,
            default_size=self.settings.index_page_size_default,
            max_size=self.settings.index_page_size_max,
        )
        return self.store.strings_page(
            job.cached_from_job_id or job.job_id,
            page=page,
            page_size=page_size,
            encoding=encoding,
            query=(query or "").strip() or None,
        )

    def result(self, job_id: str, *, findings_limit: int = MAX_FINDINGS_RETURNED) -> dict[str, Any]:
        job = self.store.get_job(job_id)
        source = job.cached_from_job_id or job.job_id
        findings = self.store.findings(source)
        yara_matches = self.store.yara_matches(source)
        return {
            "job": job.to_dict(),
            "findings": findings[:findings_limit],
            "findings_total": len(findings),
            "yara_matches": yara_matches,
            "yara_matches_total": len(yara_matches),
        }

    def cleanup(self) -> None:
        with self._lock:
            futures = list(self._futures.values())
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # worker
    # ------------------------------------------------------------------

    def _run_job(
        self,
        job_id: str,
        evidence_id: str,
        entry_id: int,
        case_id: str,
        force: bool,
        deadline: float,
    ) -> None:
        started = time.monotonic()
        job: TriageJob | None = None
        try:
            job = self.store.get_job(job_id)
            job.started_at = utc_now_iso()
            self.store.update_progress(job_id, "extracting")
            record = self.evidence.get(evidence_id)
            entry = self.indexer.tree_entry(record, entry_id)
            if entry.size is not None and int(entry.size) > int(
                self.settings.triage_max_file_size
            ):
                self._fail(
                    job,
                    code="triage_file_too_large",
                    message=(
                        f"indexed file size {entry.size} exceeds the configured "
                        f"triage limit {self.settings.triage_max_file_size} bytes"
                    ),
                    extra_warnings=[
                        "Static triage was not run because the file exceeds the size limit."
                    ],
                    started=started,
                )
                return
            extracted = None
            reuse_note = None
            if not force:
                extracted, reuse_note = self._reusable_copy(
                    record, entry, job.profile_version, job.job_id
                )
                if reuse_note:
                    job.warnings.append(reuse_note)
            if extracted is None:
                extraction = self.filesystem.extract_entry(record, entry, case_id)
                extracted = self._validate_extracted(
                    extraction.output_path, case_id
                )
                try:
                    os.chmod(extracted, 0o600)
                except OSError:
                    pass
            size = extracted.stat().st_size
            job.size = size
            job.extract_relpath = self._relative_to_var(extracted)
            if size > int(self.settings.triage_max_file_size):
                self._fail(
                    job,
                    code="triage_file_too_large",
                    message=(
                        f"file size {size} exceeds the configured triage limit "
                        f"{self.settings.triage_max_file_size} bytes"
                    ),
                    extra_warnings=[
                        "Static triage was not run because the file exceeds the size limit."
                    ],
                    started=started,
                )
                return

            remaining(deadline)
            self.store.update_progress(job_id, "hashing")
            try:
                hashes, hashed_size = hash_file(extracted, deadline)
            except AnalyzerDeadline:
                self._fail(
                    job,
                    code="triage_timeout",
                    message=PHASE_TIMEOUT_ERROR,
                    extra_warnings=["Hashing did not finish within the job deadline."],
                    started=started,
                )
                return
            job.md5 = hashes["md5"]
            job.sha1 = hashes["sha1"]
            job.sha256 = hashes["sha256"]
            job.size = hashed_size

            if not force:
                cached = self.store.find_cached(
                    evidence_id,
                    entry_id,
                    job.sha256,
                    job.profile_version,
                )
                if cached is not None:
                    self._finish_cached(job, cached, started)
                    return

            self.store.update_progress(job_id, "identifying")
            file_result = self._safe_analyzer(
                "file",
                lambda: run_file_identification(
                    extracted, self.settings, self.evidence.runner, deadline
                ),
            )
            job.analyzers.append(file_result)
            if file_result.status == "ok":
                job.mime_type = file_result.data.get("mime_type")
                job.file_type = file_result.data.get("file_type")
            entropy_result = self._safe_analyzer(
                "entropy",
                lambda: entropy_analysis(extracted, self.settings, deadline),
            )
            job.analyzers.append(entropy_result)
            if entropy_result.status == "ok":
                job.entropy = entropy_result.data.get("whole")

            if self._deadline_hit(entropy_result, file_result):
                self._finish_deadline(job, started)
                return

            self.store.update_progress(job_id, "strings")
            strings_count = self._strings_phase(job, extracted, deadline)
            if strings_count is None:
                self._finish_deadline(job, started)
                return

            self.store.update_progress(job_id, "yara")
            try:
                yara_result, matches = run_yara(extracted, self.settings, deadline)
            except AnalyzerDeadline:
                yara_result, matches = (
                    AnalyzerResult(
                        name="yara",
                        status="timeout",
                        error=PHASE_TIMEOUT_ERROR,
                    ),
                    [],
                )
            except Exception as exc:
                yara_result, matches = (
                    AnalyzerResult(
                        name="yara",
                        status="failed",
                        error=str(exc)[:1000],
                    ),
                    [],
                )
            job.analyzers.append(yara_result)
            job.yara_status = yara_result.status
            if matches:
                self.store.insert_yara_matches(job.job_id, matches)

            self.store.update_progress(job_id, "metadata")
            exiftool_result = self._safe_analyzer(
                "exiftool",
                lambda: run_exiftool(
                    extracted, self.settings, self.evidence.runner, deadline
                ),
            )
            job.analyzers.append(exiftool_result)
            pe_result = self._safe_analyzer(
                "pe",
                lambda: run_pe(extracted, self.settings, deadline),
            )
            job.analyzers.append(pe_result)
            job.pe_status = pe_result.status

            self._finish(job, started)
        except AnalyzerDeadline:
            if job is not None:
                self._finish_deadline(job, started)
        except (EntryNotFoundError, DFIRError) as exc:
            if job is None:
                try:
                    job = self.store.get_job(job_id)
                except Exception:
                    job = None
            if job is not None:
                self._fail(
                    job,
                    code=getattr(exc, "code", "triage_error"),
                    message=str(exc),
                    started=started,
                )
            else:
                self.store.mark_failed(
                    job_id, code=getattr(exc, "code", "triage_error"), message=str(exc)
                )
        except Exception as exc:  # noqa: BLE001 - job isolation
            logger.exception("triage job %s failed", job_id)
            if job is None:
                try:
                    job = self.store.get_job(job_id)
                except TriageNotFoundError:
                    job = None
            if job is not None:
                self._fail(
                    job,
                    code="triage_internal_error",
                    message=str(exc)[:500],
                    started=started,
                )
            else:
                self.store.mark_failed(
                    job_id, code="triage_internal_error", message=str(exc)[:500]
                )
        finally:
            self.audit.event(
                "triage_finish",
                evidence_id=evidence_id,
                request_id=get_correlation_id(),
                details={
                    "job_id": job_id,
                    "entry_id": entry_id,
                    "status": job.status if job is not None else "unknown",
                    "duration_ms": round((time.monotonic() - started) * 1000.0, 1),
                    "cached": bool(job and job.cached_from_job_id),
                },
            )

    # ------------------------------------------------------------------
    # phases
    # ------------------------------------------------------------------

    def sha256_for_entry(
        self, record, entry_id: int, *, case_id: str = "case01"
    ) -> dict[str, Any]:
        """Resolve a SHA-256 server-side for a file entry, without analyzers.

        Reuses a recorded triage hash when available, then a valid cached
        extraction, and only extracts when neither exists. Used by the
        VirusTotal hash lookup so the browser never supplies the hash.
        """
        from .index_models import validate_entry_id

        case_id = self.policy.validate_case_id(case_id)
        entry = self.indexer.tree_entry(record, validate_entry_id(entry_id))
        if entry.entry_type != "file":
            raise TriageRejectedError(
                "hash lookup only applies to files",
                code="hash_directory_rejected",
            )
        if entry.inode is None and entry.backend_type != "ad1":
            raise TriageRejectedError(
                "entry has no MFT/inode and cannot be hashed",
                code="hash_entry_without_inode",
            )
        previous = self.store.latest_for_entry(record.evidence_id, entry.id)
        if previous is not None and previous.sha256:
            return {
                "sha256": previous.sha256,
                "md5": previous.md5,
                "sha1": previous.sha1,
                "size": previous.size,
                "source": "triage",
                "job_id": previous.job_id,
            }
        deadline = time.monotonic() + float(self.settings.triage_job_timeout)
        extracted, note = self._reusable_copy(
            record,
            entry,
            self.settings.triage_profile_version,
            "",
        )
        if extracted is None:
            extraction = self.filesystem.extract_entry(record, entry, case_id)
            extracted = self._validate_extracted(extraction.output_path, case_id)
            try:
                os.chmod(extracted, 0o600)
            except OSError:
                pass
        hashes, size = hash_file(extracted, deadline)
        self.audit.event(
            "hash_only",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "entry_id": entry.id,
                "inode": entry.inode,
                "size": size,
                "reused_copy": bool(note),
                "reason": note,
            },
        )
        return {
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "size": size,
            "source": "hash_only",
            "job_id": None,
        }

    def _reusable_copy(
        self, record, entry, profile_version: str, current_job_id: str
    ):
        """Return a validated existing triage copy, or (None, note).

        A copy is reusable only when a previous job for the same evidence,
        entry and profile recorded it, the file is still present, it is inside
        the case export directory, is not a symlink, and its size/mtime match
        the provenance sidecar. Anything unexpected falls back to a fresh
        extraction with an explicit reason, never a silent reuse.
        """
        try:
            previous = self.store.latest_completed_for_entry(
                record.evidence_id,
                entry.id,
                exclude_job_id=current_job_id,
            )
        except Exception:  # noqa: BLE001 - cache reuse is best effort
            return None, None
        if previous is None or not previous.extract_relpath:
            return None, None
        if previous.profile_version != profile_version:
            return None, None
        if previous.sha256 is None:
            return None, None
        candidate = self.settings.var_dir / previous.extract_relpath
        if candidate.is_symlink():
            return None, "cached copy was a symlink; re-extracted"
        try:
            resolved = self._validate_extracted(str(candidate), previous.case_id)
        except DFIRError:
            return None, "cached copy was missing or unsafe; re-extracted"
        sidecar = resolved.with_name(resolved.name + ".provenance.json")
        if not sidecar.is_file() or sidecar.is_symlink():
            return None, "cached copy had no provenance sidecar; re-extracted"
        try:
            import json

            data = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, "cached copy provenance was unreadable; re-extracted"
        if str(data.get("sha256") or "") != previous.sha256:
            return None, "cached copy hash differed from its provenance; re-extracted"
        try:
            stat_result = resolved.stat()
        except OSError:
            return None, "cached copy was not readable; re-extracted"
        if data.get("size") is not None and int(data["size"]) != stat_result.st_size:
            return None, "cached copy size changed; re-extracted"
        return resolved, "reused the existing extraction copy"

    def _strings_phase(
        self, job: TriageJob, path: Path, deadline: float
    ) -> int | None:
        try:
            strings, truncated = scan_strings(path, self.settings, deadline)
        except AnalyzerDeadline:
            job.analyzers.append(
                AnalyzerResult(
                    name="strings",
                    status="timeout",
                    error=PHASE_TIMEOUT_ERROR,
                )
            )
            return None
        except Exception as exc:  # noqa: BLE001
            job.analyzers.append(
                AnalyzerResult(
                    name="strings",
                    status="failed",
                    error=str(exc)[:500],
                )
            )
            return 0
        batch: list[tuple[Any, ...]] = []
        for encoding, offset, value in strings:
            batch.append((encoding, offset, value))
            if len(batch) >= 1000:
                self.store.insert_strings(job.job_id, batch)
                batch.clear()
        self.store.insert_strings(job.job_id, batch)
        job.strings_count = len(strings)
        findings = derive_findings(strings, self.settings)
        self.store.insert_findings(job.job_id, findings)
        job.findings_count = len(findings)
        job.analyzers.append(
            AnalyzerResult(
                name="strings",
                status="ok",
                data={
                    "max_strings": int(self.settings.triage_max_strings),
                    "max_string_length": int(self.settings.triage_max_string_length),
                    "min_string_length": int(self.settings.triage_min_string_length),
                    "findings": len(findings),
                },
                warnings=(
                    ["string output truncated at the configured maximum"]
                    if truncated
                    else []
                ),
                truncated=truncated,
            )
        )
        job.warnings.extend(
            ["string output truncated at the configured maximum"] if truncated else []
        )
        return len(strings)

    def _safe_analyzer(self, name: str, function) -> AnalyzerResult:
        start = time.monotonic()
        try:
            result = function()
        except AnalyzerDeadline as exc:
            result = AnalyzerResult(name=name, status="timeout", error=str(exc))
        except Exception as exc:  # noqa: BLE001 - analyzer isolation
            logger.warning("triage analyzer %s failed: %s", name, exc)
            result = AnalyzerResult(
                name=name, status="failed", error=str(exc)[:1000]
            )
        result.duration_ms = (time.monotonic() - start) * 1000.0
        if result.error:
            job_error = f"{name}: {result.error}"
            if job_error not in result.warnings:
                result.warnings.append(job_error)
        return result

    def _finish_cached(
        self, job: TriageJob, cached: TriageJob, started: float
    ) -> None:
        job.status = cached.status
        job.phase = "complete"
        job.cached_from_job_id = cached.cached_from_job_id or cached.job_id
        job.file_type = cached.file_type
        job.mime_type = cached.mime_type
        job.entropy = cached.entropy
        job.size = cached.size
        job.md5 = cached.md5
        job.sha1 = cached.sha1
        job.sha256 = cached.sha256
        job.strings_count = cached.strings_count
        job.findings_count = cached.findings_count
        job.yara_status = cached.yara_status
        job.pe_status = cached.pe_status
        job.tool_versions = dict(cached.tool_versions)
        job.warnings = list(
            dict.fromkeys([*cached.warnings, *job.warnings])
        )
        job.errors = list(cached.errors)
        job.duration_ms = (time.monotonic() - started) * 1000.0
        job.finished_at = utc_now_iso()
        job.analyzers = []
        self.store.finish_job(job)
        self.audit.event(
            "triage_cache_hit",
            evidence_id=job.evidence_id,
            request_id=get_correlation_id(),
            details={
                "job_id": job.job_id,
                "cached_from_job_id": cached.job_id,
                "sha256": cached.sha256,
            },
        )

    def _finish(self, job: TriageJob, started: float) -> None:
        statuses = {analyzer.status for analyzer in job.analyzers}
        partial = bool(statuses & {"failed", "timeout", "unavailable"})
        job.status = "partial" if partial else "complete"
        job.phase = "complete"
        job.finished_at = utc_now_iso()
        job.duration_ms = (time.monotonic() - started) * 1000.0
        job.tool_versions = {
            analyzer.name: analyzer.version
            for analyzer in job.analyzers
            if analyzer.version
        }
        warnings: list[str] = []
        errors: list[str] = []
        for analyzer in job.analyzers:
            for warning in analyzer.warnings:
                if warning not in warnings:
                    warnings.append(warning)
            if analyzer.error:
                errors.append(f"{analyzer.name}: {analyzer.error}")
        if job.yara_status == "no_rules":
            warnings.append(
                "No active YARA rules; this is not evidence of a clean file."
            )
        for warning in job.warnings:
            if warning not in warnings:
                warnings.append(warning)
        job.warnings = warnings
        job.errors = errors
        self.store.finish_job(job)

    def _finish_deadline(self, job: TriageJob, started: float) -> None:
        for name in ("strings", "yara", "exiftool", "pe"):
            if not any(analyzer.name == name for analyzer in job.analyzers):
                job.analyzers.append(
                    AnalyzerResult(
                        name=name,
                        status="timeout",
                        error=PHASE_TIMEOUT_ERROR,
                    )
                )
        job.status = "partial"
        job.phase = "complete"
        job.finished_at = utc_now_iso()
        job.duration_ms = (time.monotonic() - started) * 1000.0
        job.warnings.append(PHASE_TIMEOUT_ERROR)
        job.errors.append(PHASE_TIMEOUT_ERROR)
        self.store.finish_job(job)

    def _fail(
        self,
        job: TriageJob,
        *,
        code: str,
        message: str,
        extra_warnings: list[str] | None = None,
        started: float | None = None,
    ) -> None:
        job.status = "failed"
        job.phase = "complete"
        job.error_code = code
        job.error_message = message[:1000]
        job.finished_at = utc_now_iso()
        if started is not None:
            job.duration_ms = (time.monotonic() - started) * 1000.0
        if extra_warnings:
            job.warnings.extend(extra_warnings)
        job.errors.append(message[:1000])
        self.store.finish_job(job)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _validate_extracted(self, path: str, case_id: str) -> Path:
        exports = self.policy.case_exports_dir(case_id)
        candidate = Path(path)
        try:
            candidate_info = os.lstat(candidate)
        except OSError as exc:
            raise TriageRejectedError(
                "extracted file is not accessible",
                code="triage_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if stat.S_ISLNK(candidate_info.st_mode):
            raise TriageRejectedError(
                "extracted file must not be a symlink",
                code="triage_symlink_rejected",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise TriageRejectedError(
                "extracted file is not accessible",
                code="triage_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if not resolved.is_relative_to(exports.resolve()):
            raise TriageRejectedError(
                "extracted file is outside the case export directory",
                code="triage_path_escape",
            )
        info = os.lstat(resolved)
        if stat.S_ISLNK(info.st_mode):
            raise TriageRejectedError(
                "extracted file must not be a symlink",
                code="triage_symlink_rejected",
            )
        if not stat.S_ISREG(info.st_mode):
            raise TriageRejectedError(
                "extracted path is not a regular file",
                code="triage_not_regular_file",
            )
        return resolved

    def _relative_to_var(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.settings.var_dir.resolve()))
        except ValueError:
            return path.name

    def _deadline_hit(self, *results: AnalyzerResult) -> bool:
        return any(result.status == "timeout" for result in results)
