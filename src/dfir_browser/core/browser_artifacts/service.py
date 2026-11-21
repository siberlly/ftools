from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..audit import get_correlation_id
from ..config import Settings
from ..errors import DFIRError
from ..filesystem import FilesystemService
from ..index_store import IndexStore
from ..indexer import FilesystemIndexer
from .backends import backend_for, normalize_url
from .correlation import correlate
from .detector import (
    classify_entry,
    inspect_artifact_header,
    sidecar_names,
    user_from_path,
)
from .index import BrowserStore
from .models import (
    BROWSER_SCHEMA_VERSION,
    ActivitySummary,
    ArtifactCandidate,
    BackendUnavailable,
    BrowserArtifactRejected,
    BrowserProfileRow,
    RecordPage,
    SourceArtifact,
    artifact_id_for,
    profile_id_for,
)
from .presets import apply_post_filter, get_preset, list_presets
from .redaction import redact_text

logger = logging.getLogger("dfir_browser.browser_artifacts")

CASE_ID = "case01"


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _limit_warning(name: str, value: Any, limit: int) -> str:
    return f"{name} exceeded {limit} characters and was truncated"


class BrowserArtifactService:
    def __init__(
        self,
        *,
        settings: Settings,
        policy,
        filesystem: FilesystemService,
        evidence,
        indexer: FilesystemIndexer,
        index_store: IndexStore,
        audit,
        store: BrowserStore,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.index_store = index_store
        self.audit = audit
        self.store = store
        self._lock = threading.Lock()
        self._futures: dict[str, Future[None]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(settings.browser_max_concurrent_jobs)),
            thread_name_prefix="dfir-browser",
        )
        self.store.ensure_schema()
        interrupted = self.store.recover_interrupted()
        if interrupted:
            logger.warning(
                "marked %s browser artifact(s) interrupted after restart",
                interrupted,
            )

    def cleanup(self) -> None:
        with self._lock:
            futures = list(self._futures.values())
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # validation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_page(page: int, page_size: int | None, settings: Settings):
        try:
            page_number = int(page)
        except (TypeError, ValueError):
            raise BrowserArtifactRejected(
                "page must be an integer", code="browser_invalid_page"
            )
        if page_number < 1:
            raise BrowserArtifactRejected(
                "page must be >= 1", code="browser_invalid_page"
            )
        if page_size is None:
            size = int(settings.browser_page_size_default)
        else:
            try:
                size = int(page_size)
            except (TypeError, ValueError):
                raise BrowserArtifactRejected(
                    "page_size must be an integer", code="browser_invalid_page_size"
                )
        if size < 1 or size > int(settings.browser_page_size_max):
            raise BrowserArtifactRejected(
                "page_size is outside the allowed range",
                code="browser_invalid_page_size",
                details={"max": settings.browser_page_size_max},
            )
        return page_number, size

    def _validate_query(self, query: str | None) -> str | None:
        if query is None:
            return None
        text = str(query).strip()
        if not text:
            return None
        if len(text) > int(self.settings.browser_max_query_length):
            raise BrowserArtifactRejected(
                "query exceeds the configured maximum length",
                code="browser_query_too_long",
                details={"max": self.settings.browser_max_query_length},
            )
        return text

    def _validate_time(self, value: str | None) -> str | None:
        if not value:
            return None
        from .timestamp import from_iso

        stamp = from_iso(value)
        if stamp.utc is None:
            raise BrowserArtifactRejected(
                "invalid time filter",
                code="browser_invalid_time",
                details={"value": value[:64]},
            )
        return stamp.utc

    def _artifact_id_for_entry(self, evidence_id: str, entry_id: int) -> str:
        return artifact_id_for(evidence_id, entry_id)

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------
    def _scan_id(self, record) -> str:
        status = self.indexer.status_for_record(record)
        if not self.indexer.is_queryable(status):
            raise BrowserArtifactRejected(
                "filesystem index must be ready to discover browser artifacts",
                code="index_not_ready",
                details={"status": status.status, "stale": status.stale},
            )
        row = self.index_store.get_index_row(record.evidence_id)
        if row is None or not row.get("scan_id"):
            raise BrowserArtifactRejected("filesystem index has no active scan")
        return str(row["scan_id"])

    def _indexed_artifacts(self, evidence_id: str) -> dict[int, SourceArtifact]:
        return {a.entry_id: a for a in self.store.list_artifacts(evidence_id)}

    def discover(
        self,
        record,
        *,
        browser: str | None = None,
        artifact_type: str | None = None,
        include_deleted: bool = False,
    ) -> list[ArtifactCandidate]:
        scan_id = self._scan_id(record)
        entries = self.index_store.find_browser_artifact_candidates(
            record.evidence_id, scan_id, include_deleted=include_deleted
        )
        indexed = self._indexed_artifacts(record.evidence_id)
        candidates: list[ArtifactCandidate] = []
        for entry in entries:
            candidate = classify_entry(entry, evidence_id=record.evidence_id)
            if candidate is None:
                continue
            candidate.artifact_id = self._artifact_id_for_entry(
                record.evidence_id, entry.id
            )
            known = indexed.get(entry.id)
            if known is not None:
                candidate.artifact_id = known.artifact_id
                candidate.state = known.status
                candidate.index_status = known.status
                candidate.records_indexed = known.records_indexed
                candidate.parse_errors = known.parse_errors
                candidate.backend = known.backend
                candidate.sidecars = known.sidecars
                candidate.signature_status = (
                    "valid" if known.status in {"ready", "partial"} else "unverified"
                )
            else:
                candidate.sidecars = [
                    name for name, _, _ in self._resolve_sidecars(record, entry)
                ]
            candidate.parser_supported = backend_for(
                candidate.artifact_type
            ).supported
            if candidate.artifact_type == "webcache":
                candidate.parser_supported = self._webcache_available()
            if browser and candidate.browser != browser:
                continue
            if artifact_type and candidate.artifact_type != artifact_type:
                continue
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                0 if item.browser == "webcache" else 1,
                0 if item.browser == "chromium" else 1,
                item.user or "",
                item.path.lower(),
            )
        )
        return candidates

    @staticmethod
    def _webcache_available() -> bool:
        try:
            import dissect.esedb  # noqa: F401

            return True
        except Exception:
            return False

    def _resolve_sidecars(self, record, entry) -> list[tuple[str, int | None, str]]:
        scan_id = self._scan_id(record)
        parent = entry.parent_path
        out: list[tuple[str, int | None, str]] = []
        for name in sidecar_names(entry):
            rows = self.index_store.find_entries_by_basename(
                record.evidence_id, scan_id, name, 5
            )
            for row in rows:
                if row.full_path == f"{parent}/{name}":
                    out.append((name, row.id, row.full_path))
                    break
        return out

    EXPECTED_ARTIFACT_TYPES = (
        ("webcache", "IE / Legacy Edge WebCacheV01.dat"),
        ("chromium_history", "Edge / Chrome User Data <profile>/History"),
        ("firefox_places", "Firefox places.sqlite"),
    )

    def coverage(
        self, record, *, candidates: list[ArtifactCandidate] | None = None
    ) -> list[dict[str, Any]]:
        """Report every expected artifact type as present/indexed/not_present."""
        items = (
            candidates
            if candidates is not None
            else self.discover(record, include_deleted=True)
        )
        by_type: dict[str, list[ArtifactCandidate]] = {}
        for item in items:
            by_type.setdefault(item.artifact_type, []).append(item)
        coverage: list[dict[str, Any]] = []
        for artifact_type, label in self.EXPECTED_ARTIFACT_TYPES:
            found = by_type.get(artifact_type, [])
            indexed = [i for i in found if i.state in {"ready", "partial"}]
            if not found:
                status = "not_present"
            elif indexed:
                status = "indexed"
            else:
                status = "present"
            coverage.append(
                {
                    "artifact_type": artifact_type,
                    "label": label,
                    "status": status,
                    "candidates": len(found),
                    "indexed": len(indexed),
                    "browsers": sorted({i.browser for i in found}),
                    "users": sorted({i.user for i in found if i.user}),
                    "parser_supported": all(
                        i.parser_supported for i in found
                    )
                    if found
                    else True,
                }
            )
        return coverage

    def list_artifacts(
        self,
        record,
        *,
        browser: str | None = None,
        artifact_type: str | None = None,
        include_deleted: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> RecordPage:
        page, size = self._validate_page(page, page_size, self.settings)
        candidates = self.discover(
            record,
            browser=browser,
            artifact_type=artifact_type,
            include_deleted=include_deleted,
        )
        total = len(candidates)
        start = (page - 1) * size
        page_obj = _CandidatePage(
            items=candidates[start : start + size],
            total=total,
            page=page,
            page_size=size,
        )
        page_obj.coverage = self.coverage(record, candidates=candidates)
        return page_obj

    # ------------------------------------------------------------------
    # indexing
    # ------------------------------------------------------------------
    def start_index(
        self,
        record,
        entry_id: int,
        *,
        recover_sidecars: bool = True,
        rebuild: bool = False,
    ) -> dict[str, Any]:
        scan_id = self._scan_id(record)
        entry = self.indexer.tree_entry(record, entry_id)
        if entry.entry_type != "file":
            raise BrowserArtifactRejected(
                "browser indexing only accepts files",
                code="browser_directory_rejected",
            )
        if entry.inode is None:
            raise BrowserArtifactRejected(
                "entry has no MFT/inode and cannot be extracted",
                code="browser_entry_without_inode",
            )
        candidate = classify_entry(entry, evidence_id=record.evidence_id)
        if candidate is None:
            raise BrowserArtifactRejected(
                "entry does not look like a supported browser artifact",
                code="browser_not_candidate",
            )
        backend_cls = backend_for(candidate.artifact_type)
        if not backend_cls.supported:
            raise BackendUnavailable(
                "no parser backend is available for this artifact type",
                details={"artifact_type": candidate.artifact_type},
            )
        if (
            candidate.artifact_type == "webcache"
            and not self._webcache_available()
        ):
            raise BackendUnavailable(
                "WebCache ESE backend is unavailable",
                details={
                    "backend": "dissect.esedb",
                    "hint": "pip install dissect.esedb==3.18",
                },
            )
        size_limit = int(self.settings.browser_max_artifact_size)
        if entry.size is not None and int(entry.size) > size_limit:
            raise BrowserArtifactRejected(
                "artifact exceeds the configured maximum size",
                code="browser_artifact_too_large",
                details={"size": entry.size, "limit": size_limit},
            )
        artifact_id = self._artifact_id_for_entry(record.evidence_id, entry.id)
        existing = self.store.find_by_entry(record.evidence_id, entry.id)
        if (
            existing is not None
            and not rebuild
            and existing.status in {"ready", "partial"}
            and existing.schema_version == BROWSER_SCHEMA_VERSION
            and existing.parser_version == self.settings.browser_parser_version
            and self._cached_copy_valid(existing)
        ):
            return {
                "started": False,
                "cached": True,
                "artifact": existing.to_dict(),
                "note": "existing browser index is valid; nothing was re-extracted",
            }
        limit = max(1, int(self.settings.browser_max_concurrent_jobs)) + max(
            0, int(self.settings.browser_max_queued_jobs)
        )
        active = self._active_jobs()
        if active >= limit:
            raise BrowserArtifactRejected(
                "too many browser index jobs are queued or running",
                code="browser_queue_full",
                details={"limit": limit},
            )
        sidecars = self._resolve_sidecars(record, entry) if recover_sidecars else []
        artifact = SourceArtifact(
            artifact_id=artifact_id,
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            inode=entry.inode,
            evidence_path=entry.full_path,
            filename=entry.basename,
            browser=candidate.browser,
            artifact_type=candidate.artifact_type,
            user=candidate.user,
            profile_name=candidate.profile_name,
            size=entry.size,
            sha256=None,
            sidecars=[name for name, _, _ in sidecars],
            sidecars_used=[],
            extract_relpath=None,
            backend=backend_cls.name,
            parser_version=self.settings.browser_parser_version,
            schema_version=BROWSER_SCHEMA_VERSION,
            status="queued",
            phase="queued",
            warnings=list(candidate.warnings),
            created_at=_now(),
        )
        if existing is not None:
            artifact.created_at = existing.created_at
        self.store.upsert_artifact(artifact)
        with self._lock:
            future = self._executor.submit(
                self._run_index,
                artifact_id,
                record.evidence_id,
                entry.id,
                recover_sidecars,
            )
            self._futures[artifact_id] = future
            future.add_done_callback(
                lambda _f, key=artifact_id: self._forget(key)
            )
        self.audit.event(
            "browser_index_start",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "artifact_id": artifact_id,
                "entry_id": entry.id,
                "inode": entry.inode,
                "browser": candidate.browser,
                "artifact_type": candidate.artifact_type,
                "rebuild": bool(rebuild),
                "recover_sidecars": bool(recover_sidecars),
            },
        )
        return {
            "started": True,
            "cached": False,
            "artifact": artifact.to_dict(),
            "note": "browser index job started",
        }

    def _active_jobs(self) -> int:
        with self.store._connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM browser_artifacts "
                    "WHERE status IN ('queued','running')"
                ).fetchone()["n"]
            )

    def _forget(self, artifact_id: str) -> None:
        with self._lock:
            self._futures.pop(artifact_id, None)

    def status(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.store.get_artifact(artifact_id)
        data = artifact.to_dict()
        data["elapsed_seconds"] = self._elapsed(artifact)
        return data

    @staticmethod
    def _elapsed(artifact: SourceArtifact) -> float | None:
        if not artifact.started_at:
            return None
        end = artifact.completed_at or _now()
        try:
            start = datetime.fromisoformat(artifact.started_at.replace("Z", "+00:00"))
            finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
        except ValueError:
            return None
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if finish.tzinfo is None:
            finish = finish.replace(tzinfo=timezone.utc)
        return round((finish - start).total_seconds(), 2)

    def _cached_copy_valid(self, artifact: SourceArtifact) -> bool:
        if not artifact.extract_relpath:
            return False
        try:
            path = self._validate_extracted(
                str(self.settings.var_dir / artifact.extract_relpath)
            )
        except DFIRError:
            return False
        try:
            if artifact.sha256:
                sha, size = _sha256_file(path)
                return sha == artifact.sha256 and (
                    artifact.size is None or size == artifact.size
                )
        except OSError:
            return False
        return path.exists()

    def _run_index(
        self,
        artifact_id: str,
        evidence_id: str,
        entry_id: int,
        recover_sidecars: bool,
    ) -> None:
        started = time.monotonic()
        deadline = started + float(self.settings.browser_parser_timeout)
        artifact: SourceArtifact | None = None
        try:
            artifact = self.store.get_artifact(artifact_id)
            artifact.started_at = _now()
            self.store.update_phase(artifact_id, "extracting")
            record = self.evidence.get(evidence_id)
            entry = self.indexer.tree_entry(record, entry_id)
            workdir = self._workdir(artifact_id)
            primary, reused, note = self._prepare_copy(
                artifact, record, entry, workdir, recover_sidecars
            )
            size = primary.stat().st_size
            if size > int(self.settings.browser_max_artifact_size):
                self._fail(
                    artifact,
                    code="browser_artifact_too_large",
                    message=f"file size {size} exceeds the configured maximum",
                )
                return
            self.store.update_phase(artifact_id, "validating")
            sha256, hashed = _sha256_file(primary)
            header = inspect_artifact_header(primary)
            expected = "ese" if artifact.artifact_type == "webcache" else "sqlite"
            warnings = list(artifact.warnings)
            if note:
                warnings.append(note)
            artifact.sha256 = sha256
            artifact.size = hashed
            artifact.extract_relpath = str(
                primary.resolve().relative_to(self.settings.var_dir.resolve())
            )
            if not header.signature_valid:
                self._fail(
                    artifact,
                    code="browser_invalid_signature",
                    message=header.detail or "unrecognized database signature",
                )
                return
            if header.format != expected:
                self._fail(
                    artifact,
                    code="browser_signature_mismatch",
                    message=(
                        f"expected a {expected} database but found {header.format}"
                    ),
                )
                return
            artifact.warnings = warnings
            self.store.update_phase(artifact_id, "parsing")
            profile_id = profile_id_for(
                evidence_id,
                artifact.browser,
                artifact.user,
                artifact.profile_name,
            )
            backend = backend_for(artifact.artifact_type)(
                primary,
                settings=self.settings,
                profile_id=profile_id,
                artifact_id=artifact_id,
            )
            outcome = backend.parse(deadline)
            self.store.update_phase(artifact_id, "indexing")
            warnings.extend(outcome.warnings)
            for visit in outcome.visits:
                visit.user = artifact.user
            for download in outcome.downloads:
                download.user = artifact.user
            for cache in outcome.cache:
                cache.user = artifact.user
            visits = outcome.visits[: int(self.settings.browser_max_records)]
            downloads = outcome.downloads[: int(self.settings.browser_max_records)]
            cache = outcome.cache[: int(self.settings.browser_max_records)]
            counts = self.store.insert_records(
                visits=visits, downloads=downloads, cache=cache
            )
            profile = BrowserProfileRow(
                profile_id=profile_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                user=artifact.user or outcome.profile.get("user"),
                browser=artifact.browser,
                profile_name=artifact.profile_name
                or outcome.profile.get("profile_name"),
                source_path=artifact.evidence_path,
                artifact_types=[artifact.artifact_type],
                warnings=list(dict.fromkeys(warnings)),
            )
            self.store.upsert_profile(profile)
            if outcome.errors:
                self.store.insert_errors(artifact_id, outcome.errors)
            times = [
                item.visit_time_utc
                for item in visits
                if item.visit_time_utc
            ] + [
                item.start_time_utc
                for item in downloads
                if item.start_time_utc
            ] + [
                item.accessed_time_utc
                for item in cache
                if item.accessed_time_utc
            ]
            artifact.records_seen = outcome.records_seen
            artifact.records_indexed = (
                counts["visits"] + counts["downloads"] + counts["cache"]
            )
            artifact.parse_errors = len(outcome.errors)
            artifact.first_record_time = min(times) if times else None
            artifact.last_record_time = max(times) if times else None
            artifact.phase = "ready"
            artifact.completed_at = _now()
            if artifact.parse_errors and artifact.records_indexed:
                artifact.status = "partial"
                artifact.error_code = "browser_parse_errors"
                artifact.error_message = (
                    f"{artifact.parse_errors} record(s) could not be parsed"
                )
            elif not artifact.records_indexed and artifact.parse_errors:
                artifact.status = "failed"
                artifact.error_code = "browser_no_records"
                artifact.error_message = "no usable records were parsed"
            else:
                artifact.status = "ready"
            if artifact.artifact_type == "webcache":
                artifact.sidecars_used = []
                if artifact.sidecars:
                    warnings.append(
                        "ESE transaction logs were detected but are not replayed; "
                        "the base database was parsed as-is"
                    )
            else:
                artifact.sidecars_used = [
                    name for name in artifact.sidecars
                    if (workdir / name).exists()
                ]
            artifact.warnings = list(dict.fromkeys(warnings))
            self.store.finish_artifact(artifact)
        except BackendUnavailable as exc:
            if artifact is None:
                artifact = self.store.get_artifact(artifact_id)
            self._fail(artifact, code=exc.code, message=str(exc))
        except DFIRError as exc:
            if artifact is None:
                artifact = self.store.get_artifact(artifact_id)
            self._fail(
                artifact,
                code=getattr(exc, "code", "browser_error"),
                message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - job isolation
            logger.exception("browser index %s failed", artifact_id)
            if artifact is None:
                try:
                    artifact = self.store.get_artifact(artifact_id)
                except Exception:
                    artifact = None
            if artifact is not None:
                self._fail(
                    artifact,
                    code="browser_internal_error",
                    message=redact_text(str(exc))[:500],
                )
        finally:
            self.audit.event(
                "browser_index_finish",
                evidence_id=evidence_id,
                request_id=get_correlation_id(),
                details={
                    "artifact_id": artifact_id,
                    "entry_id": entry_id,
                    "status": artifact.status if artifact else "unknown",
                    "records_seen": artifact.records_seen if artifact else 0,
                    "records_indexed": artifact.records_indexed if artifact else 0,
                    "parse_errors": artifact.parse_errors if artifact else 0,
                    "duration_ms": round((time.monotonic() - started) * 1000.0, 1),
                },
            )

    def _workdir(self, artifact_id: str) -> Path:
        directory = self.policy.case_exports_dir(CASE_ID) / "browser" / artifact_id
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        return directory

    def _prepare_copy(
        self,
        artifact: SourceArtifact,
        record,
        entry,
        workdir: Path,
        recover_sidecars: bool,
    ) -> tuple[Path, bool, str | None]:
        if artifact.extract_relpath and artifact.sha256:
            candidate = self.settings.var_dir / artifact.extract_relpath
            try:
                resolved = self._validate_extracted(str(candidate))
                sha256, size = _sha256_file(resolved)
            except (DFIRError, OSError):
                note = "previous working copy was missing or unsafe; re-extracted"
            else:
                if sha256 == artifact.sha256 and (
                    artifact.size is None or size == artifact.size
                ):
                    return resolved, True, "reused the existing working copy"
                note = "previous working copy changed; re-extracted"
        else:
            note = None
        image = self.evidence.ensure_image(record)
        extraction = self.filesystem.extract(
            image,
            record.evidence_id,
            inode=entry.inode,
            case_id=CASE_ID,
            offset_sectors=record.layout.offset_sectors,
            assume_file=True,
        )
        source = Path(extraction.output_path)
        for stale in workdir.iterdir():
            if stale.is_file() and not stale.is_symlink():
                stale.unlink()
        destination = workdir / entry.basename
        shutil.move(str(source), str(destination))
        os.chmod(destination, 0o600)
        if recover_sidecars and artifact.artifact_type != "webcache":
            self._copy_sidecars(record, entry, workdir)
        return destination, False, note

    def _copy_sidecars(self, record, entry, workdir: Path) -> None:
        scan_id = self._scan_id(record)
        image = self.evidence.ensure_image(record)
        for name in sidecar_names(entry):
            rows = self.index_store.find_entries_by_basename(
                record.evidence_id, scan_id, name, 5
            )
            match = next(
                (row for row in rows
                 if row.full_path == f"{entry.parent_path}/{name}"),
                None,
            )
            if match is None or match.inode is None:
                continue
            try:
                extraction = self.filesystem.extract(
                    image,
                    record.evidence_id,
                    inode=match.inode,
                    case_id=CASE_ID,
                    offset_sectors=record.layout.offset_sectors,
                    assume_file=True,
                )
                target = workdir / name
                if target.exists():
                    target.unlink()
                shutil.move(str(extraction.output_path), str(target))
                os.chmod(target, 0o600)
            except Exception as exc:  # noqa: BLE001 - sidecars are best effort
                logger.warning(
                    "browser sidecar %s could not be extracted: %s", name, exc
                )

    def _validate_extracted(self, path: str) -> Path:
        exports = self.policy.case_exports_dir(CASE_ID)
        candidate = Path(path)
        try:
            info = os.lstat(candidate)
        except OSError as exc:
            raise BrowserArtifactRejected(
                "working copy is not accessible",
                code="browser_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise BrowserArtifactRejected(
                "working copy must not be a symlink",
                code="browser_symlink_rejected",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise BrowserArtifactRejected(
                "working copy is not accessible",
                code="browser_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if not resolved.is_relative_to(exports.resolve()):
            raise BrowserArtifactRejected(
                "working copy is outside the case export directory",
                code="browser_extract_outside_case",
            )
        if not resolved.is_file():
            raise BrowserArtifactRejected(
                "working copy is not a regular file",
                code="browser_extract_not_file",
            )
        return resolved

    def _fail(self, artifact: SourceArtifact, *, code: str, message: str) -> None:
        artifact.status = "failed"
        artifact.phase = "ready"
        artifact.error_code = code
        artifact.error_message = message[:500]
        artifact.completed_at = _now()
        artifact.warnings = list(
            dict.fromkeys([*artifact.warnings, message[:300]])
        )
        self.store.finish_artifact(artifact)

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def _profiles_for(self, evidence_id: str, profile_ids: list[str] | None):
        known = {p.profile_id for p in self.store.list_profiles(evidence_id)}
        if not profile_ids:
            return None
        return [pid for pid in profile_ids if pid in known]

    def query_downloads(
        self,
        evidence_id: str,
        *,
        profile_ids: list[str] | None = None,
        query: str | None = None,
        domain: str | None = None,
        filename: str | None = None,
        extension: str | None = None,
        state: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        executable_only: bool = False,
        include_query_string: bool = False,
        page: int = 1,
        page_size: int | None = None,
        sort_dir: str = "desc",
        preset: str | None = None,
    ) -> RecordPage:
        page, size = self._validate_page(page, page_size, self.settings)
        text = self._validate_query(query)
        start = self._validate_time(time_from)
        end = self._validate_time(time_to)
        if start and end and start > end:
            raise BrowserArtifactRejected(
                "time_from must be before time_to",
                code="browser_invalid_time_range",
            )
        if sort_dir not in {"asc", "desc"}:
            raise BrowserArtifactRejected(
                "sort_dir must be asc or desc", code="browser_invalid_sort"
            )
        preset_obj = None
        if preset:
            preset_obj = get_preset(preset)
            if preset_obj is None:
                raise BrowserArtifactRejected(
                    "unknown preset", code="browser_unknown_preset"
                )
            if preset_obj.filters.get("executable_only"):
                executable_only = True
            if preset_obj.filters.get("states"):
                state = None
        result = self.store.query_downloads(
            profile_ids=self._profiles_for(evidence_id, profile_ids),
            query=text,
            domain=domain,
            filename=filename,
            extension=extension,
            state=state,
            time_from=start,
            time_to=end,
            executable_only=executable_only,
            include_query_string=include_query_string,
            page=page,
            page_size=size,
            sort_dir=sort_dir,
        )
        if preset_obj is not None:
            result = self._filter_preset(result, preset_obj, evidence_id, size)
        return result

    def _filter_preset(self, result, preset, evidence_id: str, page_size: int):
        post = preset.filters.get("post_filter")
        states = preset.filters.get("states")
        items = result.items
        if states:
            allowed = {s.lower() for s in states}
            items = [
                item for item in items
                if (item.get("state") or "unknown").lower() in allowed
            ]
        if post:
            if post == "deleted_target":
                items = [
                    item for item in items
                    if self._target_deleted(evidence_id, item)
                ]
            elif post == "recent_window":
                stamps = [i.get("start_time_utc") for i in items if i.get("start_time_utc")]
                latest = max(stamps) if stamps else None
                if latest:
                    from datetime import timedelta

                    moment = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                    cutoff = (
                        moment - timedelta(hours=24)
                    ).isoformat(timespec="microseconds").replace("+00:00", "Z")
                    items = [
                        item for item in items
                        if item.get("start_time_utc") and item["start_time_utc"] >= cutoff
                    ]
            else:
                prepared = []
                for item in items:
                    enriched = dict(item)
                    enriched["host"] = normalize_url(item.get("url"), 2048)["host"]
                    prepared.append(enriched)
                items = [
                    item for item in prepared if apply_post_filter(post, item)
                ]
        return RecordPage(
            kind=result.kind,
            items=items[:page_size],
            total=len(items),
            page=result.page,
            page_size=result.page_size,
            sort_dir=result.sort_dir,
            warnings=[
                *result.warnings,
                f"preset {preset.rule_id}: indicator only, not a malware verdict",
            ],
        )

    def _target_deleted(self, evidence_id: str, item: dict[str, Any]) -> bool:
        try:
            result = self.correlate_download(
                evidence_id, int(item["download_id"])
            )
        except Exception:
            return False
        return any(hit.get("deleted") for hit in result["correlation"]["hits"])

    def query_history(
        self,
        evidence_id: str,
        *,
        profile_ids: list[str] | None = None,
        query: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: bool = False,
        page: int = 1,
        page_size: int | None = None,
        sort_dir: str = "desc",
    ) -> RecordPage:
        page, size = self._validate_page(page, page_size, self.settings)
        text = self._validate_query(query)
        start = self._validate_time(time_from)
        end = self._validate_time(time_to)
        if sort_dir not in {"asc", "desc"}:
            raise BrowserArtifactRejected(
                "sort_dir must be asc or desc", code="browser_invalid_sort"
            )
        return self.store.query_visits(
            profile_ids=self._profiles_for(evidence_id, profile_ids),
            query=text,
            domain=domain,
            time_from=start,
            time_to=end,
            include_query_string=include_query_string,
            page=page,
            page_size=size,
            sort_dir=sort_dir,
        )

    def query_cache(
        self,
        evidence_id: str,
        *,
        profile_ids: list[str] | None = None,
        query: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: bool = False,
        page: int = 1,
        page_size: int | None = None,
        sort_dir: str = "desc",
    ) -> RecordPage:
        page, size = self._validate_page(page, page_size, self.settings)
        text = self._validate_query(query)
        start = self._validate_time(time_from)
        end = self._validate_time(time_to)
        if sort_dir not in {"asc", "desc"}:
            raise BrowserArtifactRejected(
                "sort_dir must be asc or desc", code="browser_invalid_sort"
            )
        return self.store.query_cache(
            profile_ids=self._profiles_for(evidence_id, profile_ids),
            query=text,
            domain=domain,
            time_from=start,
            time_to=end,
            include_query_string=include_query_string,
            page=page,
            page_size=size,
            sort_dir=sort_dir,
        )

    def get_record(self, record_type: str, record_id: int) -> dict[str, Any]:
        try:
            numeric = int(record_id)
        except (TypeError, ValueError):
            raise BrowserArtifactRejected(
                "record_id must be an integer", code="browser_invalid_record_id"
            )
        if numeric < 1:
            raise BrowserArtifactRejected(
                "record_id must be positive", code="browser_invalid_record_id"
            )
        return self.store.get_record(record_type, numeric)

    def list_profiles(
        self,
        evidence_id: str,
        *,
        browser: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> RecordPage:
        page, size = self._validate_page(page, page_size, self.settings)
        profiles = self.store.list_profiles(evidence_id, browser)
        total = len(profiles)
        start = (page - 1) * size
        return RecordPage(
            kind="profiles",
            items=profiles[start : start + size],
            total=total,
            page=page,
            page_size=size,
        )

    # ------------------------------------------------------------------
    # correlation and summary
    # ------------------------------------------------------------------
    def search_all(
        self,
        evidence_id: str,
        *,
        query: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        page, size = self._validate_page(page, page_size, self.settings)
        text = self._validate_query(query)
        start = self._validate_time(time_from)
        end = self._validate_time(time_to)
        sections = {}
        for name, call in (
            ("downloads", self.query_downloads),
            ("history", self.query_history),
            ("cache", self.query_cache),
        ):
            sections[name] = call(
                evidence_id,
                query=text,
                domain=domain,
                time_from=start,
                time_to=end,
                include_query_string=include_query_string,
                page=page,
                page_size=size,
            ).to_dict()
        total = sum(section["total"] for section in sections.values())
        return {
            "trust": "untrusted_evidence_data",
            "query": text,
            "domain": domain,
            "total": total,
            "page": page,
            "page_size": size,
            "sections": sections,
            "warnings": [],
        }

    def correlate_download(
        self, evidence_id: str, download_id: int, *, limit: int = 50
    ) -> dict[str, Any]:
        store = self.store
        download = store.get_download(int(download_id))
        if download.get("source_artifact_id"):
            artifact = store.get_artifact(download["source_artifact_id"])
            if artifact.evidence_id != evidence_id:
                raise BrowserArtifactRejected(
                    "download does not belong to this evidence",
                    code="browser_evidence_mismatch",
                )
        record = self.evidence.get(evidence_id)
        scan_id = self._scan_id(record)
        result = correlate(
            target_path=download.get("target_path"),
            filename=download.get("filename"),
            download_size=download.get("received_bytes"),
            lookup_exact=lambda rel: self.index_store.find_entries_by_exact_path(
                evidence_id, scan_id, rel
            ),
            lookup_basename=lambda name, cap: self.index_store.find_entries_by_basename(
                evidence_id, scan_id, name, cap
            ),
            limit=max(1, min(int(limit), 100)),
        )
        return {
            "download": download,
            "correlation": result.to_dict(),
        }

    def summary(
        self,
        evidence_id: str,
        *,
        profile_ids: list[str] | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        top_n: int = 20,
    ) -> ActivitySummary:
        start = self._validate_time(time_from)
        end = self._validate_time(time_to)
        top_n = max(1, min(int(top_n or 20), 100))
        profiles = self._profiles_for(evidence_id, profile_ids)
        with self.store._connect() as connection:
            where, params = _scope(profiles, start, end)
            total_visits = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM browser_visits" + where, params
                ).fetchone()["n"]
            )
            total_downloads = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM browser_downloads" + where, params
                ).fetchone()["n"]
            )
            total_cache = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM browser_cache" + where, params
                ).fetchone()["n"]
            )
            bounds = _time_bounds(connection, where, params)
            users = _group(connection, "browser_visits", "user", where, params)
            browsers = _group(connection, "browser_visits", "browser", where, params)
            domain_rows = connection.execute(
                "SELECT domain, COUNT(*) AS n FROM browser_visits"
                + _and(where, "domain IS NOT NULL")
                + f" GROUP BY domain ORDER BY n DESC LIMIT {top_n}",
                params,
            ).fetchall()
            extension_rows = connection.execute(
                "SELECT extension, COUNT(*) AS n FROM browser_downloads"
                + _and(where, "extension IS NOT NULL")
                + f" GROUP BY extension ORDER BY n DESC LIMIT {top_n}",
                params,
            ).fetchall()
            state_rows = connection.execute(
                "SELECT COALESCE(state, 'unknown') AS state, COUNT(*) AS n "
                "FROM browser_downloads" + where + " GROUP BY state"
                f" ORDER BY n DESC LIMIT {top_n}",
                params,
            ).fetchall()
            bytes_row = connection.execute(
                "SELECT COALESCE(SUM(received_bytes), 0) AS n FROM browser_downloads"
                + where,
                params,
            ).fetchone()
            executable = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM browser_downloads"
                    + _and(
                        where,
                        "extension IN ('exe','dll','msi','scr','com','bat','cmd',"
                        "'ps1','js','vbs','hta','zip','rar','7z','iso','img')",
                    ),
                    params,
                ).fetchone()["n"]
            )
            day_rows = connection.execute(
                "SELECT substr(visit_time, 1, 10) AS day, COUNT(*) AS n "
                "FROM browser_visits"
                + _and(where, "visit_time IS NOT NULL")
                + " GROUP BY day ORDER BY day",
                params,
            ).fetchall()
            profile_rows = connection.execute(
                "SELECT p.profile_id, p.user, p.browser, "
                "(SELECT COUNT(*) FROM browser_visits v WHERE v.profile_id = p.profile_id) "
                "AS visits, "
                "(SELECT COUNT(*) FROM browser_downloads d WHERE d.profile_id = p.profile_id) "
                "AS downloads "
                "FROM browser_profiles p WHERE p.evidence_id = ?",
                (evidence_id,),
            ).fetchall()
        notable_rows = self.store.query_downloads(
            profile_ids=profiles,
            query=None,
            domain=None,
            filename=None,
            extension=None,
            state=None,
            time_from=start,
            time_to=end,
            executable_only=True,
            include_query_string=False,
            page=1,
            page_size=min(top_n, 25),
            sort_dir="desc",
        )
        notable = [
            {
                "download_id": item.get("download_id"),
                "filename": item.get("filename"),
                "url": item.get("url"),
                "domain": None,
                "state": item.get("state"),
                "start_time_utc": item.get("start_time_utc"),
                "user": item.get("user"),
                "browser": item.get("browser"),
            }
            for item in notable_rows.items
        ]
        return ActivitySummary(
            total_visits=total_visits,
            total_downloads=total_downloads,
            total_cache=total_cache,
            time_from=bounds[0],
            time_to=bounds[1],
            users=users,
            browsers=browsers,
            profiles={
                str(row["profile_id"]): int((row["visits"] or 0) + (row["downloads"] or 0))
                for row in profile_rows
            },
            top_domains=[
                {"domain": row["domain"], "count": int(row["n"])}
                for row in domain_rows
            ],
            top_extensions=[
                {"extension": row["extension"], "count": int(row["n"])}
                for row in extension_rows
            ],
            download_states={
                str(row["state"]): int(row["n"]) for row in state_rows
            },
            total_download_bytes=int(bytes_row["n"] or 0),
            executable_downloads=executable,
            correlated_downloads=0,
            deleted_targets=0,
            by_day={str(row["day"]): int(row["n"]) for row in day_rows},
            notable=notable,
        )

    def list_presets(self) -> list[dict[str, Any]]:
        return list_presets()


def _scope(profile_ids: list[str] | None, start: str | None, end: str | None):
    if profile_ids == []:
        return " WHERE 1 = 0", []
    clauses = []
    params: list[Any] = []
    if profile_ids:
        clauses.append(
            "profile_id IN (" + ", ".join("?" for _ in profile_ids) + ")"
        )
        params.extend(profile_ids)
    return ("", params) if not clauses else (" WHERE " + " AND ".join(clauses), params)


def _and(where: str, condition: str) -> str:
    return where + (" AND " if where else " WHERE ") + condition


def _group(connection, table: str, column: str, where: str, params) -> dict[str, int]:
    rows = connection.execute(
        f"SELECT COALESCE({column}, 'unknown') AS k, COUNT(*) AS n "
        f"FROM {table}{where} GROUP BY k ORDER BY n DESC",
        params,
    ).fetchall()
    return {str(row["k"]): int(row["n"]) for row in rows}


def _time_bounds(connection, where: str, params):
    parts: list[str] = []
    for table, column in (
        ("browser_visits", "visit_time"),
        ("browser_downloads", "start_time"),
        ("browser_cache", "accessed_time"),
    ):
        clause = where + (" AND " if where else " WHERE ") + f"{column} IS NOT NULL"
        row = connection.execute(
            f"SELECT MIN({column}) AS lo, MAX({column}) AS hi FROM {table}"
            f"{clause}",
            params,
        ).fetchone()
        if row and row["lo"]:
            parts.append(row["lo"])
        if row and row["hi"]:
            parts.append(row["hi"])
    if not parts:
        return None, None
    return min(parts), max(parts)


class _CandidatePage:
    def __init__(self, *, items, total: int, page: int, page_size: int) -> None:
        self.items = items
        self.total = total
        self.page = page
        self.page_size = page_size
        self.coverage: list[dict[str, Any]] = []

    @property
    def pages(self) -> int:
        return 0 if self.page_size <= 0 else (self.total + self.page_size - 1) // self.page_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": "untrusted_evidence_data",
            "kind": "artifacts",
            "items": [item.to_dict() for item in self.items],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "has_more": self.page * self.page_size < self.total,
            "complete": self.page * self.page_size >= self.total,
            "truncated": False,
            "coverage": self.coverage,
            "warnings": [],
        }
