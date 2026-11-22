from __future__ import annotations

import hashlib
import logging
import os
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
from ..triage import FileTriageService
from ..virustotal import VirusTotalError, VirusTotalService
from .amcache import parse_amcache_key
from .detector import classify_entry, inspect_hive_header
from .index import RegistryStore
from .models import (
    REGISTRY_SCHEMA_VERSION,
    AmcacheCompareResult,
    HiveCandidate,
    HiveNotFoundError,
    HiveNotReadyError,
    RegistryError,
    RegistryHiveRecord,
    RegistryPage,
    RegistryRejectedError,
    hive_id_for,
)
from .reader import HiveReader, RegistryLimitError, RegistryTimeoutError

logger = logging.getLogger("dfir_browser.registry")

CASE_ID = "case01"
MAX_QUERY_LENGTH = 256


def _utc_now() -> str:
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


class RegistryService:
    def __init__(
        self,
        *,
        settings: Settings,
        policy,
        filesystem: FilesystemService,
        evidence,
        indexer: FilesystemIndexer,
        index_store: IndexStore,
        triage: FileTriageService,
        virustotal: VirusTotalService,
        audit,
        store: RegistryStore,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.index_store = index_store
        self.triage = triage
        self.virustotal = virustotal
        self.audit = audit
        self.store = store
        self._lock = threading.Lock()
        self._futures: dict[str, Future[None]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(settings.registry_max_concurrent_jobs)),
            thread_name_prefix="dfir-registry",
        )
        self.store.ensure_schema()
        interrupted = self.store.recover_interrupted()
        if interrupted:
            logger.warning(
                "marked %s registry hive(s) interrupted after restart", interrupted
            )

    def cleanup(self) -> None:
        with self._lock:
            futures = list(self._futures.values())
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------
    def _scan_id(self, record) -> str:
        status = self.indexer.status_for_record(record)
        if not self.indexer.is_queryable(status):
            raise HiveNotReadyError(
                "filesystem index must be ready to discover registry hives",
                code="index_not_ready",
                details={"status": status.status, "stale": status.stale},
            )
        row = self.index_store.get_index_row(record.evidence_id)
        if row is None or not row.get("scan_id"):
            raise HiveNotReadyError("filesystem index has no active scan")
        return str(row["scan_id"])

    def list_hives(
        self,
        record,
        *,
        include_deleted: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> RegistryPage:
        page, page_size = self._validate_page(page, page_size)
        scan_id = self._scan_id(record)
        entries = self.index_store.find_registry_candidates(
            record.evidence_id, scan_id, include_deleted=include_deleted
        )
        candidates: list[HiveCandidate] = []
        for entry in entries:
            candidate = classify_entry(entry, evidence_id=record.evidence_id)
            if candidate is None:
                continue
            candidate.hive_id = hive_id_for(record.evidence_id, entry.id)
            candidates.append(candidate)
        known = self.store.latest_for_entries(
            record.evidence_id, [candidate.entry_id for candidate in candidates]
        )
        for candidate in candidates:
            info = known.get(candidate.entry_id)
            if info:
                candidate.hive_id = info["hive_id"]
                candidate.state = info["state"]
                candidate.index_status = info["state"]
                candidate.key_count = info["key_count"]
                candidate.value_count = info["value_count"]
                candidate.amcache_count = info["amcache_count"]
                candidate.dirty = info["dirty"]
                candidate.signature_status = info["signature_status"] or "unverified"
                if info["sensitive"]:
                    candidate.sensitive = True
        candidates.sort(key=lambda item: (item.hive_type, item.path.lower()))
        total = len(candidates)
        start = (page - 1) * page_size
        return RegistryPage(
            items=candidates[start : start + page_size],
            total=total,
            page=page,
            page_size=page_size,
            kind="registry_hives",
        )

    # ------------------------------------------------------------------
    # indexing
    # ------------------------------------------------------------------
    def start_index(
        self,
        record,
        entry_id: int,
        *,
        recover_with_logs: bool = False,
        rebuild: bool = False,
    ) -> dict[str, Any]:
        self._scan_id(record)
        entry = self.indexer.tree_entry(record, entry_id)
        if entry.entry_type != "file":
            raise RegistryRejectedError(
                "registry indexing only accepts files",
                code="registry_directory_rejected",
                details={"entry_id": entry.id},
            )
        if entry.inode is None and entry.backend_type != "ad1":
            raise RegistryRejectedError(
                "entry has no MFT/inode and cannot be extracted",
                code="registry_entry_without_inode",
            )
        candidate = classify_entry(entry, evidence_id=record.evidence_id)
        hive_type = candidate.hive_type if candidate else "other"
        owner = candidate.owner if candidate else None
        sensitive = bool(candidate.sensitive) if candidate else False
        hive_id = hive_id_for(record.evidence_id, entry.id)
        existing = self.store.find_hive_by_entry(record.evidence_id, entry.id)
        if (
            existing is not None
            and not rebuild
            and existing.state in {"ready", "partial"}
            and existing.schema_version == REGISTRY_SCHEMA_VERSION
            and self._cached_extract_valid(existing)
        ):
            return {
                "started": False,
                "cached": True,
                "hive": existing.to_dict(),
                "note": "existing registry index is valid; nothing was re-extracted",
            }
        limit = max(1, int(self.settings.registry_max_concurrent_jobs)) + max(
            0, int(self.settings.registry_max_queued_jobs)
        )
        with self._lock:
            if int(self.store.counts()["active"]) >= limit:
                raise RegistryError(
                    "too many registry index jobs are queued or running",
                    code="registry_queue_full",
                    details={"limit": limit},
                )
        hive = RegistryHiveRecord(
            hive_id=hive_id,
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            inode=entry.inode,
            path=entry.full_path,
            name=entry.basename,
            hive_type=hive_type,
            owner=owner,
            size=entry.size,
            sha256=None,
            extract_relpath=None,
            state="queued",
            phase="queued",
            dirty=False,
            sequence1=None,
            sequence2=None,
            recovered=False,
            parser_version=self.settings.registry_parser_version,
            schema_version=REGISTRY_SCHEMA_VERSION,
            sensitive=sensitive,
            signature_status="unverified",
            transaction_logs=[],
            warnings=[],
            created_at=_utc_now(),
        )
        if existing is not None and existing.path == entry.full_path:
            hive.created_at = existing.created_at
        self.store.upsert_hive(hive)
        with self._lock:
            future = self._executor.submit(
                self._run_index,
                hive_id,
                record.evidence_id,
                entry.id,
                bool(recover_with_logs),
                bool(rebuild),
            )
            self._futures[hive_id] = future
            future.add_done_callback(
                lambda _future, key=hive_id: self._forget(key)
            )
        self.audit.event(
            "registry_index_start",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "hive_id": hive_id,
                "entry_id": entry.id,
                "inode": entry.inode,
                "hive_type": hive_type,
                "recover_with_logs": bool(recover_with_logs),
                "rebuild": bool(rebuild),
            },
        )
        return {
            "started": True,
            "cached": False,
            "hive": hive.to_dict(),
            "note": "registry index job started",
        }

    def _forget(self, hive_id: str) -> None:
        with self._lock:
            self._futures.pop(hive_id, None)

    def _run_index(
        self,
        hive_id: str,
        evidence_id: str,
        entry_id: int,
        recover_with_logs: bool,
        rebuild: bool,
    ) -> None:
        started = time.monotonic()
        deadline = started + float(self.settings.registry_build_timeout)
        hive = None
        try:
            hive = self.store.get_hive(hive_id)
            hive.started_at = _utc_now()
            self.store.update_phase(hive_id, "extracting")
            record = self.evidence.get(evidence_id)
            entry = self.indexer.tree_entry(record, entry_id)
            extracted, reused, note = self._prepare_copy(hive, record, entry)
            size = extracted.stat().st_size
            if size > int(self.settings.registry_max_hive_size):
                self._fail(
                    hive,
                    code="registry_hive_too_large",
                    message=(
                        f"hive size {size} exceeds the configured limit "
                        f"{self.settings.registry_max_hive_size} bytes"
                    ),
                )
                return
            self.store.update_phase(hive_id, "validating")
            sha256, hashed_size = _sha256_file(extracted)
            header = inspect_hive_header(extracted)
            if not header.signature_valid:
                self._fail(
                    hive,
                    code="registry_invalid_signature",
                    message=header.error or "hive has no valid regf signature",
                    extra_warnings=["File was not parsed as a registry hive."],
                )
                return
            scan_id = self._scan_id(record)
            logs = self.index_store.find_transaction_logs(
                evidence_id, scan_id, entry.parent_path or "", entry.basename
            )
            warnings: list[str] = []
            if note:
                warnings.append(note)
            if header.dirty:
                warnings.append(
                    "hive header sequence numbers differ: hive is dirty; the base "
                    "hive was parsed without replaying transaction logs"
                )
            if logs:
                warnings.append(
                    "transaction logs found: "
                    + ", ".join(item["name"] for item in logs)
                    + "; they were not replayed"
                )
            if recover_with_logs:
                warnings.append(
                    "transaction_log_recovery_unavailable: this parser does not "
                    "replay registry transaction logs"
                )
            if hive.sensitive:
                warnings.append(
                    "sensitive hive: metadata only; credential material is never "
                    "decrypted or extracted"
                )
            hive.sha256 = sha256
            hive.size = hashed_size
            try:
                hive.extract_relpath = str(
                    extracted.resolve().relative_to(
                        self.settings.var_dir.resolve()
                    )
                )
            except ValueError:
                hive.extract_relpath = extracted.name
            hive.dirty = bool(header.dirty)
            hive.sequence1 = header.sequence1
            hive.sequence2 = header.sequence2
            hive.recovered = False
            hive.signature_status = "valid"
            hive.transaction_logs = [item["name"] for item in logs]
            hive.warnings = warnings
            self.store.update_phase(hive_id, "parsing")
            reader = HiveReader(extracted, self.settings)
            try:
                self.store.update_phase(hive_id, "indexing")
                keys, values, amcache, error = self.store.index_hive(
                    hive_id, reader.walk(deadline)
                )
            finally:
                reader.close()
            hive.key_count = keys
            hive.value_count = values
            hive.amcache_count = len(amcache)
            if error is not None:
                hive.state = (
                    "partial"
                    if getattr(error, "code", "") in {
                        "registry_timeout",
                        "registry_limit",
                    }
                    else "failed"
                )
                hive.error_code = getattr(error, "code", "registry_error")
                hive.error_message = str(error)[:1000]
                if error.code not in {"registry_timeout", "registry_limit"}:
                    hive.state = "failed"
                hive.warnings.append(str(error)[:500])
            else:
                hive.state = "ready"
            hive.phase = "ready"
            hive.finished_at = _utc_now()
            self.store.finish_hive(hive)
        except (RegistryTimeoutError, RegistryLimitError) as exc:
            if hive is None:
                hive = self.store.get_hive(hive_id)
            hive.state = "partial"
            hive.phase = "ready"
            hive.error_code = getattr(exc, "code", "registry_limit")
            hive.error_message = str(exc)[:1000]
            hive.warnings.append(str(exc)[:500])
            hive.finished_at = _utc_now()
            self.store.finish_hive(hive)
        except DFIRError as exc:
            if hive is None:
                hive = self.store.get_hive(hive_id)
            self._fail(
                hive,
                code=getattr(exc, "code", "registry_error"),
                message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - job isolation
            logger.exception("registry index %s failed", hive_id)
            if hive is None:
                try:
                    hive = self.store.get_hive(hive_id)
                except Exception:
                    hive = None
            if hive is not None:
                self._fail(
                    hive,
                    code="registry_internal_error",
                    message=str(exc)[:500],
                )
        finally:
            self.audit.event(
                "registry_index_finish",
                evidence_id=evidence_id,
                request_id=get_correlation_id(),
                details={
                    "hive_id": hive_id,
                    "entry_id": entry_id,
                    "state": hive.state if hive is not None else "unknown",
                    "keys": hive.key_count if hive is not None else 0,
                    "values": hive.value_count if hive is not None else 0,
                    "amcache": hive.amcache_count if hive is not None else 0,
                    "duration_ms": round((time.monotonic() - started) * 1000.0, 1),
                    "rebuild": bool(rebuild),
                },
            )

    def _prepare_copy(self, hive: RegistryHiveRecord, record, entry):
        if hive.extract_relpath:
            candidate = self.settings.var_dir / hive.extract_relpath
            try:
                resolved = self._validate_extracted(str(candidate))
            except DFIRError as exc:
                note = f"previous working copy was unsafe or missing; re-extracted ({exc.code})"
            else:
                try:
                    sha256, size = _sha256_file(resolved)
                except OSError:
                    note = "previous working copy was unreadable; re-extracted"
                else:
                    if (
                        hive.sha256
                        and sha256 == hive.sha256
                        and (hive.size is None or size == hive.size)
                    ):
                        return resolved, True, "reused the existing working copy"
                    note = "previous working copy changed; re-extracted"
        else:
            note = None
        extraction = self.filesystem.extract_entry(record, entry, CASE_ID)
        extracted = self._validate_extracted(extraction.output_path)
        try:
            os.chmod(extracted, 0o600)
        except OSError:
            pass
        return extracted, False, note

    def _validate_extracted(self, path: str) -> Path:
        exports = self.policy.case_exports_dir(CASE_ID)
        candidate = Path(path)
        try:
            info = os.lstat(candidate)
        except OSError as exc:
            raise RegistryRejectedError(
                "working copy is not accessible",
                code="registry_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise RegistryRejectedError(
                "working copy must not be a symlink",
                code="registry_symlink_rejected",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise RegistryRejectedError(
                "working copy is not accessible",
                code="registry_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if not resolved.is_relative_to(exports.resolve()):
            raise RegistryRejectedError(
                "working copy is outside the case export directory",
                code="registry_path_escape",
            )
        resolved_info = os.lstat(resolved)
        if not stat.S_ISREG(resolved_info.st_mode):
            raise RegistryRejectedError(
                "working copy is not a regular file",
                code="registry_not_regular_file",
            )
        return resolved

    def _relative_to_var(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.settings.var_dir.resolve()))
        except ValueError:
            return path.name

    def _cached_extract_valid(self, hive: RegistryHiveRecord) -> bool:
        if not hive.extract_relpath or not hive.sha256:
            return False
        try:
            resolved = self._validate_extracted(
                str(self.settings.var_dir / hive.extract_relpath)
            )
            sha256, size = _sha256_file(resolved)
        except (DFIRError, OSError):
            return False
        return sha256 == hive.sha256 and (
            hive.size is None or size == hive.size
        )

    def _fail(
        self,
        hive: RegistryHiveRecord,
        *,
        code: str,
        message: str,
        extra_warnings: list[str] | None = None,
    ) -> None:
        hive.state = "failed"
        hive.phase = "ready"
        hive.error_code = code
        hive.error_message = message[:1000]
        hive.finished_at = _utc_now()
        if extra_warnings:
            hive.warnings.extend(extra_warnings)
        self.store.finish_hive(hive)

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def status(self, hive_id: str) -> RegistryHiveRecord:
        hive = self.store.get_hive(hive_id)
        if hive.state == "running":
            pass
        return hive

    def _require_ready(self, hive_id: str) -> RegistryHiveRecord:
        hive = self.store.get_hive(hive_id)
        if hive.state not in {"ready", "partial"}:
            raise HiveNotReadyError(
                "registry hive index is not ready",
                code="hive_not_ready",
                details={"hive_id": hive_id, "state": hive.state},
            )
        return hive

    def list_subkeys(
        self,
        hive_id: str,
        *,
        parent_key_id: int | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> RegistryPage:
        self._require_ready(hive_id)
        if parent_key_id is None:
            # null means "the hive root key's children" for MCP/API callers.
            parent_key_id = self.registry_root_key_id(hive_id)
        else:
            parent_key_id = self._validate_key_id(parent_key_id)
        page, page_size = self._validate_page(page, page_size)
        result = self.store.list_subkeys(
            hive_id, parent_key_id, page, page_size
        )
        self.audit.event(
            "registry_list_subkeys",
            request_id=get_correlation_id(),
            details={
                "hive_id": hive_id,
                "parent_key_id": parent_key_id,
                "page": page,
                "page_size": page_size,
                "returned": len(result.items),
            },
        )
        return result

    def registry_root_key_id(self, hive_id: str) -> int:
        return self.store.root_key(hive_id).key_id

    def get_key(
        self,
        hive_id: str,
        key_id: int,
        *,
        include_values: bool = True,
        binary_preview_bytes: int | None = None,
    ) -> dict[str, Any]:
        self._require_ready(hive_id)
        key_id = self._validate_key_id(key_id)
        preview = self._validate_preview(binary_preview_bytes)
        detail = self.store.get_key(hive_id, key_id, preview)
        payload = detail.to_dict()
        if not include_values:
            payload["values"] = []
        return payload

    def search(
        self,
        hive_id: str,
        query: str,
        *,
        search_key_names: bool = True,
        search_value_names: bool = True,
        search_string_values: bool = True,
        exact: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> RegistryPage:
        self._require_ready(hive_id)
        text = self._validate_query(query)
        page, page_size = self._validate_page(page, page_size)
        result = self.store.search(
            hive_id,
            text,
            search_key_names=search_key_names,
            search_value_names=search_value_names,
            search_string_values=search_string_values,
            exact=exact,
            page=page,
            page_size=page_size,
        )
        self.audit.event(
            "registry_search",
            request_id=get_correlation_id(),
            details={
                "hive_id": hive_id,
                "query_length": len(text),
                "exact": bool(exact),
                "keys": bool(search_key_names),
                "value_names": bool(search_value_names),
                "string_values": bool(search_string_values),
                "results": result.total,
            },
        )
        return result

    def amcache_search(
        self,
        hive_id: str,
        query: str,
        *,
        exact: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> RegistryPage:
        self._require_ready(hive_id)
        text = self._validate_query(query)
        page, page_size = self._validate_page(page, page_size)
        result = self.store.amcache_search(
            hive_id, text, bool(exact), page, page_size
        )
        self.audit.event(
            "amcache_search",
            request_id=get_correlation_id(),
            details={
                "hive_id": hive_id,
                "query_length": len(text),
                "exact": bool(exact),
                "results": result.total,
            },
        )
        return result

    def amcache_record(self, hive_id: str, record_id: int) -> dict[str, Any]:
        self._require_ready(hive_id)
        return self.store.get_amcache(hive_id, self._validate_record_id(record_id))

    def compare_triage(
        self,
        record,
        hive_id: str,
        record_id: int,
        filesystem_entry_id: int,
    ) -> AmcacheCompareResult:
        hive = self._require_ready(hive_id)
        if hive.evidence_id != record.evidence_id:
            raise RegistryRejectedError(
                "hive belongs to a different evidence",
                code="hive_evidence_mismatch",
            )
        amcache = self.store.get_amcache(
            hive_id, self._validate_record_id(record_id)
        )
        entry = self.indexer.tree_entry(record, filesystem_entry_id)
        if entry.entry_type != "file":
            raise RegistryRejectedError(
                "comparison requires a filesystem file entry",
                code="comparison_directory_rejected",
            )
        algorithm = (amcache.get("hash_algorithm") or "unknown").lower()
        wanted_hash = amcache.get("hash_normalized")
        warnings: list[str] = []
        if (
            algorithm not in {"sha1", "sha256", "md5"}
            or not wanted_hash
            or not amcache.get("hash_valid")
        ):
            return AmcacheCompareResult(
                status="unknown" if algorithm == "unknown" else "incompatible",
                algorithm=algorithm if algorithm != "unknown" else None,
                amcache_hash=wanted_hash,
                filesystem_hash=None,
                record_id=record_id,
                filesystem_entry_id=entry.id,
                warnings=["Amcache hash algorithm is unknown or invalid"],
            )
        job = self.triage.store.latest_for_entry(
            record.evidence_id, entry.id
        )
        triage_job_id = job.job_id if job is not None else None
        if job is not None and job.sha256:
            hashes = {"sha1": job.sha1, "sha256": job.sha256, "md5": job.md5}
            source = "triage"
        else:
            resolved = self.triage.sha256_for_entry(record, entry.id)
            hashes = {
                "sha1": resolved.get("sha1"),
                "sha256": resolved.get("sha256"),
                "md5": resolved.get("md5"),
            }
            source = resolved.get("source") or "hash_only"
            warnings.append(f"filesystem hash computed via {source}")
        filesystem_hash = hashes.get(algorithm)
        if not filesystem_hash:
            return AmcacheCompareResult(
                status="unavailable",
                algorithm=algorithm,
                amcache_hash=wanted_hash,
                filesystem_hash=None,
                record_id=record_id,
                filesystem_entry_id=entry.id,
                triage_job_id=triage_job_id,
                warnings=[*warnings, f"{algorithm} is not available for this file"],
            )
        status = (
            "match"
            if filesystem_hash.lower() == wanted_hash.lower()
            else "mismatch"
        )
        self.audit.event(
            "amcache_compare",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "hive_id": hive_id,
                "record_id": record_id,
                "filesystem_entry_id": entry.id,
                "algorithm": algorithm,
                "status": status,
            },
        )
        return AmcacheCompareResult(
            status=status,
            algorithm=algorithm,
            amcache_hash=wanted_hash,
            filesystem_hash=filesystem_hash,
            record_id=record_id,
            filesystem_entry_id=entry.id,
            triage_job_id=triage_job_id,
            warnings=warnings,
        )

    def amcache_lookup_virustotal(
        self,
        record,
        hive_id: str,
        record_id: int,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        hive = self._require_ready(hive_id)
        if hive.evidence_id != record.evidence_id:
            raise RegistryRejectedError(
                "hive belongs to a different evidence",
                code="hive_evidence_mismatch",
            )
        amcache = self.store.get_amcache(
            hive_id, self._validate_record_id(record_id)
        )
        if (
            not amcache.get("hash_valid")
            or amcache.get("hash_algorithm") not in {"sha1", "sha256", "md5"}
            or not amcache.get("hash_normalized")
        ):
            raise RegistryRejectedError(
                "Amcache record has no validated hash to look up",
                code="amcache_hash_unavailable",
            )
        result = self.virustotal.lookup_hash(
            amcache["hash_normalized"],
            force_refresh=force_refresh,
            context={
                "evidence_id": record.evidence_id,
                "hive_id": hive_id,
                "amcache_record_id": record_id,
            },
        )
        result["hive_id"] = hive_id
        result["amcache_record_id"] = record_id
        return result

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    def _validate_page(
        self, page: int, page_size: int | None
    ) -> tuple[int, int]:
        from ..index_models import validate_page, validate_page_size

        return (
            validate_page(page),
            validate_page_size(
                page_size,
                default_size=self.settings.registry_page_size_default,
                max_size=self.settings.registry_page_size_max,
            ),
        )

    @staticmethod
    def _validate_key_id(value: int) -> int:
        try:
            key_id = int(value)
        except (TypeError, ValueError) as exc:
            raise RegistryError(
                "invalid registry key id", code="invalid_key_id"
            ) from exc
        if key_id <= 0:
            raise RegistryError("invalid registry key id", code="invalid_key_id")
        return key_id

    @staticmethod
    def _validate_record_id(value: int) -> int:
        try:
            record_id = int(value)
        except (TypeError, ValueError) as exc:
            raise RegistryError(
                "invalid Amcache record id", code="invalid_amcache_record_id"
            ) from exc
        if record_id <= 0:
            raise RegistryError(
                "invalid Amcache record id", code="invalid_amcache_record_id"
            )
        return record_id

    def _validate_preview(self, value: int | None) -> int:
        default = int(self.settings.registry_binary_preview_bytes)
        if value is None:
            return default
        try:
            preview = int(value)
        except (TypeError, ValueError) as exc:
            raise RegistryError(
                "invalid binary preview size", code="invalid_preview_size"
            ) from exc
        if preview < 0 or preview > 256:
            raise RegistryError(
                "binary preview must be between 0 and 256 bytes",
                code="invalid_preview_size",
            )
        return preview

    @staticmethod
    def _validate_query(query: str) -> str:
        text = (query or "").strip()
        if not text:
            raise RegistryError(
                "search query must not be empty", code="invalid_registry_query"
            )
        if len(text) > MAX_QUERY_LENGTH:
            raise RegistryError(
                f"search query must not exceed {MAX_QUERY_LENGTH} characters",
                code="invalid_registry_query",
            )
        return text
