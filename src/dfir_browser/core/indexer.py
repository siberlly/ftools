from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import AuditLogger, correlation_scope, get_correlation_id
from .command import CommandRunner, sanitize_argv, terminate_process_group
from .config import Settings
from .evidence import EvidenceService
from .index_models import (
    INDEX_SCHEMA_VERSION,
    DeletedFilesQuery,
    FileSearchQuery,
    IndexIncompleteError,
    IndexNotReadyError,
    IndexNotFoundError,
    IndexStartResult,
    IndexStatus,
    IndexStaleError,
    InvalidPageError,
    PaginatedEntries,
    TreePage,
    TreeAncestors,
    EntryNotFoundError,
    IndexedEntry,
    not_ready_error,
    utc_now_iso,
    validate_page,
    validate_page_size,
    validate_sort,
)
from .index_store import IndexStore
from .models import DirEntry, DirectoryListing
from .parsers import FlsLineError, ParsedIndexLine, parse_fls_index_line

logger = logging.getLogger("dfir_browser.indexer")


@dataclass(slots=True)
class _ScanHandle:
    evidence_id: str
    scan_id: str
    stop_event: threading.Event = field(default_factory=threading.Event)
    process: subprocess.Popen | None = None
    thread: threading.Thread | None = None
    lock_fd: int | None = None


@dataclass(slots=True)
class _ScanOutcome:
    argv: list[str]
    exit_code: int | None
    duration_ms: float
    timed_out: bool
    canceled: bool
    limit_reached: bool
    partial_dropped: bool
    entries_seen: int
    entries_indexed: int
    parse_errors: int
    deleted_files: int
    deleted_directories: int
    allocated_files: int
    allocated_directories: int
    stdout_bytes_seen: int
    stderr_bytes_seen: int
    stderr_truncated: bool
    stderr_text: str
    status: str
    error_code: str | None
    error_message: str | None
    current_path: str | None


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _elapsed_seconds(started_at: str | None, completed_at: str | None) -> float | None:
    start = _parse_iso(started_at)
    if start is None:
        return None
    end = _parse_iso(completed_at) or datetime.now(timezone.utc)
    return max(0.0, (end - start).total_seconds())


class FilesystemIndexer:
    """Coordinate recursive filesystem indexing and SQLite-backed queries."""

    def __init__(
        self,
        settings: Settings,
        store: IndexStore,
        evidence: EvidenceService,
        runner: CommandRunner,
        audit: AuditLogger,
    ) -> None:
        self.settings = settings
        self.store = store
        self.evidence = evidence
        self.runner = runner
        self.audit = audit
        self.locks_dir = settings.var_dir / "index" / "locks"
        self.locks_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.locks_dir, 0o700)
        except OSError:
            pass
        self._threads: dict[str, _ScanHandle] = {}
        self._lock = threading.RLock()
        self._fls_version_cache: str | None | bool = False
        self.recover_interrupted()

    # ------------------------------------------------------------------
    # identity / status
    # ------------------------------------------------------------------

    def _fls_version(self) -> str | None:
        if self._fls_version_cache is False:
            try:
                self._fls_version_cache = self.runner.version(
                    self.settings.index_fls_command[0]
                )
            except Exception:
                self._fls_version_cache = None
        return self._fls_version_cache  # type: ignore[return-value]

    def _expected_identity(
        self, record, fls_version: str | None = None
    ) -> dict[str, Any]:
        version = self._fls_version() if fls_version is None else fls_version
        return {
            "source_sha256": record.source_sha256 or "",
            "raw_exposure_path": record.raw_exposure_path or "",
            "filesystem": record.layout.filesystem or "",
            "offset_sectors": int(record.layout.offset_sectors or 0),
            "index_schema_version": INDEX_SCHEMA_VERSION,
            "scanner_version": self.settings.index_scanner_version,
            "fls_version": version or "",
        }

    @staticmethod
    def _identity_matches(
        row: dict[str, Any], expected: dict[str, Any]
    ) -> bool:
        comparisons = (
            ("source_sha256", str),
            ("raw_exposure_path", str),
            ("filesystem", str),
            ("offset_sectors", int),
            ("index_schema_version", int),
            ("scanner_version", str),
            ("fls_version", str),
        )
        for key, cast in comparisons:
            row_value = row.get(key)
            expected_value = expected.get(key)
            if cast is int:
                if int(row_value or 0) != int(expected_value or 0):
                    return False
            elif str(row_value or "") != str(expected_value or ""):
                return False
        return True

    def _build_status(
        self, record, row: dict[str, Any] | None
    ) -> IndexStatus:
        expected = self._expected_identity(record)
        if row is None:
            return IndexStatus(
                evidence_id=record.evidence_id,
                found=False,
                status="pending",
                stale=False,
                queryable=False,
                complete=False,
                scanner_version=self.settings.index_scanner_version,
                warning="Filesystem index has not been built.",
            )

        stale = not self._identity_matches(row, expected)
        status = str(row.get("status") or "pending")
        parse_errors = int(row.get("parse_errors") or 0)
        queryable = (
            not stale and status in {"ready", "incomplete"}
        )
        complete = (
            not stale
            and status == "ready"
            and parse_errors == 0
        )
        if stale:
            warning = (
                "Filesystem index identity does not match the current "
                "evidence, exposure mapping or scanner; rebuild required."
            )
        elif status == "running":
            warning = "Filesystem index scan is running."
        elif status == "pending":
            warning = "Filesystem index has not been built."
        elif status == "failed":
            warning = (
                "Filesystem index failed: "
                + str(row.get("error_message") or row.get("error_code") or "unknown error")
            )
        elif status == "interrupted":
            warning = "Filesystem index scan was interrupted; rebuild required."
        elif status == "incomplete":
            warning = (
                "Filesystem index is incomplete; results may be missing entries."
            )
        elif parse_errors:
            warning = (
                "Filesystem index has parse errors; results may be missing entries."
            )
        else:
            warning = None

        return IndexStatus(
            evidence_id=record.evidence_id,
            found=True,
            status=status,
            stale=stale,
            queryable=queryable,
            complete=complete,
            scan_id=row.get("scan_id"),
            source_sha256=row.get("source_sha256"),
            raw_exposure_path=row.get("raw_exposure_path"),
            filesystem=row.get("filesystem"),
            offset_sectors=(
                int(row["offset_sectors"])
                if row.get("offset_sectors") is not None
                else None
            ),
            fls_version=row.get("fls_version"),
            index_schema_version=int(
                row.get("index_schema_version") or INDEX_SCHEMA_VERSION
            ),
            scanner_version=str(row.get("scanner_version") or ""),
            started_at=row.get("started_at"),
            completed_at=row.get("completed_at"),
            elapsed_seconds=_elapsed_seconds(
                row.get("started_at"), row.get("completed_at")
            ),
            entries_seen=int(row.get("entries_seen") or 0),
            entries_indexed=int(row.get("entries_indexed") or 0),
            parse_errors=parse_errors,
            deleted_files=int(row.get("deleted_files") or 0),
            deleted_directories=int(row.get("deleted_directories") or 0),
            allocated_files=int(row.get("allocated_files") or 0),
            allocated_directories=int(row.get("allocated_directories") or 0),
            current_path=row.get("current_path"),
            error_code=row.get("error_code"),
            error_message=row.get("error_message"),
            warning=warning,
        )

    def status_for_record(self, record) -> IndexStatus:
        return self._build_status(
            record, self.store.get_index_row(record.evidence_id)
        )

    def status(self, evidence_id: str) -> IndexStatus:
        return self.status_for_record(self.evidence.get(evidence_id))

    @staticmethod
    def is_queryable(status: IndexStatus) -> bool:
        return status.queryable

    def _require_queryable(
        self, record, *, require_complete: bool = False
    ) -> tuple[IndexStatus, str]:
        status = self.status_for_record(record)
        if not status.found:
            raise IndexNotFoundError(
                "filesystem index has not been built",
                details={"evidence_id": record.evidence_id},
            )
        if status.stale:
            self.store.mark_stale(record.evidence_id)
            raise IndexStaleError(
                status.warning or "filesystem index is stale",
                details={
                    "evidence_id": record.evidence_id,
                    "status": status.status,
                },
            )
        if not status.queryable:
            raise not_ready_error(status)
        if require_complete and not status.complete:
            raise IndexIncompleteError(
                status.warning or "filesystem index is incomplete",
                details={"evidence_id": record.evidence_id},
            )
        if not status.scan_id:
            raise IndexNotReadyError(
                "filesystem index has no active scan generation",
                details={"evidence_id": record.evidence_id},
            )
        return status, status.scan_id

    # ------------------------------------------------------------------
    # scan lifecycle
    # ------------------------------------------------------------------

    def _lock_path(self, evidence_id: str) -> Path:
        return self.locks_dir / f"{evidence_id}.lock"

    def _acquire_lock(self, evidence_id: str) -> int | None:
        descriptor = os.open(
            self._lock_path(evidence_id), os.O_CREAT | os.O_RDWR, 0o600
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return None
        except OSError:
            os.close(descriptor)
            raise
        return descriptor

    @staticmethod
    def _release_lock(descriptor: int | None) -> None:
        if descriptor is None:
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def recover_interrupted(self) -> None:
        for row in self.store.list_running():
            evidence_id = str(row["evidence_id"])
            scan_id = row.get("scan_id")
            descriptor = self._acquire_lock(evidence_id)
            if descriptor is None:
                # Another process is scanning this evidence.
                continue
            try:
                self.store.mark_interrupted(
                    evidence_id,
                    scan_id,
                    "process restarted while the index scan was running",
                )
                logger.info(
                    "marked interrupted index scan for %s (%s)",
                    evidence_id,
                    scan_id,
                )
            finally:
                self._release_lock(descriptor)

    def start_scan(
        self, evidence_id: str, rebuild: bool = False
    ) -> IndexStartResult:
        record = self.evidence.get(evidence_id)
        existing = self.status_for_record(record)
        if not rebuild and existing.status == "ready" and not existing.stale:
            return IndexStartResult(
                started=False,
                scan_id=existing.scan_id,
                status=existing,
                existing_index_status=existing,
                note="index already ready",
            )
        if not rebuild and existing.status == "running":
            return IndexStartResult(
                started=False,
                scan_id=existing.scan_id,
                status=existing,
                existing_index_status=existing,
                note="index scan already running",
            )

        with self._lock:
            in_process = self._threads.get(evidence_id)
            if in_process is not None and in_process.thread is not None and in_process.thread.is_alive():
                current = self.status_for_record(record)
                return IndexStartResult(
                    started=False,
                    scan_id=in_process.scan_id,
                    status=current,
                    existing_index_status=existing,
                    note="index scan already running",
                )

            descriptor = self._acquire_lock(evidence_id)
            if descriptor is None:
                current = self.status_for_record(record)
                if current.status != "running":
                    current = replace(
                        current,
                        status="running",
                        queryable=False,
                        complete=False,
                        warning="Another filesystem index scan is running.",
                    )
                return IndexStartResult(
                    started=False,
                    scan_id=current.scan_id,
                    status=current,
                    existing_index_status=existing,
                    note="index_running",
                )

            try:
                worker_owns_lock = False
                current = self.status_for_record(record)
                if not rebuild and current.status == "ready" and not current.stale:
                    self._release_lock(descriptor)
                    return IndexStartResult(
                        started=False,
                        scan_id=current.scan_id,
                        status=current,
                        existing_index_status=current,
                        note="index already ready",
                    )
                if current.status in {"pending", "running", "failed", "interrupted"}:
                    if current.status == "running":
                        self.store.mark_interrupted(
                            evidence_id,
                            current.scan_id,
                            "no active scanner lock; recovered before new scan",
                        )
                    current = self.status_for_record(record)

                image = self.evidence.ensure_image(record)

                fls_version = self._fls_version() or ""
                identity = self._expected_identity(record, fls_version)
                scan_id = uuid.uuid4().hex
                started_at = utc_now_iso()
                self.store.begin_scan(
                    evidence_id, scan_id, identity, started_at
                )
                self.audit.event(
                    "index_rebuild" if rebuild else "index_start",
                    evidence_id=evidence_id,
                    request_id=get_correlation_id(),
                    details={
                        "scan_id": scan_id,
                        "rebuild": bool(rebuild),
                        "source_sha256": identity["source_sha256"],
                        "raw_exposure_path": identity["raw_exposure_path"],
                        "filesystem": identity["filesystem"],
                        "offset_sectors": identity["offset_sectors"],
                    },
                )

                handle = _ScanHandle(
                    evidence_id=evidence_id,
                    scan_id=scan_id,
                    lock_fd=descriptor,
                )
                thread = threading.Thread(
                    target=self._run_scan,
                    name=f"dfir-index-{evidence_id}",
                    args=(
                        handle,
                        record,
                        image,
                        scan_id,
                        identity,
                        rebuild,
                    ),
                    daemon=True,
                )
                handle.thread = thread
                self._threads[evidence_id] = handle
                try:
                    thread.start()
                except Exception as exc:
                    self._threads.pop(evidence_id, None)
                    self.store.finish_scan(
                        evidence_id,
                        scan_id,
                        status="failed",
                        entries_seen=0,
                        entries_indexed=0,
                        parse_errors=0,
                        deleted_files=0,
                        deleted_directories=0,
                        allocated_files=0,
                        allocated_directories=0,
                        error_code="index_start_failed",
                        error_message=str(exc),
                    )
                    raise
                worker_owns_lock = True
            except Exception:
                if not worker_owns_lock:
                    self._release_lock(descriptor)
                    descriptor = None
                raise

        status = self.status_for_record(record)
        return IndexStartResult(
            started=True,
            scan_id=scan_id,
            status=status,
            existing_index_status=existing,
            note="index scan started",
        )

    def _run_scan(
        self,
        handle: _ScanHandle,
        record,
        image: Path,
        scan_id: str,
        identity: dict[str, Any],
        rebuild: bool,
    ) -> None:
        error: Exception | None = None
        try:
            with correlation_scope("index") as request_id:
                outcome = self._scan(handle, record, image, scan_id)
                if outcome.status in {"ready", "incomplete"}:
                    # Link the tree before publishing the index as ready so a
                    # concurrent reader can never see ready rows with no parents.
                    self.store.link_tree(handle.evidence_id, scan_id)
                self.store.finish_scan(
                    handle.evidence_id,
                    scan_id,
                    status=outcome.status,
                    entries_seen=outcome.entries_seen,
                    entries_indexed=outcome.entries_indexed,
                    parse_errors=outcome.parse_errors,
                    deleted_files=outcome.deleted_files,
                    deleted_directories=outcome.deleted_directories,
                    allocated_files=outcome.allocated_files,
                    allocated_directories=outcome.allocated_directories,
                    error_code=outcome.error_code,
                    error_message=outcome.error_message,
                    current_path=None,
                )
                self.audit.record(
                    command="fls-index",
                    argv=sanitize_argv(outcome.argv),
                    exit_code=outcome.exit_code,
                    duration_ms=outcome.duration_ms,
                    timed_out=outcome.timed_out or outcome.canceled,
                    stdout_truncated=outcome.limit_reached,
                    stderr_truncated=outcome.stderr_truncated,
                    bytes_seen={
                        "stdout": outcome.stdout_bytes_seen,
                        "stderr": outcome.stderr_bytes_seen,
                    },
                    success=(
                        outcome.exit_code == 0
                        and not outcome.timed_out
                        and not outcome.canceled
                    ),
                    evidence_id=handle.evidence_id,
                    request_id=request_id,
                    extra={
                        "scan_id": scan_id,
                        "entries_seen": outcome.entries_seen,
                        "entries_indexed": outcome.entries_indexed,
                        "parse_errors": outcome.parse_errors,
                        "status": outcome.status,
                        "complete": outcome.status == "ready",
                        "rebuild": bool(rebuild),
                    },
                )
                self.audit.event(
                    (
                        "index_finish"
                        if outcome.status in {"ready", "incomplete"}
                        else "index_failure"
                    ),
                    evidence_id=handle.evidence_id,
                    request_id=request_id,
                    details={
                        "scan_id": scan_id,
                        "status": outcome.status,
                        "complete": outcome.status == "ready",
                        "entries_seen": outcome.entries_seen,
                        "entries_indexed": outcome.entries_indexed,
                        "parse_errors": outcome.parse_errors,
                        "deleted_files": outcome.deleted_files,
                        "deleted_directories": outcome.deleted_directories,
                        "duration_ms": round(outcome.duration_ms, 3),
                        "error_code": outcome.error_code,
                        "rebuild": bool(rebuild),
                    },
                )
                logger.info(
                    "index scan %s for %s finished status=%s entries_seen=%s "
                    "entries_indexed=%s parse_errors=%s duration_ms=%.1f",
                    scan_id,
                    handle.evidence_id,
                    outcome.status,
                    outcome.entries_seen,
                    outcome.entries_indexed,
                    outcome.parse_errors,
                    outcome.duration_ms,
                )
        except Exception as exc:
            error = exc
            logger.exception(
                "index scan %s for %s failed unexpectedly", scan_id, handle.evidence_id
            )
            try:
                self.store.finish_scan(
                    handle.evidence_id,
                    scan_id,
                    status="failed",
                    entries_seen=0,
                    entries_indexed=0,
                    parse_errors=0,
                    deleted_files=0,
                    deleted_directories=0,
                    allocated_files=0,
                    allocated_directories=0,
                    error_code="index_internal_error",
                    error_message=str(exc)[:500],
                )
            except Exception:
                logger.exception("could not record index failure")
            try:
                self.audit.event(
                    "index_failure",
                    evidence_id=handle.evidence_id,
                    details={
                        "scan_id": scan_id,
                        "error_code": "index_internal_error",
                        "error": str(exc)[:300],
                    },
                )
            except Exception:
                pass
        finally:
            with self._lock:
                current = self._threads.get(handle.evidence_id)
                if current is handle:
                    self._threads.pop(handle.evidence_id, None)
            self._release_lock(handle.lock_fd)
            handle.lock_fd = None
            handle.process = None
            _ = error

    def _scan(
        self,
        handle: _ScanHandle,
        record,
        image: Path,
        scan_id: str,
    ) -> _ScanOutcome:
        argv = list(self.settings.index_fls_command)
        offset = int(record.layout.offset_sectors or 0)
        if offset > 0:
            argv.extend(["-o", str(offset)])
        argv.extend(["-r", "-p", "-l", str(image)])

        child_env = dict(os.environ)
        child_env["LC_ALL"] = "C.UTF-8"
        child_env["TZ"] = "UTC"

        start = time.monotonic()
        timed_out_event = threading.Event()
        stdout_bytes_seen = 0
        line_no = 0
        entries_seen = 0
        entries_indexed = 0
        parse_errors = 0
        deleted_files = 0
        deleted_directories = 0
        allocated_files = 0
        allocated_directories = 0
        current_path: str | None = None
        entry_batch: list[tuple[Any, ...]] = []
        error_batch: list[tuple[Any, ...]] = []
        pending_partial: bytes | None = None
        partial_dropped = False
        limit_reached = False

        def record_error(line: str, message: str) -> None:
            nonlocal parse_errors, current_path
            parse_errors += 1
            raw = line.encode("utf-8", "replace")[
                : self.settings.index_max_raw_error_bytes
            ].decode("utf-8", "replace")
            error_batch.append(
                (
                    handle.evidence_id,
                    scan_id,
                    line_no,
                    raw,
                    message,
                    utc_now_iso(),
                )
            )
            if len(error_batch) >= self.settings.index_batch_size:
                self.store.insert_parse_errors(error_batch)
                error_batch.clear()

        def flush_batches() -> None:
            nonlocal current_path
            if entry_batch:
                self.store.insert_entries(entry_batch)
                entry_batch.clear()
            if error_batch:
                self.store.insert_parse_errors(error_batch)
                error_batch.clear()
            self.store.update_progress(
                handle.evidence_id,
                scan_id,
                entries_seen=entries_seen,
                entries_indexed=entries_indexed,
                parse_errors=parse_errors,
                deleted_files=deleted_files,
                deleted_directories=deleted_directories,
                allocated_files=allocated_files,
                allocated_directories=allocated_directories,
                current_path=current_path,
            )

        def consume_line(line: str) -> None:
            nonlocal entries_seen, entries_indexed, deleted_files
            nonlocal deleted_directories, allocated_files
            nonlocal allocated_directories, current_path
            nonlocal limit_reached
            entries_seen += 1
            try:
                entry: ParsedIndexLine = parse_fls_index_line(line)
            except FlsLineError as exc:
                record_error(line, str(exc))
                return
            raw_hash = hashlib.sha256(
                line.encode("utf-8", "replace")
            ).hexdigest()
            entry_batch.append(
                (
                    handle.evidence_id,
                    scan_id,
                    entry.full_path,
                    entry.parent_path,
                    entry.basename,
                    entry.extension,
                    entry.inode,
                    entry.sequence,
                    entry.attribute_id,
                    entry.fls_type,
                    entry.entry_type,
                    1 if entry.allocated else 0,
                    1 if entry.deleted else 0,
                    entry.size,
                    entry.crtime,
                    entry.mtime,
                    entry.atime,
                    entry.ctime,
                    raw_hash,
                    None,
                )
            )
            entries_indexed += 1
            current_path = entry.full_path[:512]
            if entry.deleted:
                if entry.entry_type == "directory":
                    deleted_directories += 1
                else:
                    deleted_files += 1
            else:
                if entry.entry_type == "directory":
                    allocated_directories += 1
                else:
                    allocated_files += 1
            if len(entry_batch) >= self.settings.index_batch_size:
                flush_batches()
            if entries_seen >= self.settings.index_max_entries:
                limit_reached = True

        stderr_file = tempfile.TemporaryFile()
        process: subprocess.Popen | None = None
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                shell=False,
                env=child_env,
                start_new_session=(os.name == "posix"),
            )
            handle.process = process

            def on_timeout() -> None:
                timed_out_event.set()
                if process is not None and process.poll() is None:
                    terminate_process_group(process, logger)

            timer = threading.Timer(
                self.settings.index_timeout, on_timeout
            )
            timer.daemon = True
            timer.start()
            try:
                assert process.stdout is not None
                while not handle.stop_event.is_set():
                    raw = process.stdout.readline(
                        self.settings.index_max_line_bytes + 1
                    )
                    if not raw:
                        break
                    stdout_bytes_seen += len(raw)
                    if not raw.endswith(b"\n"):
                        if len(raw) > self.settings.index_max_line_bytes:
                            line_no += 1
                            record_error(
                                raw.decode("utf-8", "replace"),
                                "line exceeds configured maximum line size",
                            )
                            entries_seen += 1
                            while True:
                                chunk = process.stdout.readline(
                                    self.settings.index_max_line_bytes + 1
                                )
                                if not chunk:
                                    break
                                stdout_bytes_seen += len(chunk)
                                if chunk.endswith(b"\n"):
                                    break
                            continue
                        pending_partial = raw
                        break
                    line_no += 1
                    line = raw.rstrip(b"\r\n").decode(
                        "utf-8", "replace"
                    )
                    if not line.strip():
                        continue
                    consume_line(line)
                    if limit_reached:
                        terminate_process_group(process, logger)
                        break
            finally:
                timer.cancel()

            if process.poll() is None:
                if (
                    timed_out_event.is_set()
                    or handle.stop_event.is_set()
                    or limit_reached
                ):
                    terminate_process_group(process, logger)
                else:
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        terminate_process_group(process, logger)
            exit_code = process.returncode

            canceled = handle.stop_event.is_set()
            timed_out = timed_out_event.is_set()
            if pending_partial is not None:
                if (
                    not timed_out
                    and not canceled
                    and not limit_reached
                    and exit_code == 0
                ):
                    line_no += 1
                    line = pending_partial.rstrip(b"\r\n").decode(
                        "utf-8", "replace"
                    )
                    if line.strip():
                        consume_line(line)
                else:
                    line_no += 1
                    entries_seen += 1
                    partial_dropped = True
                    record_error(
                        pending_partial.decode("utf-8", "replace"),
                        "final partial line dropped because output was incomplete",
                    )
            flush_batches()
        finally:
            if process is not None and process.poll() is None:
                terminate_process_group(process, logger)
            if process is not None and process.stdout is not None:
                try:
                    process.stdout.close()
                except OSError:
                    pass
            stderr_file.seek(0, os.SEEK_END)
            stderr_bytes_seen = stderr_file.tell()
            stderr_file.seek(0)
            stderr_raw = stderr_file.read(
                self.settings.index_max_raw_error_bytes
            )
            stderr_text = stderr_raw.decode("utf-8", "replace")
            stderr_truncated = (
                stderr_bytes_seen > self.settings.index_max_raw_error_bytes
            )
            stderr_file.close()

        duration_ms = (time.monotonic() - start) * 1000.0
        canceled = handle.stop_event.is_set()
        timed_out = timed_out_event.is_set()

        if canceled:
            status = "interrupted"
            error_code = "interrupted"
            error_message = "index scan was canceled by process shutdown"
        elif timed_out:
            status = "failed"
            error_code = "index_timeout"
            error_message = (
                f"index scan exceeded the {self.settings.index_timeout:g}s limit"
            )
        elif limit_reached:
            status = "incomplete"
            error_code = "index_entry_limit"
            error_message = (
                "index scan stopped at the configured entry limit "
                f"({self.settings.index_max_entries})"
            )
        elif exit_code != 0:
            status = "failed"
            error_code = "fls_failed"
            error_message = (
                f"fls exited with code {exit_code}"
                + (f": {stderr_text[:500]}" if stderr_text else "")
            )
        elif partial_dropped:
            status = "incomplete"
            error_code = "partial_output"
            error_message = "final fls output line was incomplete and was dropped"
        elif parse_errors:
            status = "incomplete"
            error_code = "parse_errors"
            error_message = f"{parse_errors} fls output line(s) could not be parsed"
        else:
            status = "ready"
            error_code = None
            error_message = None

        return _ScanOutcome(
            argv=argv,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            canceled=canceled,
            limit_reached=limit_reached,
            partial_dropped=partial_dropped,
            entries_seen=entries_seen,
            entries_indexed=entries_indexed,
            parse_errors=parse_errors,
            deleted_files=deleted_files,
            deleted_directories=deleted_directories,
            allocated_files=allocated_files,
            allocated_directories=allocated_directories,
            stdout_bytes_seen=stdout_bytes_seen,
            stderr_bytes_seen=stderr_bytes_seen,
            stderr_truncated=stderr_truncated,
            stderr_text=stderr_text,
            status=status,
            error_code=error_code,
            error_message=error_message,
            current_path=current_path,
        )

    def cancel_all(self) -> None:
        with self._lock:
            handles = list(self._threads.values())
        for handle in handles:
            handle.stop_event.set()
            process = handle.process
            if process is not None and process.poll() is None:
                terminate_process_group(process, logger)
        for handle in handles:
            if handle.thread is not None:
                handle.thread.join(timeout=10.0)
                if handle.thread.is_alive():
                    logger.warning(
                        "index scan %s for %s did not stop in time",
                        handle.scan_id,
                        handle.evidence_id,
                    )
                    try:
                        self.store.mark_interrupted(
                            handle.evidence_id,
                            handle.scan_id,
                            "process shutdown while index scan was running",
                        )
                    except Exception:
                        pass
                    self._release_lock(handle.lock_fd)
                    handle.lock_fd = None

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    def _page_args(
        self, page: int, page_size: int | None
    ) -> tuple[int, int]:
        return (
            validate_page(page),
            validate_page_size(
                page_size,
                default_size=self.settings.index_page_size_default,
                max_size=self.settings.index_page_size_max,
            ),
        )

    def _summary(self, status: IndexStatus) -> dict[str, Any]:
        return {
            "entries_seen": status.entries_seen,
            "entries_indexed": status.entries_indexed,
            "deleted_files": status.deleted_files,
            "deleted_directories": status.deleted_directories,
            "allocated_files": status.allocated_files,
            "allocated_directories": status.allocated_directories,
            "parse_errors": status.parse_errors,
            "index_complete": status.complete,
            "index_status": status.status,
            "index_stale": status.stale,
        }

    def resolve_directory_path(self, record, inode: int) -> str | None:
        _status, scan_id = self._require_queryable(record)
        return self.store.resolve_directory_path(
            record.evidence_id, scan_id, inode
        )

    def list_directory(
        self,
        record,
        path: str = "",
        *,
        page: int = 1,
        page_size: int | None = None,
    ) -> DirectoryListing:
        status, scan_id = self._require_queryable(record)
        page, page_size = self._page_args(page, page_size)
        normalized_path = (path or "").strip("/")
        entries, total = self.store.query_directory(
            record.evidence_id,
            scan_id,
            normalized_path,
            page_size,
            (page - 1) * page_size,
        )
        dir_entries = [
            DirEntry(
                name=entry.basename,
                inode=entry.inode or 0,
                sequence=entry.sequence,
                attribute_id=entry.attribute_id,
                entry_type=entry.entry_type,
                allocated=entry.allocated,
                deleted=entry.deleted,
                size=entry.size,
                mtime=entry.modified_time,
                atime=entry.accessed_time,
                ctime=entry.mft_modified_time,
                crtime=entry.created_time,
                full_path=entry.full_path,
                parent_path=entry.parent_path,
                basename=entry.basename,
                extension=entry.extension,
                fls_type=entry.fls_type,
            )
            for entry in entries
        ]
        breadcrumb: list[dict[str, Any]] = [{"name": "/", "path": ""}]
        if normalized_path:
            accumulated: list[str] = []
            for part in normalized_path.split("/"):
                accumulated.append(part)
                breadcrumb.append(
                    {"name": part, "path": "/".join(accumulated)}
                )
        inode = 5
        if normalized_path:
            inode = (
                self.store.resolve_directory_inode(
                    record.evidence_id, scan_id, normalized_path
                )
                or 0
            )
        return DirectoryListing(
            evidence_id=record.evidence_id,
            inode=inode,
            offset_sectors=int(record.layout.offset_sectors or 0),
            breadcrumb=breadcrumb,
            entries=dir_entries,
            warnings=[status.warning] if status.warning else [],
            tool_version=status.fls_version,
            command={},
            complete=status.complete,
            truncated=False,
            warning=status.warning,
            cursor=None,
            next_cursor=(
                str(page + 1) if page * page_size < total else None
            ),
            source="index",
            path=normalized_path,
            index_status=status.status,
            total=total,
            page=page,
            page_size=page_size,
        )

    def list_all_under(
        self,
        record,
        path: str = "",
        *,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
    ) -> PaginatedEntries:
        status, scan_id = self._require_queryable(record)
        page, page_size = self._page_args(page, page_size)
        sort, sort_dir = validate_sort(sort, sort_dir)
        normalized_path = (path or "").strip("/")
        rows, total = self.store.query_all_under(
            record.evidence_id,
            scan_id,
            normalized_path,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        self.audit.event(
            "entries_list",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "has_path": bool(normalized_path),
                "page": page,
                "page_size": page_size,
                "sort": sort,
                "sort_dir": sort_dir,
            },
        )
        return PaginatedEntries(
            results=rows,
            total=total,
            page=page,
            page_size=page_size,
            index_status=status,
            complete=status.complete,
            warning=status.warning,
            summary=self._summary(status),
            sort=sort,
            sort_dir=sort_dir,
        )

    def list_deleted(
        self, record, query: DeletedFilesQuery
    ) -> PaginatedEntries:
        status, scan_id = self._require_queryable(record)
        rows, total = self.store.query_deleted(
            record.evidence_id,
            scan_id,
            include_directories=query.include_directories,
            extension=query.extension,
            search=query.search,
            sort=query.sort,
            sort_dir=query.sort_dir,
            page=query.page,
            page_size=query.page_size,
        )
        self.audit.event(
            "deleted_list",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "include_directories": query.include_directories,
                "has_extension": bool(query.extension),
                "has_search": bool(query.search),
                "page": query.page,
                "page_size": query.page_size,
                "sort": query.sort,
                "sort_dir": query.sort_dir,
            },
        )
        return PaginatedEntries(
            results=rows,
            total=total,
            page=query.page,
            page_size=query.page_size,
            index_status=status,
            complete=status.complete,
            warning=status.warning,
            summary=self._summary(status),
            sort=query.sort,
            sort_dir=query.sort_dir,
        )

    def search(self, record, query: FileSearchQuery) -> PaginatedEntries:
        status, scan_id = self._require_queryable(record)
        rows, total = self.store.search(
            record.evidence_id,
            scan_id,
            query=query.query,
            exact=query.exact,
            extension=query.extension,
            deleted_only=query.deleted_only,
            allocated_only=query.allocated_only,
            entry_type=query.entry_type,
            sort=query.sort,
            sort_dir=query.sort_dir,
            page=query.page,
            page_size=query.page_size,
        )
        self.audit.event(
            "search",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "query_length": len(query.query),
                "exact": query.exact,
                "has_extension": bool(query.extension),
                "deleted_only": query.deleted_only,
                "allocated_only": query.allocated_only,
                "entry_type": query.entry_type,
                "page": query.page,
                "page_size": query.page_size,
                "sort": query.sort,
                "sort_dir": query.sort_dir,
            },
        )
        return PaginatedEntries(
            results=rows,
            total=total,
            page=query.page,
            page_size=query.page_size,
            index_status=status,
            complete=status.complete,
            warning=status.warning,
            summary=self._summary(status),
            sort=query.sort,
            sort_dir=query.sort_dir,
        )

    # ------------------------------------------------------------------
    # tree navigation
    # ------------------------------------------------------------------

    def _tree_status(
        self, record, *, require_complete: bool = False
    ) -> tuple[IndexStatus, str]:
        return self._require_queryable(record, require_complete=require_complete)

    def tree_page(
        self,
        record,
        parent_entry_id: int,
        *,
        include_deleted: bool = True,
        directories_only: bool = False,
        filter_text: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
    ) -> TreePage:
        from .index_models import (
            ROOT_ENTRY_ID,
            TreePage,
            validate_entry_id,
            validate_page,
            validate_page_size,
            validate_sort,
            validate_tree_filter,
        )

        status, scan_id = self._tree_status(record)
        entry_id = validate_entry_id(parent_entry_id)
        page = validate_page(page)
        page_size = validate_page_size(
            page_size,
            default_size=self.settings.index_page_size_default,
            max_size=self.settings.index_page_size_max,
        )
        sort, sort_dir = validate_sort(sort, sort_dir)
        filter_text = validate_tree_filter(filter_text)

        parent_node = None
        parent_id: int | None = None
        if entry_id != ROOT_ENTRY_ID:
            parent = self.store.get_entry(
                record.evidence_id, scan_id, entry_id
            )
            if parent.entry_type != "directory":
                raise IndexNotReadyError(
                    "tree children can only be listed for directories",
                    code="not_a_directory",
                    details={"entry_id": entry_id},
                )
            parent_id = parent.id
            parent_node = parent.to_tree_node(has_children=True)

        rows, total = self.store.children_of(
            record.evidence_id,
            scan_id,
            parent_id,
            include_deleted=include_deleted,
            directories_only=directories_only,
            filter_text=filter_text,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        self.audit.event(
            "tree_children",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "parent_entry_id": entry_id,
                "page": page,
                "page_size": page_size,
                "include_deleted": include_deleted,
                "directories_only": directories_only,
                "has_filter": bool(filter_text),
                "returned": len(rows),
            },
        )
        return TreePage(
            evidence_id=record.evidence_id,
            parent=parent_node,
            children=[
                row.to_tree_node(has_children=bool(row.entry_type == "directory"))
                for row in rows
            ],
            total=total,
            page=page,
            page_size=page_size,
            include_deleted=include_deleted,
            directories_only=directories_only,
            filter=filter_text,
            index_status=status,
            complete=status.complete,
            warning=status.warning,
            sort=sort,
            sort_dir=sort_dir,
        )

    def tree_entry(self, record, entry_id: int) -> IndexedEntry:
        from .index_models import validate_entry_id

        _status, scan_id = self._tree_status(record)
        return self.store.get_entry(
            record.evidence_id, scan_id, validate_entry_id(entry_id)
        )

    def tree_ancestors(self, record, entry_id: int) -> TreeAncestors:
        from .index_models import (
            ROOT_ENTRY_ID,
            TreeAncestors,
            validate_entry_id,
        )

        status, scan_id = self._tree_status(record)
        entry_pk = validate_entry_id(entry_id)
        if entry_pk == ROOT_ENTRY_ID:
            raise EntryNotFoundError(
                "the synthetic root has no ancestors",
                details={"entry_id": entry_pk},
            )
        entry, ancestors = self.store.entry_ancestors(
            record.evidence_id, scan_id, entry_pk
        )
        return TreeAncestors(
            evidence_id=record.evidence_id,
            entry=entry.to_tree_node(),
            ancestors=[node.to_tree_node() for node in ancestors],
            root_id=ROOT_ENTRY_ID,
            resolvable=True,
            warning=status.warning,
            index_status=status,
        )

    def tree_reveal(self, record, entry_id: int) -> dict[str, Any]:
        """Return the ancestor chain and the child page needed to reveal a node."""
        from .index_models import ROOT_ENTRY_ID, validate_entry_id

        status, scan_id = self._tree_status(record)
        entry_pk = validate_entry_id(entry_id)
        if entry_pk == ROOT_ENTRY_ID:
            return {
                "trust": "untrusted_evidence_data",
                "evidence_id": record.evidence_id,
                "entry_id": ROOT_ENTRY_ID,
                "entry": None,
                "ancestors": [],
                "steps": [],
                "resolvable": True,
                "warning": None,
                "index_status": status.status,
            }
        entry, ancestors = self.store.entry_ancestors(
            record.evidence_id, scan_id, entry_pk
        )
        page_size = self.settings.index_page_size_max
        steps: list[dict[str, Any]] = []
        chain = [*ancestors, entry]
        for index in range(len(chain) - 1):
            parent = chain[index]
            child = chain[index + 1]
            if parent.entry_type != "directory":
                continue
            steps.append(
                {
                    "parent_id": parent.id,
                    "parent_path": parent.full_path,
                    "child_id": child.id,
                    "page": self.store.child_page_of(
                        record.evidence_id,
                        scan_id,
                        parent.id,
                        child.id,
                        page_size,
                    ),
                    "page_size": page_size,
                }
            )
        warning = None
        if entry.parent_id is None and entry.parent_path:
            warning = (
                "Entry is attached to the volume root because its parent "
                "directory is absent from the index (for example orphaned "
                "entries)."
            )
        return {
            "trust": "untrusted_evidence_data",
            "evidence_id": record.evidence_id,
            "entry_id": entry.id,
            "entry": entry.to_tree_node().to_dict(),
            "ancestors": [node.to_tree_node().to_dict() for node in ancestors],
            "steps": steps,
            "resolvable": True,
            "warning": warning,
            "index_status": status.status,
        }

    def resolve_entry_path(self, record, path: str) -> IndexedEntry:
        """Resolve a normalized index path to exactly one entry (no host FS)."""
        _status, scan_id = self._tree_status(record)
        normalized = (path or "").strip("/")
        if not normalized:
            raise EntryNotFoundError(
                "empty path does not identify an entry",
                details={"path": path},
            )
        return self.store.get_entry_by_path(
            record.evidence_id, scan_id, normalized
        )
