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
from .detector import classify_entry, inspect_evtx_header, level_name
from .index import EvtxStore
from .models import (
    EVTX_SCHEMA_VERSION,
    EventPage,
    EventQuery,
    EvtxError,
    EvtxEvent,
    EvtxLog,
    EvtxLogNotReady,
    EvtxRejected,
    LOG_PHASES,
    LogCandidate,
    log_id_for,
)
from .parser import (
    EvtxBackend,
    EvtxLimit,
    EvtxTimeout,
    normalize_event,
)
from .presets import PresetNotFound, get_preset, list_presets

logger = logging.getLogger("dfir_browser.evtx")

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


class EvtxService:
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
        store: EvtxStore,
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
            max_workers=max(1, int(settings.evtx_max_concurrent_jobs)),
            thread_name_prefix="dfir-evtx",
        )
        self.store.ensure_schema()
        interrupted = self.store.recover_interrupted()
        if interrupted:
            logger.warning(
                "marked %s EVTX log(s) interrupted after restart", interrupted
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
            raise EvtxRejected(
                "filesystem index must be ready to discover event logs",
                code="index_not_ready",
                details={"status": status.status, "stale": status.stale},
            )
        row = self.index_store.get_index_row(record.evidence_id)
        if row is None or not row.get("scan_id"):
            raise EvtxRejected("filesystem index has no active scan")
        return str(row["scan_id"])

    def list_logs(
        self,
        record,
        *,
        include_deleted: bool = False,
        indexed_only: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ):
        page, page_size = self._validate_page(page, page_size)
        scan_id = self._scan_id(record)
        entries = self.index_store.find_evtx_candidates(
            record.evidence_id, scan_id, include_deleted=include_deleted
        )
        indexed = {
            log.entry_id: log
            for log in self.store.list_for_evidence(record.evidence_id)
        }
        candidates: list[LogCandidate] = []
        for entry in entries:
            candidate = classify_entry(entry, evidence_id=record.evidence_id)
            if candidate is None:
                continue
            candidate.log_id = log_id_for(record.evidence_id, entry.id)
            known = indexed.get(entry.id)
            if known is not None:
                candidate.log_id = known.log_id
                candidate.state = known.status
                candidate.index_status = known.status
                candidate.records_indexed = known.records_indexed
                candidate.parse_errors = known.parse_errors
                candidate.first_event_time = known.first_event_time
                candidate.last_event_time = known.last_event_time
            if indexed_only and known is None:
                continue
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                0 if item.priority else 1,
                item.channel.lower(),
                item.name.lower(),
            )
        )
        total = len(candidates)
        start = (page - 1) * page_size
        from .models import EventPage as _Page  # local to avoid name clash

        return _SimplePage(
            items=candidates[start : start + page_size],
            total=total,
            page=page,
            page_size=page_size,
        )

    # ------------------------------------------------------------------
    # indexing
    # ------------------------------------------------------------------
    def start_index(
        self, record, entry_id: int, *, rebuild: bool = False
    ) -> dict[str, Any]:
        self._scan_id(record)
        entry = self.indexer.tree_entry(record, entry_id)
        if entry.entry_type != "file":
            raise EvtxRejected(
                "EVTX indexing only accepts files",
                code="evtx_directory_rejected",
            )
        if entry.inode is None and entry.backend_type != "ad1":
            raise EvtxRejected(
                "entry has no MFT/inode and cannot be extracted",
                code="evtx_entry_without_inode",
            )
        candidate = classify_entry(entry, evidence_id=record.evidence_id)
        if candidate is None:
            raise EvtxRejected(
                "entry does not look like a Windows Event Log",
                code="evtx_not_candidate",
            )
        if entry.size is not None and int(entry.size) > int(
            self.settings.evtx_max_file_size
        ):
            raise EvtxRejected(
                "event log exceeds the configured maximum size",
                code="evtx_file_too_large",
                details={
                    "size": entry.size,
                    "limit": self.settings.evtx_max_file_size,
                },
            )
        log_id = log_id_for(record.evidence_id, entry.id)
        existing = self.store.find_by_entry(record.evidence_id, entry.id)
        if (
            existing is not None
            and not rebuild
            and existing.status in {"ready", "partial"}
            and existing.index_schema == EVTX_SCHEMA_VERSION
            and existing.parser_version == self.settings.evtx_parser_version
            and self._cached_copy_valid(existing)
        ):
            return {
                "started": False,
                "cached": True,
                "log": existing.to_dict(),
                "note": "existing EVTX index is valid; nothing was re-extracted",
            }
        limit = max(1, int(self.settings.evtx_max_concurrent_jobs)) + max(
            0, int(self.settings.evtx_max_queued_jobs)
        )
        with self._lock:
            active = int(
                self.store._connect()
                .execute(
                    "SELECT COUNT(*) AS n FROM evtx_logs "
                    "WHERE status IN ('queued','running')"
                )
                .fetchone()["n"]
            )
        if active >= limit:
            raise EvtxRejected(
                "too many EVTX index jobs are queued or running",
                code="evtx_queue_full",
                details={"limit": limit},
            )
        log = EvtxLog(
            log_id=log_id,
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            inode=entry.inode,
            evidence_path=entry.full_path,
            filename=entry.basename,
            detected_channel=candidate.channel,
            size=entry.size,
            sha256=None,
            allocated=bool(entry.allocated),
            deleted=bool(entry.deleted),
            parser=EvtxBackend.name,
            parser_version=self.settings.evtx_parser_version,
            index_schema=EVTX_SCHEMA_VERSION,
            status="queued",
            phase="queued",
            records_seen=0,
            records_indexed=0,
            parse_errors=0,
            first_event_time=None,
            last_event_time=None,
            extract_relpath=None,
            warnings=list(candidate.warnings),
            created_at=_now(),
        )
        if existing is not None and existing.entry_id == entry.id:
            log.created_at = existing.created_at
        self.store.upsert_log(log)
        with self._lock:
            future = self._executor.submit(
                self._run_index, log_id, record.evidence_id, entry.id
            )
            self._futures[log_id] = future
            future.add_done_callback(
                lambda _f, key=log_id: self._forget(key)
            )
        self.audit.event(
            "evtx_index_start",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "log_id": log_id,
                "entry_id": entry.id,
                "inode": entry.inode,
                "channel": candidate.channel,
                "rebuild": bool(rebuild),
            },
        )
        return {
            "started": True,
            "cached": False,
            "log": log.to_dict(),
            "note": "EVTX index job started",
        }

    def _forget(self, log_id: str) -> None:
        with self._lock:
            self._futures.pop(log_id, None)

    def _run_index(self, log_id: str, evidence_id: str, entry_id: int) -> None:
        started = time.monotonic()
        deadline = started + float(self.settings.evtx_index_timeout)
        log = None
        try:
            log = self.store.get_log(log_id)
            log.started_at = _now()
            self.store.update_phase(log_id, "extracting")
            record = self.evidence.get(evidence_id)
            entry = self.indexer.tree_entry(record, entry_id)
            extracted, reused, note = self._prepare_copy(log, record, entry)
            size = extracted.stat().st_size
            if size > int(self.settings.evtx_max_file_size):
                self._fail(
                    log,
                    code="evtx_file_too_large",
                    message=f"file size {size} exceeds the configured maximum",
                )
                return
            self.store.update_phase(log_id, "validating")
            sha256, hashed = _sha256_file(extracted)
            header = inspect_evtx_header(extracted)
            if not header.signature_valid:
                self._fail(
                    log,
                    code="evtx_invalid_signature",
                    message=header.error or "file has no ElfFile signature",
                )
                return
            warnings = list(log.warnings)
            if note:
                warnings.append(note)
            if header.chunk_count is not None and header.chunk_count == 0:
                warnings.append("EVTX header reports zero chunks")
            log.sha256 = sha256
            log.size = hashed
            try:
                log.extract_relpath = str(
                    extracted.resolve().relative_to(
                        self.settings.var_dir.resolve()
                    )
                )
            except ValueError:
                log.extract_relpath = extracted.name
            log.warnings = warnings
            self.store.update_phase(log_id, "parsing")

            backend = EvtxBackend(extracted, self.settings)
            batch: list[EvtxEvent] = []
            errors: list[tuple[int | None, str]] = []
            parse_error_count = 0
            seen = 0
            indexed = 0
            first_ts = None
            last_ts = None
            batch_size = max(1, int(self.settings.evtx_batch_size))
            try:
                for raw in backend.records(deadline):
                    seen += 1
                    if raw.error:
                        errors.append((raw.record_id, raw.error))
                        parse_error_count += 1
                        continue
                    if raw.xml_too_large:
                        errors.append(
                            (
                                raw.record_id,
                                f"event XML exceeds {self.settings.evtx_max_event_xml_bytes} bytes",
                            )
                        )
                        parse_error_count += 1
                        continue
                    parsed = normalize_event(
                        log_id=log_id,
                        raw=raw,
                        xml_text=raw.xml,
                        settings=self.settings,
                        channel_fallback=log.detected_channel,
                    )
                    if parsed.record_id is None:
                        errors.append((raw.record_id, "missing record id"))
                        parse_error_count += 1
                        continue
                    event = EvtxEvent(
                        log_id=log_id,
                        record_id=parsed.record_id,
                        chunk_number=parsed.chunk_number,
                        timestamp_utc=parsed.timestamp_utc,
                        timestamp_raw=parsed.timestamp_raw,
                        channel=parsed.channel,
                        provider_name=parsed.provider_name,
                        provider_guid=parsed.provider_guid,
                        event_id=parsed.event_id,
                        event_id_raw=parsed.event_id_raw,
                        qualifiers=parsed.qualifiers,
                        level=parsed.level,
                        level_name=level_name(parsed.level),
                        task=parsed.task,
                        opcode=parsed.opcode,
                        keywords=parsed.keywords,
                        computer=parsed.computer,
                        user_sid=parsed.user_sid,
                        process_id=parsed.process_id,
                        thread_id=parsed.thread_id,
                        activity_id=parsed.activity_id,
                        related_activity_id=parsed.related_activity_id,
                        version=parsed.version,
                        event_data=parsed.event_data,
                        user_data=parsed.user_data,
                        rendering_info=parsed.rendering_info,
                        message=parsed.message,
                        message_status=parsed.message_status,
                        raw_xml=parsed.raw_xml,
                        raw_xml_sha256=parsed.raw_xml_sha256,
                        summary=parsed.summary,
                        truncated=parsed.truncated,
                        parse_warnings=parsed.warnings,
                    )
                    batch.append(event)
                    indexed += 1
                    if parsed.timestamp_utc:
                        if first_ts is None or parsed.timestamp_utc < first_ts:
                            first_ts = parsed.timestamp_utc
                        if last_ts is None or parsed.timestamp_utc > last_ts:
                            last_ts = parsed.timestamp_utc
                    if len(batch) >= batch_size:
                        self.store.insert_events(log_id, batch)
                        batch.clear()
                    if len(errors) >= batch_size:
                        self.store.insert_parse_errors(log_id, errors)
                        errors.clear()
            except EvtxTimeout as exc:
                log.status = "partial"
                log.error_code = exc.code
                log.error_message = str(exc)
                warnings.append(str(exc))
            except EvtxLimit as exc:
                log.status = "partial"
                log.error_code = exc.code
                log.error_message = str(exc)
                warnings.append(str(exc))
            if batch:
                self.store.insert_events(log_id, batch)
            if errors:
                self.store.insert_parse_errors(log_id, errors)
            log.records_seen = seen
            log.records_indexed = indexed
            # ``errors`` is a bounded buffer and can be flushed several times;
            # retain the full count rather than only the final partial batch.
            log.parse_errors = parse_error_count
            log.first_event_time = first_ts
            log.last_event_time = last_ts
            log.phase = "ready"
            log.completed_at = _now()
            if log.status not in {"partial"}:
                log.status = "ready" if log.parse_errors == 0 else "partial"
            if log.status == "partial" and not log.error_message:
                log.error_message = (
                    f"{log.parse_errors} record(s) could not be parsed"
                )
            log.warnings = list(dict.fromkeys(warnings))
            self.store.finish_log(log)
        except DFIRError as exc:
            if log is None:
                log = self.store.get_log(log_id)
            self._fail(
                log, code=getattr(exc, "code", "evtx_error"), message=str(exc)
            )
        except Exception as exc:  # noqa: BLE001 - job isolation
            logger.exception("EVTX index %s failed", log_id)
            if log is None:
                try:
                    log = self.store.get_log(log_id)
                except Exception:
                    log = None
            if log is not None:
                self._fail(
                    log, code="evtx_internal_error", message=str(exc)[:500]
                )
        finally:
            self.audit.event(
                "evtx_index_finish",
                evidence_id=evidence_id,
                request_id=get_correlation_id(),
                details={
                    "log_id": log_id,
                    "entry_id": entry_id,
                    "status": log.status if log else "unknown",
                    "records_seen": log.records_seen if log else 0,
                    "records_indexed": log.records_indexed if log else 0,
                    "parse_errors": log.parse_errors if log else 0,
                    "duration_ms": round((time.monotonic() - started) * 1000.0, 1),
                },
            )

    def _prepare_copy(self, log: EvtxLog, record, entry):
        if log.extract_relpath:
            candidate = self.settings.var_dir / log.extract_relpath
            try:
                resolved = self._validate_extracted(str(candidate))
            except DFIRError as exc:
                note = (
                    "previous working copy was unsafe or missing; "
                    f"re-extracted ({exc.code})"
                )
            else:
                try:
                    sha256, size = _sha256_file(resolved)
                except OSError:
                    note = "previous working copy was unreadable; re-extracted"
                else:
                    if (
                        log.sha256
                        and sha256 == log.sha256
                        and (log.size is None or size == log.size)
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
            raise EvtxRejected(
                "working copy is not accessible",
                code="evtx_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise EvtxRejected(
                "working copy must not be a symlink",
                code="evtx_symlink_rejected",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise EvtxRejected(
                "working copy is not accessible",
                code="evtx_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if not resolved.is_relative_to(exports.resolve()):
            raise EvtxRejected(
                "working copy is outside the case export directory",
                code="evtx_path_escape",
            )
        if not stat.S_ISREG(os.lstat(resolved).st_mode):
            raise EvtxRejected(
                "working copy is not a regular file",
                code="evtx_not_regular_file",
            )
        return resolved

    def _cached_copy_valid(self, log: EvtxLog) -> bool:
        if not log.extract_relpath or not log.sha256:
            return False
        try:
            resolved = self._validate_extracted(
                str(self.settings.var_dir / log.extract_relpath)
            )
            sha256, size = _sha256_file(resolved)
        except (DFIRError, OSError):
            return False
        return sha256 == log.sha256 and (log.size is None or size == log.size)

    def _fail(self, log: EvtxLog, *, code: str, message: str) -> None:
        log.status = "failed"
        log.phase = "ready"
        log.error_code = code
        log.error_message = message[:1000]
        log.completed_at = _now()
        self.store.finish_log(log)

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def status(self, log_id: str) -> EvtxLog:
        return self.store.get_log(log_id)

    def _require_ready(self, log_id: str) -> EvtxLog:
        log = self.store.get_log(log_id)
        if log.status not in {"ready", "partial"}:
            raise EvtxLogNotReady(
                "EVTX log index is not ready",
                details={"log_id": log_id, "status": log.status},
            )
        return log

    def query(
        self,
        record,
        *,
        log_ids: list[str] | None = None,
        channels: list[str] | None = None,
        providers: list[str] | None = None,
        event_ids: list[int] | None = None,
        levels: list[int] | None = None,
        user_sid: str | None = None,
        computer: str | None = None,
        process_id: int | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        text: str | None = None,
        preset: str | None = None,
        sort_dir: str = "asc",
        page: int = 1,
        page_size: int | None = None,
    ) -> EventPage:
        page, page_size = self._validate_page(page, page_size)
        sort_dir = "desc" if str(sort_dir).lower() == "desc" else "asc"
        resolved_logs = self._resolve_log_ids(record, log_ids)
        if preset:
            try:
                definition = get_preset(preset)
            except PresetNotFound as exc:
                raise EvtxRejected(str(exc), code="evtx_unknown_preset") from exc
            event_ids = list(definition.event_ids)
            if not channels:
                channels = list(definition.channels) or None
        query = EventQuery(
            log_ids=resolved_logs,
            channels=[c for c in (channels or []) if c][:20],
            providers=[p for p in (providers or []) if p][:20],
            event_ids=[int(item) for item in (event_ids or [])][:50],
            levels=[int(item) for item in (levels or [])][:10],
            user_sid=(user_sid or "").strip()[:128] or None,
            computer=(computer or "").strip()[:128] or None,
            process_id=int(process_id) if process_id is not None else None,
            time_from=self._validate_time(time_from, "time_from"),
            time_to=self._validate_time(time_to, "time_to"),
            text=self._validate_text(text),
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )
        result = self.store.query_events(query)
        result.log_ids = resolved_logs
        self.audit.event(
            "evtx_query",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "log_ids": resolved_logs,
                "event_ids": query.event_ids,
                "channels": query.channels,
                "preset": preset,
                "has_text": bool(query.text),
                "page": page,
                "page_size": page_size,
                "results": result.total,
            },
        )
        return result

    def get_event(
        self, log_id: str, record_id: int, *, include_raw_xml: bool = False
    ) -> dict[str, Any]:
        self._require_ready(log_id)
        event = self.store.get_event(log_id, record_id)
        payload = event.to_dict(include_raw_xml=include_raw_xml)
        if include_raw_xml and payload.get("raw_xml"):
            limit = int(self.settings.evtx_max_raw_xml_bytes)
            xml = payload["raw_xml"]
            if len(xml) > limit:
                payload["raw_xml"] = xml[:limit]
                payload["raw_xml_truncated"] = True
            else:
                payload["raw_xml_truncated"] = False
        return payload

    def context(
        self, log_id: str, record_id: int, before: int = 5, after: int = 5
    ) -> dict[str, Any]:
        self._require_ready(log_id)
        maximum = int(self.settings.evtx_context_max)
        before = max(0, min(int(before), maximum))
        after = max(0, min(int(after), maximum))
        events = self.store.context(log_id, record_id, before, after)
        return {
            "trust": "untrusted_evidence_data",
            "log_id": log_id,
            "record_id": record_id,
            "before": before,
            "after": after,
            "events": [event.to_dict() for event in events],
            "complete": True,
        }

    def summary(
        self,
        record,
        *,
        log_ids: list[str] | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        top_n: int = 20,
    ) -> dict[str, Any]:
        resolved = self._resolve_log_ids(record, log_ids)
        summary = self.store.summary(
            resolved,
            time_from=self._validate_time(time_from, "time_from"),
            time_to=self._validate_time(time_to, "time_to"),
            top_n=max(1, min(int(top_n), 100)),
        )
        payload = summary.to_dict()
        payload["presets"] = list_presets()
        payload["notable"] = self._notable(record, resolved)
        return payload

    def _notable(self, record, log_ids: list[str]) -> list[dict[str, Any]]:
        notable: list[dict[str, Any]] = []
        for definition in _notable_presets():
            result = self.store.query_events(
                EventQuery(
                    log_ids=log_ids,
                    channels=list(definition.channels),
                    event_ids=list(definition.event_ids),
                    page=1,
                    page_size=1,
                )
            )
            if result.total:
                notable.append(
                    {
                        "rule_id": definition.rule_id,
                        "preset_id": definition.preset_id,
                        "name": definition.name,
                        "reason": definition.description,
                        "count": result.total,
                        "event_ids": list(definition.event_ids),
                        "channels": list(definition.channels),
                        "limitations": definition.limitations,
                    }
                )
        return notable

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _resolve_log_ids(
        self, record, log_ids: list[str] | None
    ) -> list[str]:
        if log_ids:
            resolved = []
            for log_id in log_ids:
                log = self.store.get_log(str(log_id))
                if log.evidence_id != record.evidence_id:
                    raise EvtxRejected(
                        "log belongs to a different evidence",
                        code="evtx_log_evidence_mismatch",
                        details={"log_id": log_id},
                    )
                resolved.append(log.log_id)
            return resolved
        return [
            log.log_id
            for log in self.store.list_for_evidence(record.evidence_id)
            if log.status in {"ready", "partial"}
        ]

    def _validate_page(
        self, page: int, page_size: int | None
    ) -> tuple[int, int]:
        from ..index_models import validate_page, validate_page_size

        return (
            validate_page(page),
            validate_page_size(
                page_size,
                default_size=self.settings.evtx_page_size_default,
                max_size=self.settings.evtx_page_size_max,
            ),
        )

    def _validate_time(self, value: str | None, field: str) -> str | None:
        text = (value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvtxRejected(
                f"{field} must be an ISO 8601 timestamp",
                code="evtx_invalid_time",
                details={"field": field},
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    def _validate_text(self, text: str | None) -> str | None:
        value = (text or "").strip()
        if not value:
            return None
        limit = int(self.settings.evtx_max_query_length)
        if len(value) > limit:
            raise EvtxRejected(
                f"text query must not exceed {limit} characters",
                code="evtx_query_too_long",
            )
        return value


class _SimplePage:
    def __init__(self, *, items, total, page, page_size) -> None:
        self.items = items
        self.total = total
        self.page = page
        self.page_size = page_size

    @property
    def pages(self) -> int:
        return (self.total + self.page_size - 1) // self.page_size if self.page_size else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": "untrusted_evidence_data",
            "items": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.items
            ],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "has_more": self.page * self.page_size < self.total,
        }


def _notable_presets():
    from .presets import PRESETS

    ids = {"log_clearing", "service_persistence", "scheduled_tasks", "powershell", "defender"}
    return [preset for preset in PRESETS if preset.preset_id in ids]
