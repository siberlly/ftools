"""Recycle Bin metadata analysis (``$I`` / ``$R`` pairs).

Windows recycles a file into ``$Recycle.Bin/<SID>/``:

* ``$I<id><ext>`` - a small record with the original path, original size and
  the **deletion timestamp**.
* ``$R<id><ext>`` - the deleted content itself.

Only the ``$I`` record is read here, from an extracted working copy. The ``$R``
content is never opened by this module.
"""
from __future__ import annotations

import logging
import re
import struct
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .audit import get_correlation_id
from .config import Settings
from .errors import DFIRError
from .index_models import validate_entry_id
from .models import TRUST_LABEL

logger = logging.getLogger("dfir_browser.recycle")

CASE_ID = "case01"
SUPPORTED_VERSIONS = (1, 2)
MIN_INFO_BYTES = 28
RECYCLE_DIR_RE = re.compile(r"(?:^|/)\$Recycle\.Bin/+([^/]+)/+\$([IR])(.+)$", re.IGNORECASE)
SID_RE = re.compile(r"^S-\d-(?:\d+-)+\d+$", re.IGNORECASE)


class RecycleError(DFIRError):
    default_code = "recycle_error"


class RecycleRejected(RecycleError):
    default_code = "recycle_rejected"


def _filetime(value: int) -> tuple[str | None, str | None]:
    """Convert a Windows FILETIME to ISO-8601 UTC plus the raw value."""
    raw = str(value)
    if value <= 0:
        return None, raw
    try:
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=value / 10
        )
    except (OverflowError, ValueError):
        return None, raw
    if not 1995 <= moment.year <= 2100:
        return None, raw
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z"), raw


def classify(entry) -> dict[str, Any] | None:
    """Describe a recycle-bin $I/$R entry, or None for other paths."""
    path = (getattr(entry, "full_path", "") or "").replace("\\", "/")
    match = RECYCLE_DIR_RE.search(path)
    if not match:
        return None
    sid, kind, recycled_name = match.group(1), match.group(2).upper(), match.group(3)
    if sid.lower() == "$i" or sid.lower() == "$r":
        return None
    return {
        "kind": "info" if kind == "I" else "content",
        "sid": sid if SID_RE.match(sid) else None,
        "sid_raw": sid,
        "recycled_name": recycled_name,
        "recycle_dir": path[: match.start(2) - 1],
    }


def parse_info_file(data: bytes) -> dict[str, Any]:
    """Parse a Windows ``$I`` record (format versions 1 and 2).

    Layout (little endian)::

        version 2: u64 version | u64 original size | u64 deletion FILETIME
                   u32 name length | N * UTF-16LE original path
        version 1: u64 version | u64 original size | u64 deletion FILETIME
                   520 * UTF-16LE original path (fixed width, no length field)
    """
    warnings: list[str] = []
    result: dict[str, Any] = {
        "version": None,
        "original_size": None,
        "deleted_time_utc": None,
        "deleted_time_raw": None,
        "original_path": None,
        "header_bytes": len(data),
        "name_length": None,
        "warnings": warnings,
    }
    if len(data) < 8:
        warnings.append("record is shorter than the 8-byte version header")
        return result
    version = struct.unpack_from("<Q", data, 0)[0]
    result["version"] = version
    if version not in SUPPORTED_VERSIONS:
        warnings.append(
            f"unsupported $I format version {version} "
            f"(supported: {', '.join(str(v) for v in SUPPORTED_VERSIONS)})"
        )
        return result
    if len(data) < 24:
        warnings.append(
            f"record is {len(data)} bytes but at least 24 are required"
        )
        return result

    original_size = struct.unpack_from("<Q", data, 8)[0]
    filetime = struct.unpack_from("<Q", data, 16)[0]
    result["original_size"] = original_size
    deleted_utc, deleted_raw = _filetime(filetime)
    result["deleted_time_utc"] = deleted_utc
    result["deleted_time_raw"] = deleted_raw
    if deleted_utc is None:
        warnings.append(
            "deletion timestamp is not a plausible FILETIME; raw value kept"
        )

    if version == 1:
        # Version 1 has no length field: a fixed 520-character UTF-16LE path
        # follows the 24-byte header.
        payload = data[24:24 + 520 * 2]
        name_length = 520
        chars = 520
    else:
        if len(data) < MIN_INFO_BYTES:
            warnings.append(
                f"record is {len(data)} bytes but at least {MIN_INFO_BYTES} "
                "are required"
            )
            return result
        name_length = struct.unpack_from("<I", data, 24)[0]
        payload = data[MIN_INFO_BYTES:]
        available_chars = len(payload) // 2
        chars = name_length
        if name_length > available_chars:
            # Some writers store the length in bytes, not UTF-16 characters.
            if name_length // 2 <= available_chars:
                chars = name_length // 2
                warnings.append(
                    "name length looks like a byte count; interpreted as "
                    "UTF-16 characters"
                )
            else:
                chars = available_chars
                warnings.append(
                    f"declared name length {name_length} exceeds the "
                    f"{available_chars} available characters; path may be truncated"
                )
    result["name_length"] = name_length
    raw_name = payload[: chars * 2]
    if raw_name:
        try:
            text = raw_name.decode("utf-16-le")
        except UnicodeDecodeError:
            text = raw_name.decode("utf-16-le", "replace")
            warnings.append("original path had invalid UTF-16 code units")
        text = text.split("\x00", 1)[0]
        result["original_path"] = text or None
        # Version 2 normally stores a trailing NUL, so the declared character
        # count is often one greater than the visible path. Only flag a real
        # shortfall.
        if (
            text
            and version == 2
            and chars == name_length
            and len(text) < name_length - 1
        ):
            warnings.append(
                f"declared name length {name_length} exceeds the stored path "
                f"({len(text)} characters)"
            )
    else:
        warnings.append("record has no stored original path")
    return result


@dataclass(slots=True)
class RecycleMetadata:
    evidence_id: str
    entry_id: int
    is_recycle_entry: bool
    filename: str
    evidence_path: str
    kind: str | None = None
    sid: str | None = None
    recycled_name: str | None = None
    info_entry_id: int | None = None
    content_entry_id: int | None = None
    version: int | None = None
    original_path: str | None = None
    original_size: int | None = None
    deleted_time_utc: str | None = None
    deleted_time_raw: str | None = None
    deletion_source: str | None = None
    content: dict[str, Any] | None = None
    index_timestamps: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    state: str = "ready"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


class RecycleBinService:
    """Resolve deletion metadata for one $I/$R entry. Read-only and bounded."""

    def __init__(
        self,
        *,
        settings: Settings,
        policy,
        filesystem,
        evidence,
        indexer,
        index_store,
        audit,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.index_store = index_store
        self.audit = audit
        self._cache: dict[tuple, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def cleanup(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------
    def _scan_id(self, record) -> str:
        row = self.index_store.get_index_row(record.evidence_id)
        if row is None or not row.get("scan_id"):
            raise RecycleRejected(
                "filesystem index is not available for this evidence",
                code="recycle_index_missing",
            )
        return str(row["scan_id"])

    def _sibling(self, record, entry, basename: str):
        scan_id = self._scan_id(record)
        for candidate in self.index_store.find_entries_by_basename(
            record.evidence_id, scan_id, basename, 10
        ):
            if candidate.full_path == f"{entry.parent_path}/{basename}":
                return candidate
        return None

    def directory_hints(
        self, record, entries: list[Any]
    ) -> dict[int, dict[str, Any]]:
        """Deletion time per $I/$R entry for a directory listing.

        Only $I headers already extracted in this case are read, so a listing
        never triggers extraction of every content file. Entries whose $I is not
        available are returned with a null time and a reason.
        """
        hints: dict[int, dict[str, Any]] = {}
        pairs: dict[str, dict[str, Any]] = {}
        for entry in entries:
            info = classify(entry)
            if info is None:
                continue
            slot = pairs.setdefault(
                info["recycled_name"],
                {"info": None, "content": None},
            )
            slot["info" if info["kind"] == "info" else "content"] = entry
        for name, slot in pairs.items():
            info_entry = slot["info"]
            content_entry = slot["content"]
            target = info_entry or content_entry
            if target is None:
                continue
            payload: dict[str, Any] = {
                "deleted_time_utc": None,
                "original_path": None,
                "original_size": None,
                "reason": None,
                "paired": bool(info_entry is not None and content_entry is not None),
            }
            if info_entry is None:
                payload["reason"] = "no $I record in this directory"
            else:
                try:
                    parsed = self._parse(record, info_entry)
                except DFIRError as exc:
                    payload["reason"] = str(exc)
                else:
                    payload["deleted_time_utc"] = parsed.get("deleted_time_utc")
                    payload["original_path"] = parsed.get("original_path")
                    payload["original_size"] = parsed.get("original_size")
                    if parsed.get("deleted_time_utc") is None:
                        payload["reason"] = "no plausible deletion timestamp"
            if info_entry is not None:
                hints[info_entry.id] = payload
            if content_entry is not None:
                hints[content_entry.id] = payload
        return hints

    def metadata(self, record, entry_id: Any) -> RecycleMetadata:
        entry = self.indexer.tree_entry(record, validate_entry_id(entry_id))
        info = classify(entry)
        base = RecycleMetadata(
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            is_recycle_entry=info is not None,
            filename=entry.basename,
            evidence_path=entry.full_path,
        )
        if info is None:
            base.state = "not_recycle_entry"
            return base
        if entry.entry_type != "file":
            base.state = "not_a_file"
            base.warnings.append("only $I and $R files carry recycle metadata")
            return base

        base.kind = info["kind"]
        base.sid = info["sid"]
        base.recycled_name = info["recycled_name"]
        base.warnings.append(
            "Recycle Bin paths, original names and timestamps are untrusted "
            "evidence data."
        )
        if info["sid"] is None:
            base.warnings.append(
                f"recycle directory name {info['sid_raw']!r} is not a SID"
            )
        base.index_timestamps = {
            "created": entry.created_time,
            "modified": entry.modified_time,
            "mft_modified": entry.mft_modified_time,
            "accessed": entry.accessed_time,
            "allocated": bool(entry.allocated),
            "deleted": bool(entry.deleted),
        }

        info_entry, content_entry = self._pair(record, entry, info)
        base.info_entry_id = info_entry.id if info_entry is not None else None
        base.content_entry_id = content_entry.id if content_entry is not None else None
        if content_entry is not None:
            base.content = {
                "entry_id": content_entry.id,
                "path": content_entry.full_path,
                "basename": content_entry.basename,
                "size": content_entry.size,
                "allocated": bool(content_entry.allocated),
                "deleted": bool(content_entry.deleted),
                "modified_time": content_entry.modified_time,
                "has_inode": content_entry.inode is not None,
            }
        else:
            base.warnings.append(
                "no matching $R content file was found in this directory; the "
                "deleted content may already be gone"
            )

        if info_entry is None:
            base.state = "info_missing"
            base.warnings.append("no matching $I record was found for this entry")
            if base.content is not None and base.content.get("modified_time"):
                base.warnings.append(
                    "no deletion timestamp is available; the $R modified time "
                    "is shown only as an indicator"
                )
            self._audit(record, entry, base, cached=False)
            return base

        try:
            parsed = self._parse(record, info_entry)
        except DFIRError as exc:
            base.state = "parse_failed"
            base.warnings.append(str(exc))
            self._audit(record, entry, base, cached=False)
            return base

        base.version = parsed.get("version")
        base.original_path = parsed.get("original_path")
        base.original_size = parsed.get("original_size")
        base.deleted_time_utc = parsed.get("deleted_time_utc")
        base.deleted_time_raw = parsed.get("deleted_time_raw")
        base.deletion_source = (
            "$I deletion timestamp" if base.deleted_time_utc else None
        )
        base.warnings.extend(parsed.get("warnings") or [])
        base.info_entry_id = info_entry.id
        if base.deleted_time_utc is None:
            base.state = "partial"
        self._audit(record, entry, base, cached=False)
        return base

    # ------------------------------------------------------------------
    def _pair(self, record, entry, info: dict[str, Any]):
        info_entry = self._sibling(
            record, entry, f"$I{info['recycled_name']}"
        )
        content_entry = self._sibling(
            record, entry, f"$R{info['recycled_name']}"
        )
        return info_entry, content_entry

    def _parse(self, record, info_entry) -> dict[str, Any]:
        key = (
            record.evidence_id,
            info_entry.id,
            info_entry.size,
            info_entry.modified_time,
        )
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return dict(cached)

        limit = int(self.settings.recycle_max_info_bytes)
        if info_entry.size is not None and int(info_entry.size) > limit:
            raise RecycleRejected(
                "$I record exceeds the configured maximum size",
                code="recycle_info_too_large",
                details={"size": info_entry.size, "limit": limit},
            )
        try:
            extraction = self.filesystem.extract_entry(record, info_entry, CASE_ID)
        except DFIRError as exc:
            raise RecycleRejected(
                f"could not read the $I record: {exc}",
                code="recycle_extract_failed",
            ) from exc
        path = Path(extraction.output_path)
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RecycleRejected(
                "extracted $I record is not accessible",
                code="recycle_extract_missing",
            ) from exc
        exports = self.policy.case_exports_dir(CASE_ID).resolve()
        if not resolved.is_relative_to(exports) or not resolved.is_file():
            raise RecycleRejected(
                "extracted $I record is outside the case export directory",
                code="recycle_extract_outside_case",
            )
        with open(resolved, "rb") as handle:
            data = handle.read(limit)
        parsed = parse_info_file(data)
        with self._lock:
            self._cache[key] = dict(parsed)
        return parsed

    def _audit(self, record, entry, result: RecycleMetadata, *, cached: bool) -> None:
        self.audit.event(
            "recycle_metadata",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "entry_id": entry.id,
                "kind": result.kind,
                "state": result.state,
                "has_deleted_time": result.deleted_time_utc is not None,
                "sid": result.sid,
                "cached": cached,
            },
        )
