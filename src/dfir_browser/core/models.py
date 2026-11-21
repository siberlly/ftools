from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRUST_LABEL = "untrusted_evidence_data"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def ns_to_iso(value: int | None) -> str | None:
    if not value:
        return None
    return (
        datetime.fromtimestamp(value / 1_000_000_000, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def human_size(value: int | None) -> str:
    if value is None:
        return ""
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{value} B"


@dataclass(slots=True)
class Layout:
    scope: str
    filesystem: str | None
    offset_sectors: int
    method: str
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Layout":
        data = data or {}
        return cls(
            scope=str(data.get("scope", "unknown")),
            filesystem=data.get("filesystem"),
            offset_sectors=int(data.get("offset_sectors", 0) or 0),
            method=str(data.get("method", "unknown")),
            details=dict(data.get("details") or {}),
            warnings=list(data.get("warnings") or []),
        )


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    resolved_source_path: str
    filename: str
    extension: str
    source_sha256: str | None
    source_size: int
    source_mtime_ns: int
    format: str
    media_size: int
    sector_size: int
    md5: str | None
    sha1: str | None
    ewfinfo_version: str | None
    ewfinfo_duration_ms: float
    ewfinfo_command: dict[str, Any]
    raw_exposure_path: str | None
    exposure_mode: str
    exposure_verified_at: str | None
    exposure_details: dict[str, Any]
    layout: Layout
    registered_at: str
    status: str
    warnings: list[str] = field(default_factory=list)

    @property
    def source_mtime_iso(self) -> str | None:
        return ns_to_iso(self.source_mtime_ns)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["layout"] = self.layout.to_dict()
        data["trust"] = TRUST_LABEL
        data["media_size_human"] = human_size(self.media_size)
        data["source_size_human"] = human_size(self.source_size)
        data["source_mtime_iso"] = ns_to_iso(self.source_mtime_ns)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRecord":
        resolved_source_path = str(
            data.get("resolved_source_path") or data.get("path") or ""
        )
        raw_exposure_path = data.get("raw_exposure_path") or data.get("image_path")
        exposure_mode = data.get("exposure_mode")
        if not exposure_mode:
            exposure_mode = "legacy" if data.get("image_path") else "direct"
        return cls(
            evidence_id=str(data["evidence_id"]),
            resolved_source_path=resolved_source_path,
            filename=str(
                data.get("filename") or Path(resolved_source_path).name
            ),
            extension=str(
                data.get("extension") or Path(resolved_source_path).suffix.lower()
            ),
            source_sha256=data.get("source_sha256"),
            source_size=int(data.get("source_size", 0) or 0),
            source_mtime_ns=int(data.get("source_mtime_ns", 0) or 0),
            format=str(data.get("format", "unknown")),
            media_size=int(data.get("media_size", 0) or 0),
            sector_size=int(data.get("sector_size", 0) or 0),
            md5=data.get("md5"),
            sha1=data.get("sha1"),
            ewfinfo_version=data.get("ewfinfo_version"),
            ewfinfo_duration_ms=float(data.get("ewfinfo_duration_ms", 0.0) or 0.0),
            ewfinfo_command=dict(data.get("ewfinfo_command") or {}),
            raw_exposure_path=raw_exposure_path,
            exposure_mode=str(exposure_mode),
            exposure_verified_at=data.get("exposure_verified_at"),
            exposure_details=dict(data.get("exposure_details") or {}),
            layout=Layout.from_dict(data.get("layout")),
            registered_at=str(data.get("registered_at", "")),
            status=str(data.get("status", "unknown")),
            warnings=list(data.get("warnings") or []),
        )


@dataclass(slots=True)
class DirEntry:
    name: str
    inode: int
    sequence: int | None
    attribute_id: int | None
    entry_type: str
    allocated: bool
    deleted: bool
    size: int | None
    mtime: str | None = None
    atime: str | None = None
    ctime: str | None = None
    crtime: str | None = None
    full_path: str | None = None
    parent_path: str | None = None
    basename: str | None = None
    extension: str | None = None
    fls_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DirectoryListing:
    evidence_id: str
    inode: int
    offset_sectors: int
    breadcrumb: list[dict[str, Any]]
    entries: list[DirEntry]
    warnings: list[str]
    tool_version: str | None
    command: dict[str, Any] = field(default_factory=dict)
    complete: bool = True
    truncated: bool = False
    warning: str | None = None
    cursor: str | None = None
    next_cursor: str | None = None
    source: str = "live"
    path: str = ""
    index_status: str | None = None
    total: int | None = None
    page: int = 1
    page_size: int = 0
    prev_url: str | None = None
    next_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        files = sum(1 for entry in self.entries if entry.entry_type == "file")
        directories = sum(
            1 for entry in self.entries if entry.entry_type == "directory"
        )
        return {
            "trust": TRUST_LABEL,
            "evidence_id": self.evidence_id,
            "inode": self.inode,
            "offset_sectors": self.offset_sectors,
            "breadcrumb": self.breadcrumb,
            "entries": [entry.to_dict() for entry in self.entries],
            "counts": {
                "total": len(self.entries),
                "files": files,
                "directories": directories,
                "deleted": sum(1 for entry in self.entries if entry.deleted),
            },
            "complete": self.complete,
            "truncated": self.truncated,
            "warning": self.warning,
            "cursor": self.cursor,
            "next_cursor": self.next_cursor,
            "source": self.source,
            "path": self.path,
            "index_status": self.index_status,
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "prev_url": self.prev_url,
            "next_url": self.next_url,
            "warnings": self.warnings,
            "tool_version": self.tool_version,
            "command": self.command,
        }


@dataclass(slots=True)
class MetadataResult:
    evidence_id: str
    inode: int
    summary: dict[str, Any]
    raw: str
    raw_truncated: bool
    warnings: list[str]
    tool_version: str | None
    command: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class ExtractionResult:
    evidence_id: str
    case_id: str
    inode: int
    name: str | None
    output_path: str
    relative_path: str
    size: int
    sha256: str
    source_size: int | None
    tool_version: str | None
    extracted_at: str
    untrusted: bool = True
    warnings: list[str] = field(default_factory=list)
    command: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data
