from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..errors import DFIRError
from ..models import TRUST_LABEL

EVTX_SCHEMA_VERSION = 1
LOG_STATUSES = {"queued", "running", "ready", "partial", "failed", "interrupted"}
LOG_PHASES = ("queued", "extracting", "validating", "parsing", "indexing", "ready")
PRIORITY_CHANNELS = (
    "Security",
    "System",
    "Application",
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
)


class EvtxError(DFIRError):
    default_code = "evtx_error"


class EvtxLogNotFound(EvtxError):
    default_code = "evtx_log_not_found"


class EvtxLogNotReady(EvtxError):
    default_code = "evtx_log_not_ready"


class EvtxRejected(EvtxError):
    default_code = "evtx_rejected"


class EvtxNotEvtx(EvtxError):
    default_code = "evtx_invalid_signature"


@dataclass(slots=True)
class LogCandidate:
    evidence_id: str
    entry_id: int
    inode: int | None
    path: str
    name: str
    channel: str
    size: int | None
    allocated: bool
    deleted: bool
    created_time: str | None
    modified_time: str | None
    accessed_time: str | None
    mft_modified_time: str | None
    confidence: float
    reason: str
    signature_status: str = "unverified"
    parser_supported: bool = True
    priority: bool = False
    log_id: str | None = None
    state: str | None = None
    index_status: str | None = None
    records_indexed: int = 0
    parse_errors: int = 0
    first_event_time: str | None = None
    last_event_time: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        data["index_status"] = self.index_status or self.state or "not_indexed"
        return data


@dataclass(slots=True)
class EvtxLog:
    log_id: str
    evidence_id: str
    entry_id: int
    inode: int | None
    evidence_path: str
    filename: str
    detected_channel: str
    size: int | None
    sha256: str | None
    allocated: bool
    deleted: bool
    parser: str
    parser_version: str
    index_schema: int
    status: str
    phase: str
    records_seen: int
    records_indexed: int
    parse_errors: int
    first_event_time: str | None
    last_event_time: str | None
    extract_relpath: str | None = None
    warnings: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class EvtxEvent:
    log_id: str
    record_id: int
    chunk_number: int | None
    timestamp_utc: str | None
    timestamp_raw: str | None
    channel: str | None
    provider_name: str | None
    provider_guid: str | None
    event_id: int | None
    event_id_raw: str | None
    qualifiers: int | None
    level: int | None
    level_name: str | None
    task: int | None
    opcode: int | None
    keywords: str | None
    computer: str | None
    user_sid: str | None
    process_id: int | None
    thread_id: int | None
    activity_id: str | None
    related_activity_id: str | None
    version: int | None
    event_data: dict[str, Any] = field(default_factory=dict)
    user_data: str | None = None
    rendering_info: str | None = None
    message: str | None = None
    message_status: str = "message_unavailable"
    raw_xml: str | None = None
    raw_xml_sha256: str | None = None
    summary: str | None = None
    truncated: bool = False
    parse_warnings: list[str] = field(default_factory=list)

    def to_dict(self, *, include_raw_xml: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_raw_xml:
            data.pop("raw_xml", None)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class EventPage:
    events: list[EvtxEvent]
    total: int
    page: int
    page_size: int
    sort_dir: str = "asc"
    complete: bool = True
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    log_ids: list[str] = field(default_factory=list)

    @property
    def pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "events": [event.to_dict() for event in self.events],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "sort_dir": self.sort_dir,
            "complete": self.complete,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "log_ids": list(self.log_ids),
        }


@dataclass(slots=True)
class EventQuery:
    log_ids: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    levels: list[int] = field(default_factory=list)
    user_sid: str | None = None
    computer: str | None = None
    process_id: int | None = None
    time_from: str | None = None
    time_to: str | None = None
    text: str | None = None
    sort_dir: str = "asc"
    page: int = 1
    page_size: int = 100

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActiveActivity:
    rule_id: str
    reason: str
    count: int
    channels: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActivitySummary:
    total_events: int
    time_from: str | None
    time_to: str | None
    by_channel: dict[str, int] = field(default_factory=dict)
    by_provider: dict[str, int] = field(default_factory=dict)
    by_event_id: dict[str, int] = field(default_factory=dict)
    by_level: dict[str, int] = field(default_factory=dict)
    by_user_sid: dict[str, int] = field(default_factory=dict)
    by_computer: dict[str, int] = field(default_factory=dict)
    by_day: dict[str, int] = field(default_factory=dict)
    top_processes: list[dict[str, Any]] = field(default_factory=list)
    top_paths: list[dict[str, Any]] = field(default_factory=list)
    notable: list[ActiveActivity] = field(default_factory=list)
    log_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "total_events": self.total_events,
            "time_from": self.time_from,
            "time_to": self.time_to,
            "by_channel": self.by_channel,
            "by_provider": self.by_provider,
            "by_event_id": self.by_event_id,
            "by_level": self.by_level,
            "by_user_sid": self.by_user_sid,
            "by_computer": self.by_computer,
            "by_day": self.by_day,
            "top_processes": self.top_processes,
            "top_paths": self.top_paths,
            "notable": [item.to_dict() for item in self.notable],
            "log_ids": list(self.log_ids),
            "warnings": list(self.warnings),
            "note": (
                "Counts and rule matches are indicators for triage, not proof of "
                "malicious activity."
            ),
        }


def log_id_for(evidence_id: str, entry_id: int) -> str:
    import hashlib

    digest = hashlib.sha256(f"{evidence_id}:{entry_id}".encode()).hexdigest()
    return "log_" + digest[:16]
