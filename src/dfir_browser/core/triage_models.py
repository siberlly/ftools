from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .errors import DFIRError
from .models import TRUST_LABEL

TRIAGE_PROFILE_VERSION = "static-triage-v1"
TRIAGE_PHASES = (
    "queued",
    "extracting",
    "hashing",
    "identifying",
    "strings",
    "yara",
    "metadata",
    "complete",
)
TRIAGE_STATUSES = {
    "queued",
    "running",
    "complete",
    "partial",
    "failed",
    "interrupted",
}
ANALYZER_STATUSES = {"ok", "failed", "timeout", "unavailable", "skipped", "no_rules"}
STRING_ENCODINGS = {"ascii", "utf-16le"}


class TriageError(DFIRError):
    default_code = "triage_error"


class TriageNotFoundError(TriageError):
    default_code = "triage_not_found"


class TriageRejectedError(TriageError):
    default_code = "triage_rejected"


class TriageQueueFullError(TriageError):
    default_code = "triage_queue_full"


@dataclass(slots=True)
class AnalyzerResult:
    name: str
    status: str = "skipped"
    duration_ms: float = 0.0
    version: str | None = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 3),
            "version": self.version,
            "error": self.error,
            "warnings": list(self.warnings),
            "truncated": self.truncated,
            "data": self.data,
        }


@dataclass(slots=True)
class TriageFinding:
    category: str
    value: str
    encoding: str
    offset: int | None
    rule_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "value": self.value,
            "encoding": self.encoding,
            "offset": self.offset,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }


@dataclass(slots=True)
class TriageJob:
    job_id: str
    evidence_id: str
    entry_id: int
    inode: int | None
    case_id: str
    profile_version: str
    status: str
    phase: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    cached_from_job_id: str | None = None
    sha256: str | None = None
    md5: str | None = None
    sha1: str | None = None
    size: int | None = None
    file_type: str | None = None
    mime_type: str | None = None
    entropy: float | None = None
    extract_relpath: str | None = None
    strings_count: int = 0
    findings_count: int = 0
    yara_status: str | None = None
    pe_status: str | None = None
    duration_ms: float | None = None
    error_code: str | None = None
    error_message: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tool_versions: dict[str, str | None] = field(default_factory=dict)
    analyzers: list[AnalyzerResult] = field(default_factory=list)

    @property
    def cached(self) -> bool:
        return self.cached_from_job_id is not None

    @property
    def finished(self) -> bool:
        return self.status in {"complete", "partial", "failed", "interrupted"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "job_id": self.job_id,
            "evidence_id": self.evidence_id,
            "entry_id": self.entry_id,
            "inode": self.inode,
            "case_id": self.case_id,
            "profile_version": self.profile_version,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cached": self.cached,
            "cached_from_job_id": self.cached_from_job_id,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "size": self.size,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "entropy": self.entropy,
            "extract_relpath": self.extract_relpath,
            "strings_count": self.strings_count,
            "findings_count": self.findings_count,
            "yara_status": self.yara_status,
            "pe_status": self.pe_status,
            "duration_ms": self.duration_ms,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "tool_versions": dict(self.tool_versions),
            "analyzers": [analyzer.to_dict() for analyzer in self.analyzers],
        }


@dataclass(slots=True)
class TriageStringsPage:
    job_id: str
    strings: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    encoding: str | None = None
    query: str | None = None

    @property
    def pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "job_id": self.job_id,
            "strings": self.strings,
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "encoding": self.encoding,
            "query": self.query,
        }


def utc_now_iso() -> str:
    from .index_models import utc_now_iso as _utc_now_iso

    return _utc_now_iso()


def analyzer_asdict(analyzer: AnalyzerResult) -> dict[str, Any]:
    return asdict(analyzer)
