from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..errors import DFIRError
from ..models import TRUST_LABEL

BROWSER_SCHEMA_VERSION = 1
ARTIFACT_STATUSES = {"queued", "running", "ready", "partial", "failed", "interrupted"}
ARTIFACT_PHASES = ("queued", "extracting", "validating", "parsing", "indexing", "ready")
RECORD_TYPES = {"download", "visit", "cache", "profile"}

BROWSERS = {
    "webcache": "IE / Legacy Edge (WebCacheV01.dat)",
    "chromium": "Chromium (Edge / Chrome History)",
    "firefox": "Firefox (places.sqlite)",
    "unknown": "Unknown",
}
ARTIFACT_TYPES = {
    "webcache": "WebCache",
    "chromium_history": "Chromium History",
    "firefox_places": "Firefox places.sqlite",
}


class BrowserArtifactError(DFIRError):
    default_code = "browser_artifact_error"


class ArtifactNotFound(BrowserArtifactError):
    default_code = "browser_artifact_not_found"


class ArtifactNotReady(BrowserArtifactError):
    default_code = "browser_artifact_not_ready"


class BrowserArtifactRejected(BrowserArtifactError):
    default_code = "browser_artifact_rejected"


class BackendUnavailable(BrowserArtifactError):
    default_code = "backend_unavailable"


@dataclass(slots=True)
class ArtifactCandidate:
    evidence_id: str
    entry_id: int
    inode: int | None
    path: str
    name: str
    user: str | None
    profile_name: str | None
    browser: str
    artifact_type: str
    size: int | None
    allocated: bool
    deleted: bool
    modified_time: str | None
    confidence: float
    reason: str
    signature_status: str = "unverified"
    sidecars: list[str] = field(default_factory=list)
    backend: str = "none"
    parser_supported: bool = True
    artifact_id: str | None = None
    state: str | None = None
    index_status: str | None = None
    records_indexed: int = 0
    parse_errors: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        data["index_status"] = self.index_status or self.state or "not_indexed"
        return data


@dataclass(slots=True)
class BrowserProfileRow:
    profile_id: str
    evidence_id: str
    artifact_id: str
    user: str | None
    browser: str
    profile_name: str | None
    source_path: str
    artifact_types: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class SourceArtifact:
    artifact_id: str
    evidence_id: str
    entry_id: int
    inode: int | None
    evidence_path: str
    filename: str
    browser: str
    artifact_type: str
    user: str | None
    profile_name: str | None
    size: int | None
    sha256: str | None
    sidecars: list[str] = field(default_factory=list)
    sidecars_used: list[str] = field(default_factory=list)
    extract_relpath: str | None = None
    backend: str = "none"
    parser_version: str = ""
    schema_version: int = BROWSER_SCHEMA_VERSION
    status: str = "queued"
    phase: str = "queued"
    records_seen: int = 0
    records_indexed: int = 0
    parse_errors: int = 0
    first_record_time: str | None = None
    last_record_time: str | None = None
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
class DownloadRecord:
    download_id: int
    profile_id: str
    source_artifact_id: str
    source_record_id: str | None
    user: str | None
    browser: str
    start_time_utc: str | None
    end_time_utc: str | None
    start_raw: str | None
    end_raw: str | None
    url: str | None
    final_url: str | None
    url_chain: list[str] = field(default_factory=list)
    referrer: str | None = None
    tab_url: str | None = None
    target_path: str | None = None
    filename: str | None = None
    received_bytes: int | None = None
    total_bytes: int | None = None
    state: str | None = None
    danger_type: str | None = None
    interrupt_reason: str | None = None
    mime_type: str | None = None
    opened: bool | None = None
    hash_value: str | None = None
    hash_algorithm: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class VisitRecord:
    visit_id: int
    profile_id: str
    source_artifact_id: str
    source_record_id: str | None
    user: str | None
    browser: str
    url: str | None
    scheme: str | None
    host: str | None
    registrable_domain: str | None
    title: str | None
    visit_time_utc: str | None
    raw_timestamp: str | None
    visit_type: str | None
    referrer_url: str | None = None
    visit_count: int | None = None
    typed_count: int | None = None
    hidden: bool | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class CacheRecord:
    cache_id: int
    profile_id: str
    source_artifact_id: str
    source_record_id: str | None
    container: str | None
    user: str | None
    browser: str
    url: str | None
    local_path: str | None
    content_type: str | None
    created_time_utc: str | None
    accessed_time_utc: str | None
    modified_time_utc: str | None
    expiry_time_utc: str | None
    size: int | None
    allocated: bool | None
    response_preview: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class RecordPage:
    kind: str
    items: list[Any]
    total: int
    page: int
    page_size: int
    sort_dir: str = "desc"
    warnings: list[str] = field(default_factory=list)

    @property
    def pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "kind": self.kind,
            "items": [
                item.to_dict() if hasattr(item, "to_dict") else item
                for item in self.items
            ],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "sort_dir": self.sort_dir,
            "has_more": self.page * self.page_size < self.total,
            "complete": self.page * self.page_size >= self.total,
            "truncated": False,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class CorrelationHit:
    entry_id: int
    path: str
    basename: str
    inode: int | None
    size: int | None
    allocated: bool
    deleted: bool
    modified_time: str | None
    confidence: float
    reason: str
    size_matches: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class ActivitySummary:
    total_visits: int
    total_downloads: int
    total_cache: int
    time_from: str | None
    time_to: str | None
    users: dict[str, int] = field(default_factory=dict)
    browsers: dict[str, int] = field(default_factory=dict)
    profiles: dict[str, int] = field(default_factory=dict)
    top_domains: list[dict[str, Any]] = field(default_factory=list)
    top_extensions: list[dict[str, Any]] = field(default_factory=list)
    download_states: dict[str, int] = field(default_factory=dict)
    total_download_bytes: int = 0
    executable_downloads: int = 0
    correlated_downloads: int = 0
    deleted_targets: int = 0
    by_day: dict[str, int] = field(default_factory=dict)
    notable: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "total_visits": self.total_visits,
            "total_downloads": self.total_downloads,
            "total_cache": self.total_cache,
            "time_from": self.time_from,
            "time_to": self.time_to,
            "users": self.users,
            "browsers": self.browsers,
            "profiles": self.profiles,
            "top_domains": self.top_domains,
            "top_extensions": self.top_extensions,
            "download_states": self.download_states,
            "total_download_bytes": self.total_download_bytes,
            "executable_downloads": self.executable_downloads,
            "correlated_downloads": self.correlated_downloads,
            "deleted_targets": self.deleted_targets,
            "by_day": self.by_day,
            "notable": self.notable,
            "warnings": self.warnings,
            "note": (
                "Counts and rules are triage indicators, not malware verdicts. "
                "URLs and titles are untrusted evidence data."
            ),
        }


def artifact_id_for(evidence_id: str, entry_id: int) -> str:
    import hashlib

    digest = hashlib.sha256(f"{evidence_id}:{entry_id}".encode()).hexdigest()
    return "ba_" + digest[:16]


def profile_id_for(evidence_id: str, browser: str, user: str | None, profile: str | None) -> str:
    import hashlib

    key = f"{evidence_id}:{browser}:{user or ''}:{profile or ''}"
    return "bp_" + hashlib.sha256(key.encode()).hexdigest()[:16]
