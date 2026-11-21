from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..errors import DFIRError
from ..models import TRUST_LABEL

REGISTRY_SCHEMA_VERSION = 2
HIVE_STATUSES = {
    "queued",
    "running",
    "ready",
    "partial",
    "failed",
    "interrupted",
}
HIVE_PHASES = (
    "queued",
    "extracting",
    "validating",
    "parsing",
    "indexing",
    "ready",
)
SENSITIVE_HIVE_TYPES = {"sam", "security"}
STRING_VALUE_TYPES = {"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"}


class RegistryError(DFIRError):
    default_code = "registry_error"


class HiveNotFoundError(RegistryError):
    default_code = "hive_not_found"


class HiveNotReadyError(RegistryError):
    default_code = "hive_not_ready"


class RegistryRejectedError(RegistryError):
    default_code = "registry_rejected"


class RegistryCorruptError(RegistryError):
    default_code = "registry_corrupt"


@dataclass(slots=True)
class HiveCandidate:
    evidence_id: str
    entry_id: int
    inode: int | None
    path: str
    name: str
    hive_type: str
    owner: str | None
    size: int | None
    allocated: bool
    deleted: bool
    modified_time: str | None
    sensitive: bool
    confidence: float
    reason: str
    signature_status: str = "unverified"
    warnings: list[str] = field(default_factory=list)
    state: str | None = None
    hive_id: str | None = None
    dirty: bool | None = None
    recovered: bool = False
    key_count: int = 0
    value_count: int = 0
    amcache_count: int = 0
    transaction_logs: list[str] = field(default_factory=list)
    index_status: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        data["index_status"] = self.index_status or self.state or "not_indexed"
        return data


@dataclass(slots=True)
class RegistryHiveRecord:
    hive_id: str
    evidence_id: str
    entry_id: int
    inode: int | None
    path: str
    name: str
    hive_type: str
    owner: str | None
    size: int | None
    sha256: str | None
    extract_relpath: str | None
    state: str
    phase: str
    dirty: bool
    sequence1: int | None
    sequence2: int | None
    recovered: bool
    parser_version: str
    schema_version: int
    sensitive: bool
    signature_status: str
    transaction_logs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    key_count: int = 0
    value_count: int = 0
    amcache_count: int = 0
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class RegistryKeyNode:
    key_id: int
    hive_id: str
    parent_key_id: int | None
    key_path: str
    name: str
    depth: int
    last_write_time: str | None
    subkey_count: int
    value_count: int
    has_children: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "key_id": self.key_id,
            "hive_id": self.hive_id,
            "parent_key_id": self.parent_key_id,
            "key_path": self.key_path,
            "name": self.name,
            "depth": self.depth,
            "last_write_time": self.last_write_time,
            "subkey_count": self.subkey_count,
            "value_count": self.value_count,
            "has_children": self.has_children,
        }


@dataclass(slots=True)
class RegistryValueItem:
    value_id: int
    key_id: int
    key_path: str
    name: str
    type_name: str
    type_id: int | None
    text_value: str | None
    raw_size: int
    raw_sha256: str | None
    preview_hex: str | None
    truncated: bool
    warnings: list[str] = field(default_factory=list)

    def to_dict(self, *, preview_bytes: int = 64) -> dict[str, Any]:
        preview = self.preview_hex
        if preview is not None:
            limit = max(0, int(preview_bytes)) * 2
            if len(preview) > limit:
                preview = preview[:limit]
                truncated = True
            else:
                truncated = self.truncated
        else:
            truncated = self.truncated
        return {
            "trust": TRUST_LABEL,
            "value_id": self.value_id,
            "key_id": self.key_id,
            "key_path": self.key_path,
            "name": self.name,
            "type": self.type_name,
            "type_id": self.type_id,
            "value": self.text_value,
            "raw_size": self.raw_size,
            "raw_sha256": self.raw_sha256,
            "preview_hex": preview,
            "truncated": truncated,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class RegistryPage:
    items: list[Any]
    total: int
    page: int
    page_size: int
    kind: str

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
            "has_more": self.page * self.page_size < self.total,
        }


@dataclass(slots=True)
class RegistryKeyDetail:
    key: RegistryKeyNode
    values: list[RegistryValueItem]
    binary_preview_bytes: int = 64

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "key": self.key.to_dict(),
            "values": [
                value.to_dict(preview_bytes=self.binary_preview_bytes)
                for value in self.values
            ],
            "binary_preview_bytes": self.binary_preview_bytes,
            "complete": True,
        }


@dataclass(slots=True)
class AmcacheRecord:
    record_id: int
    hive_id: str
    source_key_path: str
    source_key_id: int | None = None
    source_value_names: dict[str, str] = field(default_factory=dict)
    schema: str = "unknown"
    program_name: str | None = None
    executable_name: str | None = None
    executable_path: str | None = None
    file_id_raw: str | None = None
    hash_algorithm: str = "unknown"
    hash_raw: str | None = None
    hash_normalized: str | None = None
    hash_valid: bool = False
    normalization_method: str = "none"
    size: int | None = None
    publisher: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    binary_version: str | None = None
    compile_timestamp: str | None = None
    key_mtime: str | None = None
    first_run: str | None = None
    last_modified: str | None = None
    program_id: str | None = None
    volume_id: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class AmcacheCompareResult:
    status: str
    algorithm: str | None
    amcache_hash: str | None
    filesystem_hash: str | None
    record_id: int
    filesystem_entry_id: int
    triage_job_id: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        data["note"] = (
            "Hash comparison is a matching aid; a mismatch does not by itself "
            "mean the file is malicious."
        )
        return data


def hive_id_for(evidence_id: str, entry_id: int) -> str:
    import hashlib

    digest = hashlib.sha256(f"{evidence_id}:{entry_id}".encode("utf-8")).hexdigest()
    return "hive_" + digest[:16]
