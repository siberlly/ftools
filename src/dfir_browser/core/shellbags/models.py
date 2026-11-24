"""Models and errors for ShellBags."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..errors import DFIRError
from ..models import TRUST_LABEL

SHELLBAG_SCHEMA_VERSION = 1


class ShellbagError(DFIRError):
    default_code = "shellbag_error"


class ShellbagRejected(ShellbagError):
    default_code = "shellbag_rejected"


class ShellbagNotReady(ShellbagError):
    default_code = "shellbag_not_ready"


class ShellbagNotFound(ShellbagError):
    default_code = "shellbag_not_found"


@dataclass(slots=True)
class ShellbagNodeRecord:
    node_id: int
    evidence_id: str
    hive_id: str
    parent_id: int | None
    depth: int
    name: str | None
    path: str | None
    item_type: int
    type_name: str
    name_source: str | None
    is_dir: bool
    is_device: bool
    device_id: int | None
    drive: str | None
    volume_label: str | None
    guid: str | None
    device_path: str | None
    size_bytes: int | None
    key_last_write_utc: str | None
    embedded_timestamps: list[str] = field(default_factory=list)
    registry_key_path: str | None = None
    registry_value_name: str | None = None
    registry_key_id: int | None = None
    user_sid: str | None = None
    mru_rank: int | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class ShellbagDeviceRecord:
    device_id: int
    evidence_id: str
    node_id: int | None
    name: str | None
    kind: str
    detail: str | None
    drive: str | None
    volume_label: str | None
    user_sid: str | None
    first_seen_utc: str | None
    node_count: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class ShellbagHiveRecord:
    hive_id: str
    evidence_id: str
    entry_id: int
    path: str
    name: str
    hive_type: str
    user_sid: str | None
    state: str
    error: str | None
    node_count: int
    device_count: int
    extract_relpath: str | None
    updated_at: str | None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class ShellbagIndexState:
    evidence_id: str
    state: str
    progress: int
    hives: int
    nodes: int
    devices: int
    errors: list[str] = field(default_factory=list)
    updated_at: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data
