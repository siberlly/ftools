from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import HiveCandidate, SENSITIVE_HIVE_TYPES

KNOWN_NAMES = {
    "system": "system",
    "software": "software",
    "sam": "sam",
    "security": "security",
    "default": "default",
    "ntuser.dat": "ntuser",
    "usrclass.dat": "usrclass",
    "amcache.hve": "amcache",
}

CONFIG_PATH_RE = re.compile(
    r"(^|/)Windows/System32/config/[^/]+$", re.IGNORECASE
)
USER_PROFILE_RE = re.compile(
    r"(?:^|/)(?:Users|Documents and Settings)/([^/]+)/", re.IGNORECASE
)
VOLUME_GUID_RE = re.compile(
    r"^\{[0-9A-Fa-f-]{36}\}", re.IGNORECASE
)


@dataclass(slots=True)
class HiveHeader:
    signature_valid: bool
    sequence1: int | None
    sequence2: int | None
    dirty: bool | None
    last_written: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_valid": self.signature_valid,
            "sequence1": self.sequence1,
            "sequence2": self.sequence2,
            "dirty": self.dirty,
            "last_written": self.last_written,
            "error": self.error,
        }


def _filetime_to_iso(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        base = datetime(1601, 1, 1, tzinfo=timezone.utc)
        return (
            (base + timedelta(microseconds=value / 10))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, ValueError):
        return None


def inspect_hive_header(path: Path) -> HiveHeader:
    """Read only the 4 KiB base block. Never parses the whole hive."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(4096)
    except OSError as exc:
        return HiveHeader(False, None, None, None, None, str(exc)[:300])
    if len(header) < 512 or header[:4] != b"regf":
        return HiveHeader(
            False,
            None,
            None,
            None,
            None,
            "missing regf signature" if len(header) >= 4 else "hive header too short",
        )
    sequence1 = int.from_bytes(header[4:8], "little")
    sequence2 = int.from_bytes(header[8:12], "little")
    raw_time = int.from_bytes(header[12:20], "little")
    return HiveHeader(
        signature_valid=True,
        sequence1=sequence1,
        sequence2=sequence2,
        dirty=sequence1 != sequence2,
        last_written=_filetime_to_iso(raw_time),
    )


def owner_from_path(path: str) -> str | None:
    match = USER_PROFILE_RE.search(path or "")
    if not match:
        return None
    owner = match.group(1)
    if owner.lower() in {"public", "default", "all users", "default user"}:
        return owner
    return owner


def classify_entry(entry, *, evidence_id: str) -> HiveCandidate | None:
    name = (entry.basename or "").strip()
    lowered = name.lower()
    path = entry.full_path or ""
    hive_type = KNOWN_NAMES.get(lowered)
    confidence = 0.0
    reasons: list[str] = []
    if hive_type:
        confidence = 0.75
        reasons.append(f"known hive filename {name}")
        if CONFIG_PATH_RE.search(path):
            confidence = 0.95
            reasons.append("known Windows config path")
        if hive_type in {"ntuser", "usrclass"}:
            if owner_from_path(path):
                confidence = 0.95
                reasons.append("user profile path")
            else:
                confidence = min(confidence, 0.8)
        if hive_type == "amcache" and "appcompat" in path.lower():
            confidence = 0.98
            reasons.append("Amcache path")
    elif lowered.endswith(".hve"):
        hive_type = "other"
        confidence = 0.5
        reasons.append("non-standard .hve extension")
    else:
        return None
    owner = owner_from_path(path)
    sensitive = hive_type in SENSITIVE_HIVE_TYPES
    warnings: list[str] = []
    if sensitive:
        warnings.append(
            "Sensitive hive: metadata browsing only; credential material is "
            "never decrypted or extracted."
        )
    return HiveCandidate(
        evidence_id=evidence_id,
        entry_id=entry.id,
        inode=entry.inode,
        path=path,
        name=name,
        hive_type=hive_type,
        owner=owner,
        size=entry.size,
        allocated=bool(entry.allocated),
        deleted=bool(entry.deleted),
        modified_time=entry.modified_time,
        sensitive=sensitive,
        confidence=round(confidence, 2),
        reason="; ".join(reasons),
        warnings=warnings,
    )
