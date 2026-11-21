from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import LogCandidate

EVTX_MAGIC = b"ElfFile\x00"
LOGS_PATH_RE = re.compile(
    r"(?:^|/)Windows/System32/winevt/Logs/[^/]+\.evtx$", re.IGNORECASE
)
MIN_SENSIBLE_SIZE = 4096
MAX_SENSIBLE_SIZE = 2 * 1024 * 1024 * 1024

_PRIORITY_EXACT = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "windows powershell": "Windows PowerShell",
    "microsoft-windows-powershell%4operational": "Microsoft-Windows-PowerShell/Operational",
    "microsoft-windows-windows defender%4operational": (
        "Microsoft-Windows-Windows Defender/Operational"
    ),
    "microsoft-windows-taskscheduler%4operational": (
        "Microsoft-Windows-TaskScheduler/Operational"
    ),
    "microsoft-windows-sysmon%4operational": (
        "Microsoft-Windows-Sysmon/Operational"
    ),
    "microsoft-windows-wmi-activity%4operational": (
        "Microsoft-Windows-WMI-Activity/Operational"
    ),
    "microsoft-windows-bits-client%4operational": (
        "Microsoft-Windows-Bits-Client/Operational"
    ),
    "microsoft-windows-dns-client%4operational": (
        "Microsoft-Windows-DNS-Client/Operational"
    ),
    "microsoft-windows-terminalservices-localsessionmanager%4operational": (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    ),
    "microsoft-windows-terminalservices-remoteconnectionmanager%4operational": (
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    ),
}
PRIORITY_FAMILIES = ("microsoft-windows-terminalservices-",)


@dataclass(slots=True)
class EvtxHeader:
    signature_valid: bool
    size: int | None
    chunk_count: int | None
    flags: int | None
    error: str | None = None


def inspect_evtx_header(path: Path) -> EvtxHeader:
    """Read the 128-byte EVTX file header only."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(4096)
    except OSError as exc:
        return EvtxHeader(False, None, None, None, str(exc)[:300])
    if len(header) < 128 or header[:8] != EVTX_MAGIC:
        return EvtxHeader(
            False,
            None,
            None,
            None,
            "missing ElfFile signature" if len(header) >= 8 else "file too short",
        )
    import os

    try:
        size = os.path.getsize(path)
    except OSError:
        size = None
    chunk_count = int.from_bytes(header[42:44], "little")
    flags = int.from_bytes(header[120:124], "little")
    return EvtxHeader(True, size, chunk_count, flags)


def channel_from_filename(name: str) -> str:
    stem = re.sub(r"\.evtx$", "", name, flags=re.IGNORECASE)
    if not stem:
        return "unknown"
    lowered = stem.lower()
    if lowered in _PRIORITY_EXACT:
        return _PRIORITY_EXACT[lowered]
    if "%4" in stem:
        base, _, tail = stem.partition("%4")
        label = {"operational": "Operational", "admin": "Admin"}.get(
            tail.lower(), tail
        )
        return f"{base}/{label}" if label else base
    return stem


def is_priority_channel(channel: str) -> bool:
    if channel in _PRIORITY_EXACT.values():
        return True
    lowered = channel.lower()
    return any(family in lowered for family in PRIORITY_FAMILIES)


def classify_entry(entry, *, evidence_id: str) -> LogCandidate | None:
    name = (entry.basename or "").strip()
    if not name.lower().endswith(".evtx"):
        return None
    path = entry.full_path or ""
    channel = channel_from_filename(name)
    confidence = 0.6
    reasons = ["evtx extension"]
    if LOGS_PATH_RE.search(path):
        confidence = 0.98
        reasons.append("Windows winevt Logs path")
    elif "/winevt/logs/" in path.lower():
        confidence = 0.9
        reasons.append("winevt logs path")
    if name.lower().rstrip(".evtx") in {
        "security",
        "system",
        "application",
    }:
        confidence = min(0.99, confidence + 0.01)
    size = entry.size
    warnings: list[str] = []
    if size is not None and size < MIN_SENSIBLE_SIZE:
        warnings.append(
            f"file size {size} bytes is small for an EVTX log; may be empty or truncated"
        )
        confidence = max(0.3, confidence - 0.25)
    if size is not None and size > MAX_SENSIBLE_SIZE:
        warnings.append("file size exceeds the configured EVTX maximum")
    return LogCandidate(
        evidence_id=evidence_id,
        entry_id=entry.id,
        inode=entry.inode,
        path=path,
        name=name,
        channel=channel,
        size=size,
        allocated=bool(entry.allocated),
        deleted=bool(entry.deleted),
        created_time=entry.created_time,
        modified_time=entry.modified_time,
        accessed_time=entry.accessed_time,
        mft_modified_time=entry.mft_modified_time,
        confidence=round(confidence, 2),
        reason="; ".join(reasons),
        priority=is_priority_channel(channel),
        warnings=warnings,
    )


LEVEL_NAMES = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}


def level_name(value: int | None) -> str | None:
    if value is None:
        return None
    return LEVEL_NAMES.get(value, f"Level{value}")


def candidate_summary(payload: dict[str, Any]) -> str:
    return (
        f"{payload.get('channel') or 'unknown'} "
        f"event {payload.get('event_id') or '?'} "
        f"from {payload.get('provider_name') or 'unknown provider'}"
    )
