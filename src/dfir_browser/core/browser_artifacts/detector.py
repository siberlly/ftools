from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ARTIFACT_TYPES, ArtifactCandidate

# ESE database signature (ulMagic 0x89ABCDEF, stored little-endian at offset 4)
ESE_MAGIC_OFFSET = 4
ESE_MAGIC = b"\xef\xcd\xab\x89"
SQLITE_MAGIC = b"SQLite format 3\x00"

USER_RE = re.compile(r"(?:^|/)(?:Users|home)/([^/]+)/", re.IGNORECASE)
# Windows: <browser>/User Data/<profile>/History
# Linux:   ~/.config/google-chrome/<profile>/History, snap/chromium/.../User Data/...
CHROMIUM_RE = re.compile(
    r"(?:Microsoft[ /]?Edge|Google/Chrome|Chromium|BraveSoftware/Brave-Browser)/User Data/([^/]+)/History$",
    re.IGNORECASE,
)
CHROMIUM_LINUX_RE = re.compile(
    r"(?:google-chrome|chromium|microsoft-edge|BraveSoftware/Brave-Browser)(?:-beta|-dev)?/([^/]+)/History$",
    re.IGNORECASE,
)
OPERA_RE = re.compile(
    r"(?:Opera Software/([^/]+)|/\.config/opera(?:-beta)?)/History$",
    re.IGNORECASE,
)
# Windows: <...>/Firefox/Profiles/<profile>/places.sqlite
# Linux:   ~/.mozilla/firefox/<profile>/places.sqlite
# Snap:    snap/firefox/common/.mozilla/firefox/<profile>/places.sqlite
FIREFOX_RE = re.compile(
    r"(?:Mozilla/)?Firefox/(?:Profiles/)?([^/]+)/places\.sqlite$", re.IGNORECASE
)
WEBCACHE_RE = re.compile(
    r"Microsoft/Windows/WebCache/WebCacheV\d+\.dat$", re.IGNORECASE
)


def identify_browser_details(path: str) -> tuple[str, str, str | None, str]:
    """Identify browser brand, engine, profile name, and human label from path.

    Returns:
        (brand, engine, profile_name, label)
    """
    p = path.replace("\\", "/")
    lowered = p.lower()

    brand = "unknown"
    engine = "unknown"
    label = "Unknown"
    profile = None

    # Detect brand and engine
    if "microsoft/edge" in lowered or "microsoft edge" in lowered or "microsoft-edge" in lowered:
        brand = "edge"
        engine = "chromium"
        label = "Microsoft Edge"
    elif "google/chrome" in lowered or "google chrome" in lowered or "google-chrome" in lowered:
        brand = "chrome"
        engine = "chromium"
        label = "Google Chrome"
    elif "bravesoftware" in lowered or "brave-browser" in lowered or "/brave/" in lowered:
        brand = "brave"
        engine = "chromium"
        label = "Brave"
    elif "opera software" in lowered or "/opera" in lowered:
        brand = "opera"
        engine = "chromium"
        label = "Opera"
    elif "chromium" in lowered:
        brand = "chromium"
        engine = "chromium"
        label = "Chromium"
    elif "firefox" in lowered or "mozilla" in lowered:
        brand = "firefox"
        engine = "gecko"
        label = "Mozilla Firefox"
    elif "webcache" in lowered:
        brand = "webcache"
        engine = "trident"
        label = "IE / Legacy Edge (WebCacheV01.dat)"

    # Detect profile
    if "user data/" in lowered:
        m = re.search(r"User Data/([^/]+)", p, re.IGNORECASE)
        if m:
            profile = m.group(1)
    elif brand in {"chrome", "chromium", "edge", "brave"}:
        matches = re.findall(
            r"(?:google-chrome|chromium|microsoft-edge|Brave-Browser)(?:-beta|-dev)?/([^/]+)",
            p,
            re.IGNORECASE,
        )
        for cand in reversed(matches):
            if cand.lower() not in {"dictionaries", "crashpad", "widevinecdm", "common", "current"}:
                profile = cand
                break
    elif brand == "opera":
        m = re.search(r"Opera Software/([^/]+)", p, re.IGNORECASE)
        if m:
            profile = m.group(1)
        elif "/.config/opera" in lowered:
            m = re.search(r"/\.config/opera(?:-beta)?/(.+)$", p, re.IGNORECASE)
            if m:
                rest = m.group(1).split("/")
                profile = rest[0] if len(rest) > 1 else "Default"
            else:
                profile = "Default"
    elif brand == "firefox":
        m = (
            re.search(r"(?:Profiles|\.mozilla/firefox)/([^/]+)", p, re.IGNORECASE)
            or re.search(r"(?:^|/)firefox/(?:Profiles/)?([^/]+)", p, re.IGNORECASE)
        )
        if m:
            candidate = m.group(1)
            if candidate.lower() not in {"crash reports", "pending pings", "profiles", "common"}:
                profile = candidate

    return brand, engine, profile, label


@dataclass(slots=True)
class ArtifactHeader:
    signature_valid: bool
    format: str
    detail: str | None = None


def inspect_artifact_header(path: Path) -> ArtifactHeader:
    """Read only the first 4 KiB; never parses the whole database."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError as exc:
        return ArtifactHeader(False, "unreadable", str(exc)[:200])
    if head[: len(SQLITE_MAGIC)] == SQLITE_MAGIC:
        return ArtifactHeader(True, "sqlite")
    if head[ESE_MAGIC_OFFSET : ESE_MAGIC_OFFSET + 4] == ESE_MAGIC:
        return ArtifactHeader(True, "ese")
    return ArtifactHeader(False, "unknown", "no SQLite or ESE signature")


def user_from_path(path: str) -> str | None:
    match = USER_RE.search(path or "")
    if match:
        candidate = match.group(1)
        if candidate.lower() not in {"public", "default", "default user", "all users"}:
            return candidate
    return None


def classify_entry(entry, *, evidence_id: str) -> ArtifactCandidate | None:
    path = entry.full_path or ""
    name = entry.basename or ""
    lowered = name.lower()
    browser = None
    artifact_type = None
    profile = None
    confidence = 0.0
    reasons: list[str] = []

    chromium = CHROMIUM_RE.search(path) or CHROMIUM_LINUX_RE.search(path)
    opera = OPERA_RE.search(path)
    firefox = FIREFOX_RE.search(path)
    webcache = WEBCACHE_RE.search(path)
    if webcache and lowered.startswith("webcachev") and lowered.endswith(".dat"):
        browser, artifact_type = "webcache", "webcache"
        confidence, reasons = 0.98, ["WebCacheV01.dat path"]
    elif chromium and lowered == "history":
        browser, artifact_type = "chromium", "chromium_history"
        profile = chromium.group(1)
        confidence, reasons = 0.97, ["Chromium User Data profile History"]
    elif opera and lowered == "history":
        browser, artifact_type = "chromium", "chromium_history"
        profile = opera.group(1) or "Opera Stable"
        confidence, reasons = 0.97, ["Opera profile History"]
    elif firefox and lowered == "places.sqlite":
        browser, artifact_type = "firefox", "firefox_places"
        profile = firefox.group(1)
        confidence, reasons = 0.97, ["Firefox profile places.sqlite"]
    else:
        return None

    lowered_path = path.lower()
    if "/appdata/" not in lowered_path:
        if any(
            marker in lowered_path
            for marker in (
                "/.mozilla/",
                "/.config/",
                "/snap/",
                "user data",
                "opera software",
                "bravesoftware",
            )
        ):
            reasons.append("Linux/snap browser profile path")
        else:
            confidence = max(0.4, confidence - 0.3)
            reasons.append("not under a known browser profile path")
    size = entry.size
    warnings: list[str] = []
    return ArtifactCandidate(
        evidence_id=evidence_id,
        entry_id=entry.id,
        inode=entry.inode,
        path=path,
        name=name,
        user=user_from_path(path),
        profile_name=profile,
        browser=browser,
        artifact_type=artifact_type,
        size=size,
        allocated=bool(entry.allocated),
        deleted=bool(entry.deleted),
        modified_time=entry.modified_time,
        confidence=round(confidence, 2),
        reason="; ".join(reasons),
        warnings=warnings,
    )


def browser_label(browser: str) -> str:
    from .models import BROWSERS

    return BROWSERS.get(browser, BROWSERS["unknown"])


def artifact_label(artifact_type: str) -> str:
    return ARTIFACT_TYPES.get(artifact_type, artifact_type)


def sidecar_names(entry) -> list[tuple[str, int]]:
    """Known SQLite/ESE sidecars for an artifact, as (suffix, inode)."""
    name = entry.basename or ""
    lowered = name.lower()
    if lowered.endswith(".sqlite") or lowered == "history":
        return [f"{name}-wal", f"{name}-shm", f"{name}-journal"]
    if lowered.endswith(".dat") and lowered.startswith("webcachev"):
        return [
            "WebCacheV01.jfm",
            "V01.log",
            "V01tmp.log",
            "V01.chk",
            "V0100003.log",
        ]
    return []


def build_hive_summary(candidates: list[ArtifactCandidate]) -> dict[str, Any]:
    users = sorted({c.user for c in candidates if c.user})
    browsers = sorted({c.browser for c in candidates})
    types = sorted({c.artifact_type for c in candidates})
    return {
        "total": len(candidates),
        "users": users,
        "browsers": browsers,
        "artifact_types": types,
    }
