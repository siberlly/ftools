from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

EXECUTABLE_EXTENSIONS = (
    "exe", "dll", "msi", "scr", "com", "bat", "cmd", "ps1", "js", "vbs", "hta",
    "zip", "rar", "7z", "iso", "img",
)
ARCHIVE_EXTENSIONS = ("zip", "rar", "7z", "iso", "img", "tar", "gz")

IP_LITERAL_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass(slots=True)
class Preset:
    rule_id: str
    name: str
    description: str
    reason: str
    limitations: str
    filters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "reason": self.reason,
            "limitations": self.limitations,
            "filters": self.filters,
            "note": "Indicator only, not a malware verdict.",
        }


PRESETS: tuple[Preset, ...] = (
    Preset(
        rule_id="browser.executable_downloads",
        name="Executable and archive downloads",
        description="Downloads whose filename ends in an executable or archive extension.",
        reason="Executables and archives are common malware delivery containers.",
        limitations=(
            "Extension comes from the recorded filename or target path; "
            "renamed files without a known extension are not detected. "
            "A hit says nothing about whether the file is malicious."
        ),
        filters={"executable_only": True},
    ),
    Preset(
        rule_id="browser.incomplete_downloads",
        name="Incomplete or partial downloads",
        description="Downloads not in the complete state.",
        reason="Partial downloads may indicate blocked, cancelled or interrupted transfers.",
        limitations="State strings vary by browser version; unknown states are listed as-is.",
        filters={"states": ["in_progress", "interrupted", "cancelled", "unknown"]},
    ),
    Preset(
        rule_id="browser.ip_literal_urls",
        name="Downloads from IP literal hosts",
        description="Source URL host is a bare IPv4 address.",
        reason="Direct-IP downloads bypass DNS reputation and are common in phishing.",
        limitations="IPv6 literals and CNAME chains are not evaluated offline.",
        filters={"post_filter": "ip_literal"},
    ),
    Preset(
        rule_id="browser.http_downloads",
        name="Cleartext HTTP downloads",
        description="Source URL scheme is http (no TLS).",
        reason="Unencrypted transport allows tampering and content substitution.",
        limitations="Scheme comes from the stored URL; redirects are not re-followed.",
        filters={"post_filter": "http_scheme"},
    ),
    Preset(
        rule_id="browser.suspicious_schemes",
        name="Suspicious URL schemes",
        description="URLs using non-web schemes such as file, ftp, data or blob.",
        reason="Unusual schemes can indicate local file staging or script injection.",
        limitations="Only the recorded scheme is checked, not the payload.",
        filters={"post_filter": "suspicious_scheme"},
    ),
    Preset(
        rule_id="browser.deleted_targets",
        name="Download target deleted from filesystem",
        description="Downloads whose correlated filesystem entry is unallocated.",
        reason="Anti-forensic deletion of downloaded payloads is common.",
        limitations="Requires a successful filesystem correlation; missing matches are skipped.",
        filters={"post_filter": "deleted_target"},
    ),
    Preset(
        rule_id="browser.domain_filename_mismatch",
        name="Domain and filename mismatch",
        description="Downloaded filename does not contain the registrable domain label.",
        reason="Mismatched naming can indicate masquerading content.",
        limitations="Many legitimate downloads use generic or branded filenames; expect noise.",
        filters={"post_filter": "domain_filename_mismatch"},
    ),
    Preset(
        rule_id="browser.recent_window",
        name="Downloads in a recent window",
        description="Downloads in the last 24 hours of recorded activity.",
        reason="Focuses on activity near the end of the acquired period.",
        limitations="Requires at least one timestamped download.",
        filters={"post_filter": "recent_window"},
    ),
)

PRESET_BY_ID = {preset.rule_id: preset for preset in PRESETS}


def list_presets() -> list[dict[str, Any]]:
    return [preset.to_dict() for preset in PRESETS]


def get_preset(rule_id: str) -> Preset | None:
    return PRESET_BY_ID.get(rule_id)


def apply_post_filter(name: str, record: dict[str, Any]) -> bool:
    if name == "ip_literal":
        host = (record.get("host") or "").lower()
        return bool(IP_LITERAL_RE.match(host))
    if name == "http_scheme":
        url = (record.get("url") or "").lower()
        return url.startswith("http://")
    if name == "suspicious_scheme":
        url = (record.get("url") or "").lower()
        return any(
            url.startswith(f"{scheme}:")
            for scheme in ("file", "ftp", "data", "blob", "javascript")
        )
    if name == "deleted_target":
        return bool(record.get("_deleted_target"))
    if name == "domain_filename_mismatch":
        domain = record.get("domain") or ""
        filename = (record.get("filename") or "").lower()
        if not domain or not filename:
            return False
        label = domain.split(".")[0]
        return bool(label) and label not in filename
    if name == "recent_window":
        return bool(record.get("_recent"))
    return False
