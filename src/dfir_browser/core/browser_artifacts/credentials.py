"""Metadata-only inspection and forensic analysis of browser credential stores.

This module analyzes credential artifacts from Chromium (Chrome, Chromium, Edge,
Brave, Opera) and Firefox browser profiles. It strictly adheres to digital
forensics principles:
- Evidence images are never modified.
- Evidence data is never executed.
- Secrets, passwords and encryption keys are NEVER decrypted, dumped or revealed.
- Sensitive information (usernames) is masked by default.
- If encryption algorithm cannot be verified with complete evidence, status is UNKNOWN.
- Both raw timestamps and normalized UTC timestamps are preserved.
- Full provenance (source path, inode, partition offset, SHA-256) is recorded.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detector import identify_browser_details
from .models import (
    BROWSER_BRANDS,
    BROWSER_ENGINES,
    CredentialAnalysisResult,
    CredentialRecord,
    TRUST_LABEL,
)
from .timestamp import from_chromium, from_unix_milliseconds

logger = logging.getLogger("dfir_browser.credentials")

METADATA_ONLY_NOTE = (
    "Credential stores are reported as forensic metadata only. Passwords, "
    "cookie values, secret keys and tokens are never decrypted, executed or displayed."
)

# basename -> (kind, human label)
CREDENTIAL_FILES: dict[str, tuple[str, str]] = {
    "logins.json": ("firefox_logins", "Firefox saved logins"),
    "logins-backup.json": ("firefox_logins_backup", "Firefox saved logins (backup)"),
    "key4.db": ("nss_key_db", "NSS key database (key4)"),
    "key3.db": ("nss_key_db", "NSS key database (key3)"),
    "signons.sqlite": ("firefox_legacy_logins", "Firefox legacy logins"),
    "cert9.db": ("nss_cert_db", "NSS certificate database"),
    "cookies.sqlite": ("firefox_cookies", "Firefox cookies"),
    "formhistory.sqlite": ("firefox_formhistory", "Firefox form history"),
    "Login Data": ("chromium_logins", "Chromium saved logins"),
    "Login Data For Account": ("chromium_logins", "Chromium account logins"),
    "Web Data": ("chromium_webdata", "Chromium autofill/web data"),
    "Cookies": ("chromium_cookies", "Chromium cookies"),
    "Local State": ("chromium_local_state", "Chromium local state (OS crypt key ref)"),
}

SQLITE_STORES = {
    "cookies.sqlite": ("moz_cookies", "host"),
    "formhistory.sqlite": ("moz_formhistory", "fieldname"),
    "Cookies": ("cookies", "host_key"),
    "Login Data": ("logins", "origin_url"),
    "Login Data For Account": ("logins", "origin_url"),
    "Web Data": ("autofill", "name"),
}


@dataclass(slots=True)
class CredentialStoreReport:
    name: str
    kind: str
    label: str
    path: str
    size: int | None
    exists: bool
    record_count: int | None = None
    hosts: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Provenance fields
    source_path: str = ""
    inode: int | None = None
    partition_offset: int | None = None
    offset_unit: str = "sectors"
    sha256: str | None = None
    evidence_id: str = ""
    extracted_at: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "name": self.name,
            "kind": self.kind,
            "label": self.label,
            "path": self.path,
            "size": self.size,
            "exists": self.exists,
            "record_count": self.record_count,
            "hosts": list(self.hosts),
            "fields": list(self.fields),
            "warnings": list(self.warnings),
            "source_path": self.source_path or self.path,
            "inode": self.inode,
            "partition_offset": self.partition_offset,
            "offset_unit": self.offset_unit,
            "sha256": self.sha256,
            "evidence_id": self.evidence_id,
            "extracted_at": self.extracted_at,
            "provenance": dict(self.provenance),
            "note": METADATA_ONLY_NOTE,
        }


# ------------------------------------------------------------------
# Masking & Redaction Helpers
# ------------------------------------------------------------------
def mask_username(username: str | None) -> str:
    """Mask username or email to preserve privacy by default."""
    if not username:
        return ""
    text = str(username).strip()
    if not text:
        return ""
    if "@" in text:
        parts = text.split("@", 1)
        local, domain = parts[0], parts[1]
        if len(local) <= 1:
            masked_local = "*"
        elif len(local) == 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "***" + local[-1]
        return f"{masked_local}@{domain}"
    if len(text) <= 2:
        return "**"
    if len(text) == 3:
        return text[0] + "*" + text[-1]
    return text[0] + "***" + text[-1]


def mask_password(has_password: bool = True) -> str:
    """Return masked placeholder for password. Passwords are never revealed."""
    return "••••••••" if has_password else ""


# ------------------------------------------------------------------
# Protection Status Analysis
# ------------------------------------------------------------------
def determine_chromium_protection(
    password_blob: bytes | None,
    local_state_info: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Determine protection status without assuming algorithms on raw prefixes alone.

    If information is insufficient or unverified, status is UNKNOWN.
    """
    if not password_blob:
        return "EMPTY", "No password stored"

    # Chromium OSCrypt v10 / v11 prefix
    if password_blob.startswith(b"v10") or password_blob.startswith(b"v11"):
        version_str = password_blob[:3].decode(errors="replace")
        if local_state_info and local_state_info.get("has_encrypted_key"):
            key_format = local_state_info.get("key_format")
            if key_format == "DPAPI":
                return (
                    "OSCRYPT_AES_GCM",
                    f"OSCrypt {version_str} AES-256-GCM (DPAPI encrypted master key verified in Local State)",
                )
            return (
                "UNKNOWN",
                f"OSCrypt {version_str} header present but Local State key format ({key_format}) unverified",
            )
        # Without verifying Local State key presence, do not guess algorithm:
        return (
            "UNKNOWN",
            f"OSCrypt {version_str} header present, but Local State key unverified",
        )

    # Windows DPAPI standard header: DWORD 0x01000000 (CRYPTPROTECT_DEFAULT)
    if password_blob.startswith(b"\x01\x00\x00\x00"):
        if len(password_blob) >= 16:
            return "WINDOWS_DPAPI", "Windows DPAPI crypt32 data blob"
        return "UNKNOWN", "DPAPI prefix present but data structure truncated"

    # Check if purely printable plaintext
    try:
        decoded = password_blob.decode("utf-8")
        if decoded.isprintable() and len(decoded) > 0:
            return "PLAINTEXT", "Unencrypted plaintext credentials"
    except (UnicodeDecodeError, ValueError):
        pass

    return "UNKNOWN", "Unrecognized protection format"


def determine_firefox_protection(
    enc_type: int | None,
    has_key4: bool = False,
    has_key3: bool = False,
) -> tuple[str, str]:
    """Determine Firefox protection status. If key database is unverified, status is UNKNOWN."""
    if enc_type == 1:
        if has_key4:
            return "NSS_ENCRYPTED", "NSS encrypted (key4.db present in profile)"
        if has_key3:
            return "NSS_ENCRYPTED", "NSS legacy encrypted (key3.db present in profile)"
        return "UNKNOWN", "encType=1 reported but NSS key database unverified"
    if enc_type == 0:
        return "PLAINTEXT", "Unencrypted plaintext credentials"
    return "UNKNOWN", f"Unrecognized encType ({enc_type})"


# ------------------------------------------------------------------
# SQLite and JSON Store Analysis (Metadata summary)
# ------------------------------------------------------------------
def analyze_json_logins(path: Path, report: CredentialStoreReport) -> None:
    """Count logins and list hostnames only; never touch secret fields."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        report.warnings.append(f"logins.json could not be read as JSON: {exc}")
        return
    logins = data.get("logins") if isinstance(data, dict) else None
    if not isinstance(logins, list):
        report.record_count = 0
        report.warnings.append("no logins array in this file")
        return
    report.record_count = len(logins)
    hosts: list[str] = []
    for item in logins:
        if not isinstance(item, dict):
            continue
        host = item.get("hostname")
        if isinstance(host, str) and host and host not in hosts:
            hosts.append(host)
    report.hosts = sorted(hosts)[:50]
    report.fields.append("hostname (only)")
    report.warnings.append(
        "encrypted username/password fields are present but were not read"
    )


def analyze_sqlite_store(path: Path, report: CredentialStoreReport) -> None:
    """Read only table names, row count and a host/field-name column."""
    table_spec = SQLITE_STORES.get(report.name)
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5.0
        )
    except sqlite3.Error as exc:
        report.warnings.append(f"database could not be opened: {exc}")
        return
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not tables:
            report.record_count = 0
            return
        table, column = table_spec if table_spec else (None, None)
        if table not in tables:
            report.record_count = None
            report.warnings.append(
                "schema differs from the expected layout; only file metadata shown"
            )
            return
        quoted = '"' + table.replace('"', '""') + '"'
        count = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()
        report.record_count = int(count[0]) if count else 0
        target = report.fields if report.name == "formhistory.sqlite" else report.hosts
        if column:
            values: list[str] = []
            try:
                rows = connection.execute(
                    f"SELECT DISTINCT \"{column}\" FROM {quoted} "
                    f"WHERE \"{column}\" IS NOT NULL LIMIT 60"
                )
                for row in rows:
                    text = str(row[0])
                    if text and text not in values:
                        values.append(text)
            except sqlite3.Error as exc:
                report.warnings.append(f"column {column!r} could not be read: {exc}")
            target.extend(sorted(values)[:50])
        report.warnings.append(
            "values, usernames, passwords and cookie contents were not read"
        )
    except sqlite3.Error as exc:
        report.warnings.append(f"metadata query failed: {exc}")
    finally:
        connection.close()


def analyze_store(path: Path, report: CredentialStoreReport) -> CredentialStoreReport:
    report.path = str(path)
    try:
        report.size = path.stat().st_size
    except OSError:
        report.size = None
    report.exists = True
    report.warnings = [w for w in report.warnings if w != "file not present in this profile"]
    if report.kind in {"firefox_logins", "firefox_logins_backup"}:
        analyze_json_logins(path, report)
    elif report.name in SQLITE_STORES:
        analyze_sqlite_store(path, report)
    else:
        report.warnings.append(
            "key/certificate store: presence and size only, contents not parsed"
        )
    return report


def empty_report(name: str, path: str) -> CredentialStoreReport:
    kind, label = CREDENTIAL_FILES.get(name, ("other", name))
    return CredentialStoreReport(
        name=name,
        kind=kind,
        label=label,
        path=path,
        size=None,
        exists=False,
        warnings=["file not present in this profile"],
    )


# ------------------------------------------------------------------
# Detailed Credential Records Extraction
# ------------------------------------------------------------------
def inspect_local_state(path: Path | None) -> dict[str, Any]:
    """Inspect Local State for OSCrypt configuration without exposing keys."""
    info: dict[str, Any] = {
        "exists": False,
        "has_encrypted_key": False,
        "key_format": "NONE",
    }
    if not path or not path.is_file():
        return info
    info["exists"] = True
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        os_crypt = data.get("os_crypt") if isinstance(data, dict) else None
        if isinstance(os_crypt, dict):
            raw_key = os_crypt.get("encrypted_key")
            if isinstance(raw_key, str) and raw_key:
                info["has_encrypted_key"] = True
                import base64

                try:
                    decoded = base64.b64decode(raw_key)
                    if decoded.startswith(b"DPAPI"):
                        info["key_format"] = "DPAPI"
                    else:
                        info["key_format"] = "OTHER"
                except Exception:
                    info["key_format"] = "INVALID"
    except Exception as exc:
        info["warning"] = f"could not read Local State: {exc}"
    return info


def parse_chromium_logins(
    path: Path,
    context: dict[str, Any],
    *,
    mask_sensitive: bool = True,
    local_state_info: dict[str, Any] | None = None,
) -> list[CredentialRecord]:
    """Parse Chromium Login Data SQLite database into CredentialRecord objects.

    Adheres to forensic read-only and safety rules.
    """
    records: list[CredentialRecord] = []
    if not path.is_file():
        return records

    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5.0
        )
    except sqlite3.Error as exc:
        logger.warning("could not open SQLite database %s: %s", path, exc)
        return records

    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "logins" not in tables:
            return records

        # Query existing columns dynamically to handle schema differences across Chromium versions
        cursor = connection.execute("PRAGMA table_info(logins)")
        cols = {row[1] for row in cursor.fetchall()}

        fields = [
            "origin_url" if "origin_url" in cols else "NULL AS origin_url",
            "action_url" if "action_url" in cols else "NULL AS action_url",
            "username_element" if "username_element" in cols else "NULL AS username_element",
            "username_value" if "username_value" in cols else "NULL AS username_value",
            "password_element" if "password_element" in cols else "NULL AS password_element",
            "password_value" if "password_value" in cols else "NULL AS password_value",
            "date_created" if "date_created" in cols else "NULL AS date_created",
            "date_last_used" if "date_last_used" in cols else "NULL AS date_last_used",
            "times_used" if "times_used" in cols else "0 AS times_used",
            "date_password_modified" if "date_password_modified" in cols else "NULL AS date_password_modified",
        ]
        query = f"SELECT {', '.join(fields)} FROM logins ORDER BY date_created DESC LIMIT 1000"
        rows = connection.execute(query).fetchall()

        brand = context.get("brand") or "chromium"
        brand_label = BROWSER_BRANDS.get(brand, BROWSER_BRANDS["unknown"])
        engine = context.get("engine") or "chromium"
        profile = context.get("profile") or "Default"
        user = context.get("user")
        source_path = context.get("source_path", str(path))
        entry_id = context.get("entry_id")
        inode = context.get("inode")
        partition_offset = context.get("partition_offset")
        offset_unit = context.get("offset_unit", "sectors")
        sha256 = context.get("sha256")
        evidence_id = context.get("evidence_id", "")
        extracted_at = context.get("extracted_at")
        provenance = context.get("provenance", {})

        for idx, row in enumerate(rows):
            origin_url, action_url, user_elem, user_val, pass_elem, pass_val, dt_create, dt_used, times_used, dt_mod = row
            website = str(origin_url or action_url or "unknown").strip()
            raw_username = str(user_val) if user_val is not None else None
            masked_user = mask_username(raw_username)

            pass_blob = bytes(pass_val) if pass_val is not None else None
            has_pass = bool(pass_blob and len(pass_blob) > 0)
            pass_masked = mask_password(has_pass)

            prot_status, prot_details = determine_chromium_protection(
                pass_blob, local_state_info
            )

            ts_create = from_chromium(dt_create)
            ts_used = from_chromium(dt_used)
            ts_mod = from_chromium(dt_mod) if dt_mod else None

            record = CredentialRecord(
                record_id=f"cred_cr_{idx}_{abs(hash(website + (raw_username or '')))}",
                website=website,
                action_url=str(action_url) if action_url else None,
                brand=brand,
                brand_label=brand_label,
                engine=engine,
                browser=brand,
                profile=profile,
                user=user,
                username_element=str(user_elem) if user_elem else None,
                username_masked=masked_user,
                username_raw=raw_username if not mask_sensitive else None,
                has_password=has_pass,
                password_masked=pass_masked,
                password_element=str(pass_elem) if pass_elem else None,
                protection_status=prot_status,
                protection_details=prot_details,
                created_time_utc=ts_create.utc,
                created_time_raw=ts_create.raw,
                last_used_time_utc=ts_used.utc,
                last_used_time_raw=ts_used.raw,
                password_changed_utc=ts_mod.utc if ts_mod else None,
                password_changed_raw=ts_mod.raw if ts_mod else None,
                times_used=int(times_used or 0),
                source_path=source_path,
                source_artifact_name=path.name,
                entry_id=entry_id,
                inode=inode,
                partition_offset=partition_offset,
                offset_unit=offset_unit,
                sha256=sha256,
                evidence_id=evidence_id,
                extracted_at=extracted_at,
                provenance=provenance,
            )
            records.append(record)

    except sqlite3.Error as exc:
        logger.warning("database error reading %s: %s", path, exc)
    finally:
        connection.close()

    return records


def parse_firefox_logins(
    path: Path,
    context: dict[str, Any],
    *,
    mask_sensitive: bool = True,
    has_key4: bool = False,
    has_key3: bool = False,
) -> list[CredentialRecord]:
    """Parse Firefox logins.json into CredentialRecord objects."""
    records: list[CredentialRecord] = []
    if not path.is_file():
        return records

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(content)
    except (OSError, ValueError) as exc:
        logger.warning("could not parse logins.json %s: %s", path, exc)
        return records

    if not isinstance(data, dict):
        return records
    logins = data.get("logins")
    if not isinstance(logins, list):
        return records

    brand = context.get("brand") or "firefox"
    brand_label = BROWSER_BRANDS.get(brand, "Mozilla Firefox")
    engine = context.get("engine") or "gecko"
    profile = context.get("profile") or "Default"
    user = context.get("user")
    source_path = context.get("source_path", str(path))
    entry_id = context.get("entry_id")
    inode = context.get("inode")
    partition_offset = context.get("partition_offset")
    offset_unit = context.get("offset_unit", "sectors")
    sha256 = context.get("sha256")
    evidence_id = context.get("evidence_id", "")
    extracted_at = context.get("extracted_at")
    provenance = context.get("provenance", {})

    for idx, item in enumerate(logins):
        if not isinstance(item, dict):
            continue
        website = str(item.get("hostname") or item.get("formSubmitURL") or "unknown").strip()
        user_field = item.get("usernameField")
        enc_user = item.get("encryptedUsername")
        enc_pass = item.get("encryptedPassword")
        pass_field = item.get("passwordField")
        enc_type = item.get("encType")

        # ``encryptedUsername`` is a base64 NSS SDRM container, not a username.
        # Masking the base64 would display meaningless characters, so expose the
        # real field name and mark the value as encrypted instead.
        if enc_type == 0:
            raw_user = str(enc_user) if enc_user is not None else None
            masked_user = mask_username(raw_user)
        else:
            raw_user = None
            masked_user = "[ENCRYPTED]"
        has_pass = bool(enc_pass)

        prot_status, prot_details = determine_firefox_protection(
            enc_type, has_key4=has_key4, has_key3=has_key3
        )

        dt_create = item.get("timeCreated")
        dt_used = item.get("timeLastUsed")
        dt_mod = item.get("timePasswordChanged")
        times_used = item.get("timesUsed")

        ts_create = from_unix_milliseconds(dt_create)
        ts_used = from_unix_milliseconds(dt_used)
        ts_mod = from_unix_milliseconds(dt_mod) if dt_mod else None

        record = CredentialRecord(
            record_id=f"cred_ff_{idx}_{abs(hash(website + (raw_user or '')))}",
            website=website,
            action_url=str(item.get("formSubmitURL")) if item.get("formSubmitURL") else None,
            brand=brand,
            brand_label=brand_label,
            engine=engine,
            browser=brand,
            profile=profile,
            user=user,
            username_element=str(user_field) if user_field else None,
            username_masked=masked_user,
            username_raw=raw_user if not mask_sensitive else None,
            has_password=has_pass,
            password_masked=mask_password(has_pass),
            password_element=str(pass_field) if pass_field else None,
            protection_status=prot_status,
            protection_details=prot_details,
            created_time_utc=ts_create.utc,
            created_time_raw=ts_create.raw,
            last_used_time_utc=ts_used.utc,
            last_used_time_raw=ts_used.raw,
            password_changed_utc=ts_mod.utc if ts_mod else None,
            password_changed_raw=ts_mod.raw if ts_mod else None,
            times_used=int(times_used or 0),
            source_path=source_path,
            source_artifact_name=path.name,
            entry_id=entry_id,
            inode=inode,
            partition_offset=partition_offset,
            offset_unit=offset_unit,
            sha256=sha256,
            evidence_id=evidence_id,
            extracted_at=extracted_at,
            provenance=provenance,
        )
        records.append(record)

    return records


# ------------------------------------------------------------------
# Investigator Export Functions (Redacted by default)
# ------------------------------------------------------------------
def export_credentials_json(
    records: list[CredentialRecord],
    *,
    mask_sensitive: bool = True,
) -> str:
    """Export credential records as redacted forensic metadata only.

    ``mask_sensitive`` remains accepted for compatibility, but exports never
    include raw usernames or any credential secret.
    """
    exported = []
    for r in records:
        d = r.to_dict()
        d["username_raw"] = None
        exported.append(d)
    return json.dumps(
        {
            "trust": TRUST_LABEL,
            "count": len(exported),
            "mask_sensitive": True,
            "records": exported,
        },
        indent=2,
        ensure_ascii=False,
    )


def export_credentials_csv(
    records: list[CredentialRecord],
    *,
    mask_sensitive: bool = True,
) -> str:
    """Export credential records as redacted forensic metadata only."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "website",
        "action_url",
        "browser_brand",
        "browser_engine",
        "profile",
        "os_user",
        "username",
        "has_password",
        "protection_status",
        "protection_details",
        "created_time_utc",
        "created_time_raw",
        "last_used_time_utc",
        "last_used_time_raw",
        "times_used",
        "source_path",
        "inode",
        "partition_offset",
        "sha256",
        "evidence_id",
    ])
    for r in records:
        username = r.username_masked
        writer.writerow([
            r.website,
            r.action_url or "",
            r.brand_label,
            r.engine,
            r.profile,
            r.user or "",
            username,
            "YES" if r.has_password else "NO",
            r.protection_status,
            r.protection_details,
            r.created_time_utc or "",
            r.created_time_raw or "",
            r.last_used_time_utc or "",
            r.last_used_time_raw or "",
            r.times_used,
            r.source_path,
            r.inode if r.inode is not None else "",
            r.partition_offset if r.partition_offset is not None else "",
            r.sha256 or "",
            r.evidence_id,
        ])
    return output.getvalue()
