from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AmcacheRecord
from .reader import RawValue

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
VOLUME_RE = re.compile(r"^\{[0-9A-Fa-f-]{36}\}")

MODERN_SCHEMA = "inventory_application_file"
LEGACY_SCHEMA = "legacy_file"
UNKNOWN_SCHEMA = "unknown"

MODERN_FIELD_NAMES = {
    "executable_path": ("LowerCaseLongPath", "LongPath"),
    "file_id": ("FileId",),
    "size": ("Size",),
    "publisher": ("Publisher",),
    "product_name": ("ProductName",),
    "product_version": ("ProductVersion",),
    "binary_version": ("BinFileVersion", "Version"),
    "program_id": ("ProgramId",),
    "link_date": ("LinkDate",),
    "program_name": ("Name",),
    "binary_type": ("BinaryType",),
}

LEGACY_FIELD_NAMES = {
    "executable_path": ("0",),
    "size": ("1",),
    "program_id": ("100",),
    "file_id": ("101",),
}


def normalize_file_id(raw: str | None) -> dict[str, Any]:
    """Normalize an Amcache FileId without guessing.

    Returns raw, normalized hash, algorithm, validity and the exact method.
    A 44-hex value starting with ``0000`` is the common prefixed SHA-1 form;
    anything else is preserved raw and reported as unknown.
    """
    result = {
        "raw": raw,
        "algorithm": "unknown",
        "hash": None,
        "valid": False,
        "method": "none",
    }
    if not raw:
        return result
    value = str(raw).strip().lower()
    result["raw"] = raw
    if not value:
        return result
    if not HEX_RE.fullmatch(value):
        result["method"] = "non-hex"
        return result
    if len(value) == 40:
        result.update(
            algorithm="sha1",
            hash=value,
            valid=True,
            method="40-hex-sha1",
        )
        return result
    if len(value) == 44 and value.startswith("0000"):
        result.update(
            algorithm="sha1",
            hash=value[4:],
            valid=True,
            method="strip-4-hex-prefix-sha1",
        )
        return result
    if len(value) == 64:
        # 64 hex is SHA-256 shaped, but Amcache FileId is normally SHA-1.
        result["method"] = "64-hex-ambiguous"
        return result
    if len(value) == 44:
        result["method"] = "44-hex-unknown-prefix"
        return result
    result["method"] = f"unrecognized-length-{len(value)}"
    return result


def _value_map(values: list[RawValue]) -> dict[str, RawValue]:
    return {value.name.lower(): value for value in values}


def _pick(
    values: dict[str, RawValue], names: tuple[str, ...]
) -> tuple[str | None, str | None]:
    for name in names:
        value = values.get(name.lower())
        if value is None:
            continue
        if value.text_value is not None:
            return value.text_value, value.name
    return None, None


def _int_value(
    values: dict[str, RawValue], names: tuple[str, ...]
) -> tuple[int | None, str | None]:
    text, source = _pick(values, names)
    if text is None:
        return None, None
    try:
        return int(text, 0), source
    except (TypeError, ValueError):
        return None, source


def _parse_link_date(text: str | None) -> str | None:
    if not text:
        return None
    for fmt in (
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y",
    ):
        try:
            parsed = datetime.strptime(text.strip(), fmt).replace(
                tzinfo=timezone.utc
            )
            return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            continue
    return None


def is_amcache_key(key_path: str) -> bool:
    lowered = key_path.lower()
    return (
        "\\root\\inventoryapplicationfile\\" in lowered
        or "\\root\\file\\" in lowered
    )


def schema_for_path(key_path: str) -> str:
    lowered = key_path.lower()
    if "\\root\\inventoryapplicationfile\\" in lowered:
        return MODERN_SCHEMA
    if "\\root\\file\\" in lowered:
        return LEGACY_SCHEMA
    return UNKNOWN_SCHEMA


def volume_id_for_path(key_path: str) -> str | None:
    match = VOLUME_RE.match(key_path or "")
    if match:
        return match.group(0)
    lowered = key_path.lower()
    marker = "\\root\\file\\"
    if marker in lowered:
        tail = key_path[len(marker) + key_path.lower().index(marker) :]
        parts = tail.split("\\")
        if len(parts) >= 3 and VOLUME_RE.match(parts[1] or ""):
            return parts[1]
    return None


def parse_amcache_key(
    *,
    hive_id: str,
    key_path: str,
    key_mtime: str | None,
    values: list[RawValue],
    source_key_path: str | None = None,
) -> AmcacheRecord | None:
    schema = schema_for_path(key_path)
    if schema == UNKNOWN_SCHEMA:
        return None
    by_name = _value_map(values)
    source_names: dict[str, str] = {}
    warnings: list[str] = []

    mapping = MODERN_FIELD_NAMES if schema == MODERN_SCHEMA else LEGACY_FIELD_NAMES
    executable_path, source = _pick(by_name, mapping["executable_path"])
    if source:
        source_names["executable_path"] = source
    if not executable_path:
        warnings.append("no executable path value found")
    file_id_raw, source = _pick(by_name, mapping["file_id"])
    if source:
        source_names["file_id"] = source
    size, source = _int_value(by_name, mapping["size"])
    if source:
        source_names["size"] = source
    publisher, source = _pick(by_name, mapping.get("publisher", ()))
    if source:
        source_names["publisher"] = source
    product_name, source = _pick(by_name, mapping.get("product_name", ()))
    if source:
        source_names["product_name"] = source
    product_version, source = _pick(
        by_name, mapping.get("product_version", ())
    )
    if source:
        source_names["product_version"] = source
    binary_version, source = _pick(
        by_name, mapping.get("binary_version", ())
    )
    if source:
        source_names["binary_version"] = source
    program_id, source = _pick(by_name, mapping.get("program_id", ()))
    if source:
        source_names["program_id"] = source
    link_date_text, source = _pick(by_name, mapping.get("link_date", ()))
    if source:
        source_names["link_date"] = source
    program_name, source = _pick(by_name, mapping.get("program_name", ()))
    if source:
        source_names["program_name"] = source

    normalized = normalize_file_id(file_id_raw)
    if normalized["algorithm"] == "unknown" and file_id_raw:
        warnings.append(
            "FileId was preserved raw but its hash algorithm is unknown; "
            "no normalization was guessed"
        )
    if not file_id_raw:
        warnings.append("no FileId value found")

    executable_name = program_name
    if not executable_name and executable_path:
        executable_name = Path(str(executable_path).replace("\\", "/")).name
    if not program_name:
        program_name = product_name or executable_name

    return AmcacheRecord(
        record_id=0,
        hive_id=hive_id,
        source_key_path=source_key_path or key_path,
        source_value_names=source_names,
        schema=schema,
        program_name=program_name,
        executable_name=executable_name,
        executable_path=executable_path,
        file_id_raw=file_id_raw,
        hash_algorithm=normalized["algorithm"],
        hash_raw=normalized["raw"],
        hash_normalized=normalized["hash"],
        hash_valid=bool(normalized["valid"]),
        normalization_method=normalized["method"],
        size=size,
        publisher=publisher,
        product_name=product_name,
        product_version=product_version,
        binary_version=binary_version,
        compile_timestamp=_parse_link_date(link_date_text),
        key_mtime=key_mtime,
        first_run=None,
        last_modified=key_mtime,
        program_id=program_id,
        volume_id=volume_id_for_path(key_path),
        warnings=warnings,
    )
