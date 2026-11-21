from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import timezone
from pathlib import Path
from typing import Any, Iterator

from .detector import HiveHeader, inspect_hive_header
from .models import RegistryCorruptError, RegistryError

TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

BINARY_TYPES = {
    "REG_BINARY",
    "REG_NONE",
    "REG_RESOURCE_LIST",
    "REG_FULL_RESOURCE_DESCRIPTOR",
    "REG_RESOURCE_REQUIREMENTS_LIST",
}

EMBEDDED_NULL = "\u2400"


class RegistryLimitError(RegistryError):
    default_code = "registry_limit"


class RegistryTimeoutError(RegistryError):
    default_code = "registry_timeout"


@dataclass(slots=True)
class RawValue:
    name: str
    type_name: str
    type_id: int | None
    raw: bytes
    text_value: str | None
    preview_hex: str | None
    raw_sha256: str | None
    raw_size: int
    truncated: bool
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class KeyRecord:
    path: str
    name: str
    parent_path: str | None
    depth: int
    last_write_time: str | None
    subkey_count: int
    value_count: int
    subkeys: list[Any]
    values: list[RawValue]


def _iso_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    try:
        if getattr(value, "tzinfo", None) is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")
    except (AttributeError, ValueError):
        return str(value)[:64]


def _to_text(raw: bytes, warnings: list[str]) -> str:
    try:
        text = raw.decode("utf-16le")
    except UnicodeDecodeError:
        text = raw.decode("utf-16le", "replace")
        warnings.append("invalid UTF-16 sequence replaced")
    return text


def decode_value(
    name: str,
    type_id: int | None,
    raw: bytes,
    *,
    max_value_bytes: int,
    max_text_length: int,
    preview_bytes: int,
) -> RawValue:
    type_name = TYPE_NAMES.get(type_id, f"UNKNOWN_{type_id}") if type_id is not None else "UNKNOWN"
    warnings: list[str] = []
    total_size = len(raw)
    truncated = total_size > max_value_bytes
    if truncated:
        raw = raw[:max_value_bytes]
        warnings.append(
            f"value truncated at {max_value_bytes} bytes (raw size {total_size})"
        )
    text_value: str | None = None
    preview_hex: str | None = None

    if type_name in {"REG_SZ", "REG_EXPAND_SZ"}:
        text = _to_text(raw, warnings)
        text = text.rstrip("\x00")
        if "\x00" in text:
            warnings.append("embedded NUL in string value")
            text = text.replace("\x00", EMBEDDED_NULL)
        if len(text) > max_text_length:
            text = text[:max_text_length]
            warnings.append("decoded text length truncated")
        text_value = text
    elif type_name == "REG_MULTI_SZ":
        text = _to_text(raw, warnings)
        parts = [part for part in text.split("\x00") if part]
        joined = "\n".join(parts)
        if len(joined) > max_text_length:
            joined = joined[:max_text_length]
            warnings.append("decoded text length truncated")
        text_value = joined
    elif type_name == "REG_DWORD":
        if len(raw) >= 4:
            text_value = str(int.from_bytes(raw[:4], "little"))
        else:
            warnings.append("REG_DWORD shorter than 4 bytes")
    elif type_name == "REG_DWORD_BIG_ENDIAN":
        if len(raw) >= 4:
            text_value = str(int.from_bytes(raw[:4], "big"))
        else:
            warnings.append("REG_DWORD_BIG_ENDIAN shorter than 4 bytes")
    elif type_name == "REG_QWORD":
        if len(raw) >= 8:
            text_value = str(int.from_bytes(raw[:8], "little"))
        else:
            warnings.append("REG_QWORD shorter than 8 bytes")
    else:
        preview_hex = raw[: max(1, preview_bytes)].hex()
        if len(raw) > preview_bytes:
            warnings.append("binary preview truncated")

    return RawValue(
        name=name or "(default)",
        type_name=type_name,
        type_id=type_id,
        raw=raw,
        text_value=text_value,
        preview_hex=preview_hex,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=total_size,
        truncated=truncated,
        warnings=warnings,
    )


class HiveReader:
    """Read-only wrapper over python-registry with strict limits."""

    def __init__(self, path: Path | str, settings) -> None:
        self.path = Path(path)
        self.settings = settings
        self.header: HiveHeader = inspect_hive_header(self.path)
        if not self.header.signature_valid:
            raise RegistryCorruptError(
                "hive has no valid regf signature",
                details={
                    "signature": self.header.signature_valid,
                    "error": self.header.error,
                },
            )
        self._registry = None

    def open(self) -> None:
        if self._registry is not None:
            return
        try:
            from Registry import Registry  # type: ignore
        except Exception as exc:  # pragma: no cover - dependency guard
            raise RegistryError(
                "python-registry is not installed",
                code="registry_parser_unavailable",
            ) from exc
        try:
            self._registry = Registry.Registry(str(self.path))
        except Exception as exc:
            raise RegistryCorruptError(
                f"cannot parse registry hive: {exc}"[:500],
                details={"path": self.path.name},
            ) from exc

    def walk(self, deadline: float) -> Iterator[KeyRecord]:
        self.open()
        assert self._registry is not None
        try:
            root = self._registry.root()
        except Exception as exc:
            raise RegistryCorruptError(
                f"cannot read hive root key: {exc}"[:500]
            ) from exc
        max_keys = max(1, int(self.settings.registry_max_keys))
        max_depth = max(1, int(self.settings.registry_max_depth))
        max_value_bytes = max(1, int(self.settings.registry_max_value_bytes))
        max_text = max(1, int(self.settings.registry_max_text_length))
        preview = max(1, int(self.settings.registry_binary_preview_bytes))
        stack: list[tuple[Any, int, str | None]] = [(root, 0, None)]
        emitted = 0
        while stack:
            if emitted % 256 == 0 and time.monotonic() > deadline:
                raise RegistryTimeoutError("registry index build timed out")
            key, depth, parent_path = stack.pop()
            if depth > max_depth:
                raise RegistryLimitError(
                    f"registry depth exceeds {max_depth}",
                    details={"path": _safe_path(key)},
                )
            emitted += 1
            if emitted > max_keys:
                raise RegistryLimitError(
                    f"registry key limit {max_keys} reached",
                    details={"keys": emitted},
                )
            try:
                subkeys = list(key.subkeys())
            except Exception as exc:
                raise RegistryCorruptError(
                    f"cannot enumerate subkeys: {exc}"[:500]
                ) from exc
            try:
                raw_values = list(key.values())
            except Exception as exc:
                raise RegistryCorruptError(
                    f"cannot enumerate values: {exc}"[:500]
                ) from exc
            values: list[RawValue] = []
            for item in raw_values:
                try:
                    name = item.name()
                except Exception:
                    name = "(unknown)"
                try:
                    type_id = int(item.value_type())
                except Exception:
                    type_id = None
                try:
                    raw = item.raw_data()
                except Exception as exc:
                    values.append(
                        RawValue(
                            name=name or "(default)",
                            type_name=TYPE_NAMES.get(type_id, "UNKNOWN"),
                            type_id=type_id,
                            raw=b"",
                            text_value=None,
                            preview_hex=None,
                            raw_sha256=None,
                            raw_size=0,
                            truncated=False,
                            warnings=[f"cannot read raw value: {exc}"[:300]],
                        )
                    )
                    continue
                values.append(
                    decode_value(
                        name,
                        type_id,
                        raw,
                        max_value_bytes=max_value_bytes,
                        max_text_length=max_text,
                        preview_bytes=preview,
                    )
                )
            yield KeyRecord(
                path=_safe_path(key),
                name=_safe_name(key),
                parent_path=parent_path,
                depth=depth,
                last_write_time=_iso_timestamp(_safe_timestamp(key)),
                subkey_count=len(subkeys),
                value_count=len(values),
                subkeys=subkeys,
                values=values,
            )
            for child in reversed(subkeys):
                stack.append((child, depth + 1, _safe_path(key)))

    def close(self) -> None:
        if self._registry is not None:
            try:
                self._registry.close()
            except Exception:
                pass
            self._registry = None


def _safe_path(key: Any) -> str:
    try:
        return key.path()
    except Exception:
        return "<unreadable>"


def _safe_name(key: Any) -> str:
    try:
        name = key.name()
    except Exception:
        return "<unreadable>"
    return name or "(default)"


def _safe_timestamp(key: Any) -> Any:
    try:
        return key.timestamp()
    except Exception:
        return None
