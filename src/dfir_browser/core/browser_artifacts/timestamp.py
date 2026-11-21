from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Plausible bounds for forensic timestamps; outside these we keep raw + warn.
MIN_YEAR = 1995
MAX_YEAR = 2100
MIN_TS = datetime(MIN_YEAR, 1, 1, tzinfo=timezone.utc)
MAX_TS = datetime(MAX_YEAR, 1, 1, tzinfo=timezone.utc)

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$"
)


@dataclass(slots=True)
class Timestamp:
    utc: str | None
    raw: str | None
    method: str
    warning: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "utc": self.utc,
            "raw": self.raw,
            "method": self.method,
            "warning": self.warning,
        }


def _format(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _valid(value: datetime) -> bool:
    return MIN_TS <= value <= MAX_TS


def from_windows_filetime(value) -> Timestamp:
    """Windows FILETIME: 100 ns ticks since 1601-01-01 UTC."""
    raw = None if value is None else str(value)
    if value in (None, 0, "0", ""):
        return Timestamp(None, raw, "windows_filetime_zero")
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return Timestamp(None, raw, "windows_filetime_invalid", "not an integer")
    if ticks <= 0:
        return Timestamp(None, raw, "windows_filetime_invalid", "non-positive")
    try:
        moment = WINDOWS_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, ValueError):
        return Timestamp(None, raw, "windows_filetime_overflow", "out of range")
    if not _valid(moment):
        return Timestamp(None, raw, "windows_filetime_out_of_range", "implausible year")
    return Timestamp(_format(moment), raw, "windows_filetime")


def from_chromium(value) -> Timestamp:
    """Chromium: microseconds since 1601-01-01 UTC."""
    raw = None if value is None else str(value)
    if value in (None, 0, "0", ""):
        return Timestamp(None, raw, "chromium_zero")
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return Timestamp(None, raw, "chromium_invalid", "not an integer")
    if micros <= 0:
        return Timestamp(None, raw, "chromium_invalid", "non-positive")
    try:
        moment = WINDOWS_EPOCH + timedelta(microseconds=micros)
    except (OverflowError, ValueError):
        return Timestamp(None, raw, "chromium_overflow", "out of range")
    if not _valid(moment):
        return Timestamp(None, raw, "chromium_out_of_range", "implausible year")
    return Timestamp(_format(moment), raw, "chromium_1601_microseconds")


def from_unix_seconds(value) -> Timestamp:
    raw = None if value is None else str(value)
    if value in (None, 0, "0", ""):
        return Timestamp(None, raw, "unix_zero")
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return Timestamp(None, raw, "unix_invalid", "not an integer")
    if seconds <= 0:
        return Timestamp(None, raw, "unix_invalid", "non-positive")
    try:
        moment = UNIX_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return Timestamp(None, raw, "unix_overflow", "out of range")
    if not _valid(moment):
        return Timestamp(None, raw, "unix_out_of_range", "implausible year")
    return Timestamp(_format(moment), raw, "unix_seconds")


def from_unix_microseconds(value) -> Timestamp:
    raw = None if value is None else str(value)
    if value in (None, 0, "0", ""):
        return Timestamp(None, raw, "unix_micros_zero")
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return Timestamp(None, raw, "unix_micros_invalid", "not an integer")
    try:
        moment = UNIX_EPOCH + timedelta(microseconds=micros)
    except (OverflowError, ValueError):
        return Timestamp(None, raw, "unix_micros_overflow", "out of range")
    if not _valid(moment):
        return Timestamp(None, raw, "unix_micros_out_of_range", "implausible year")
    return Timestamp(_format(moment), raw, "unix_microseconds")


def from_datetime(value) -> Timestamp:
    if value is None:
        return Timestamp(None, None, "datetime_missing")
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if not _valid(moment):
            return Timestamp(None, str(value), "datetime_out_of_range")
        return Timestamp(_format(moment), str(value), "datetime")
    return Timestamp(None, str(value), "datetime_unsupported")


def from_iso(value) -> Timestamp:
    raw = None if value is None else str(value)
    if not value:
        return Timestamp(None, raw, "iso_missing")
    text = str(value).strip()
    if not _ISO_RE.match(text):
        return Timestamp(None, raw, "iso_unrecognized", "unrecognized timestamp")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return Timestamp(None, raw, "iso_invalid", "cannot parse")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if not _valid(moment):
        return Timestamp(None, raw, "iso_out_of_range", "implausible year")
    return Timestamp(_format(moment), raw, "iso8601")


def from_ese(value) -> Timestamp:
    """ESE timestamps arrive as datetime objects from dissect.esedb."""
    if isinstance(value, datetime):
        return from_datetime(value)
    if isinstance(value, (int, float)):
        return from_windows_filetime(value)
    return from_iso(value)
