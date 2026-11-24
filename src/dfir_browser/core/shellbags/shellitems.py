"""Shell item (IDList) decoding for ShellBags.

Only the raw shell item bytes are used. Names are recovered from the documented
layouts where available and from embedded UTF-16 strings otherwise, which is
what makes ``type 0x00`` MTP/portable-device items usable instead of
``<UNKNOWN: 0x00>``.
"""
from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Shell item type codes (subset with well-known meaning).
TYPE_NAMES = {
    0x00: "unknown",
    0x1F: "root_folder",
    0x20: "volume",
    0x21: "volume",
    0x23: "network_location",
    0x25: "network_location",
    0x29: "network_location",
    0x2A: "network_location",
    0x2E: "guid_folder",
    0x2F: "volume",
    0x30: "file_entry",
    0x31: "directory",
    0x32: "file",
    0x35: "network_location",
    0x39: "network_location",
    0x3A: "network_location",
    0x3D: "network_location",
    0x40: "control_panel",
    0x41: "network",
    0x42: "network",
    0x46: "network",
    0x47: "network",
    0x4C: "users_property_view",
    0x4D: "users_property_view",
    0x4E: "users_property_view",
    0x52: "uri",
    0x53: "uri",
    0x54: "uri",
    0x55: "uri",
    0x58: "control_panel",
    0x59: "control_panel",
    0x5A: "control_panel",
    0x5C: "control_panel",
    0x5E: "control_panel",
    0x61: "uri",
    0x62: "uri",
    0x63: "uri",
    0x64: "uri",
    0x65: "uri",
    0x66: "uri",
    0x67: "uri",
    0x68: "uri",
    0x69: "uri",
    0x6A: "uri",
    0x6B: "uri",
    0x6C: "uri",
    0x6D: "uri",
    0x6E: "uri",
    0x6F: "uri",
    0x70: "uri",
    0x71: "control_panel",
    0x72: "control_panel",
    0x74: "delegate",
    0x75: "delegate",
    0x76: "delegate",
    0x77: "delegate",
    0x78: "delegate",
    0x79: "delegate",
    0x7A: "delegate",
    0x7B: "delegate",
    0x7C: "delegate",
    0x7D: "delegate",
}

# Well-known shell folder GUIDs.
ROOT_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "5e6ab780-7743-11cf-a12b-00aa004ae837": "My Computer",
}

KNOWN_FOLDER_GUIDS = {
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "ed4824af-dce4-45a8-81e2-fc7965083634": "Documents",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "c4aa340d-f20f-4863-afef-f87ef2e6ba25": "Public",
    "1b3ea5dc-b587-4786-b4ef-bd1dc332aeae": "Libraries",
}

# MTP / portable-device interface classes seen in shell item device paths.
DEVICE_PORTABLE_GUID = "6ac27878-a6fa-4155-ba85-f98f491d4f33"
USB_PATH_RE = re.compile(
    r"usb#vid_[0-9a-f]{4}&pid_[0-9a-f]{4}", re.IGNORECASE
)
DEVICE_PATH_RE = re.compile(r"^\\\\\?\\|^\\\?\?\\|^usb#|^swd#", re.IGNORECASE)
GUID_RE = re.compile(r"^\{[0-9a-fA-F-]{36}\}$")
SID_RE = re.compile(r"^SID-\{")
PROP_RE = re.compile(r"^prop\d+$", re.IGNORECASE)
RESOURCE_RE = re.compile(r"^@?[\w.-]+\.(dll|exe),-\d+$", re.IGNORECASE)
GENERIC_LABELS = {
    "generic hierarchical",
    "internal storage",
    "removable storage",
    "portable device",
}


@dataclass(slots=True)
class ParsedItem:
    item_type: int
    type_name: str
    name: str | None
    name_source: str | None
    is_dir: bool
    is_device: bool
    device_kind: str | None
    drive: str | None
    volume_label: str | None
    guid: str | None
    size_bytes: int | None
    embedded_timestamps: list[str] = field(default_factory=list)
    device_path: str | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_type": self.item_type,
            "type_name": self.type_name,
            "name": self.name,
            "name_source": self.name_source,
            "is_dir": self.is_dir,
            "is_device": self.is_device,
            "device_kind": self.device_kind,
            "drive": self.drive,
            "volume_label": self.volume_label,
            "guid": self.guid,
            "size_bytes": self.size_bytes,
            "embedded_timestamps": self.embedded_timestamps,
            "device_path": self.device_path,
            "warnings": self.warnings,
        }


def _plausible(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        moment = WINDOWS_EPOCH + timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return None
    if not 1995 <= moment.year <= 2100:
        return None
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def dos_datetime(value: int) -> str | None:
    """Decode a packed DOS date/time (high 16 = date, low 16 = time)."""
    if not value:
        return None
    date = (value >> 16) & 0xFFFF
    time = value & 0xFFFF
    year = 1980 + ((date >> 9) & 0x7F)
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = (time >> 11) & 0x1F
    minute = (time >> 5) & 0x3F
    second = (time & 0x1F) * 2
    if not (1995 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    try:
        return (
            datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except ValueError:
        return None


def _ansi(data: bytes) -> str:
    text = data.split(b"\x00", 1)[0]
    return text.decode("cp1252", "replace").strip()


def utf16_strings(data: bytes) -> list[tuple[int, str]]:
    """Return (offset, text) for printable UTF-16LE runs, even and odd aligned."""
    found: list[tuple[int, str]] = []
    for start in (0, 1):
        index = start
        while index + 1 < len(data):
            chars: list[str] = []
            begin = index
            while index + 1 < len(data):
                code = data[index] | (data[index + 1] << 8)
                if 32 <= code < 0x7F:
                    chars.append(chr(code))
                    index += 2
                elif code == 0:
                    break
                else:
                    chars = []
                    break
            if len(chars) >= 3:
                found.append((begin, "".join(chars)))
                index += 2
            else:
                index += 2
    return found


def _meaningful(text: str) -> bool:
    value = text.strip()
    if len(value) < 2:
        return False
    low = value.lower()
    if GUID_RE.match(value) or SID_RE.match(value) or PROP_RE.match(value):
        return False
    if RESOURCE_RE.match(value):
        return False
    if low in GENERIC_LABELS and len(value) < 4:
        return False
    if DEVICE_PATH_RE.match(value):
        return False
    if value.startswith("@"):
        return False
    if sum(char.isalnum() for char in value) < 2:
        return False
    return True


def _best_utf16_name(data: bytes) -> tuple[str | None, str | None]:
    candidates = []
    for offset, text in utf16_strings(data):
        if not _meaningful(text):
            continue
        # Prefer earlier strings: the item name precedes property stores.
        score = -offset
        if text.lower() in GENERIC_LABELS:
            score -= 1000
        candidates.append((score, text))
    if not candidates:
        return None, None
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return candidates[0][1], "utf16"


def _embedded_timestamps(data: bytes) -> list[str]:
    """Collect plausible FILETIMEs that follow a 0xBEEF extension signature."""
    stamps: list[str] = []
    for signature in (b"\x04\x00\xef\xbe", b"\x11\x00\xef\xbe", b"\x0b\x00\xef\xbe"):
        start = 0
        while True:
            index = data.find(signature, start)
            if index < 0:
                break
            start = index + 4
            for offset in range(index + 4, min(index + 4 + 40, len(data) - 7), 8):
                value = struct.unpack_from("<Q", data, offset)[0]
                stamp = _plausible(value)
                if stamp and stamp not in stamps:
                    stamps.append(stamp)
            if len(stamps) >= 4:
                return stamps[:4]
    return stamps[:4]


def _device_from(data: bytes, strings: list[str]) -> tuple[bool, str | None, str | None]:
    """Detect a device item and its kind from a shell item."""
    joined = " ".join(strings)
    lowered = joined.lower()
    device_path = None
    for text in strings:
        if DEVICE_PATH_RE.match(text) or USB_PATH_RE.search(text):
            device_path = text
            break
    if device_path is None:
        raw_lower = data.lower()
        if DEVICE_PORTABLE_GUID.encode() in raw_lower or b"usb#vid_" in raw_lower:
            device_path = ""
        else:
            return False, None, None
    lowered_path = (device_path or "").lower()
    # An MTP/WPD device enumerates over USB, so check the portable-device
    # interface identifier before the generic USB transport.
    if DEVICE_PORTABLE_GUID in lowered_path:
        return True, "mtp", device_path
    if USB_PATH_RE.search(device_path or "") or "usb#" in lowered_path:
        return True, "usb", device_path
    if "swd#" in (device_path or "").lower():
        return True, "portable", device_path
    return True, "portable", device_path


def parse_shell_item(data: bytes) -> ParsedItem | None:
    """Parse the first shell item in ``data``.

    Returns None when the buffer is not a shell item (too short or size 0).
    """
    if len(data) < 4:
        return None
    size = struct.unpack_from("<H", data, 0)[0]
    if size < 4 or size > len(data):
        # Tolerate a short final item but not a bogus one.
        size = len(data)
    item = data[:size]
    item_type = item[2]
    warnings: list[str] = []
    strings = [text for _offset, text in utf16_strings(item)]
    name: str | None = None
    name_source: str | None = None
    is_dir = False
    drive = None
    volume_label = None
    guid = None
    size_bytes = None
    stamps = _embedded_timestamps(item)
    is_device, device_kind, device_path = _device_from(item, strings)

    if item_type in (0x31, 0x32, 0x30):
        if len(item) >= 0x0E:
            attrs = struct.unpack_from("<H", item, 0x0C)[0]
            is_dir = item_type == 0x31 or bool(attrs & 0x10)
            modified = struct.unpack_from("<I", item, 0x08)[0]
            stamp = dos_datetime(modified)
            if stamp and stamp not in stamps:
                stamps.insert(0, stamp)
            short = _ansi(item[0x0E:])
            if short:
                name = short
                name_source = "ansi"
        if len(item) >= 0x0A:
            size_bytes = struct.unpack_from("<I", item, 0x04)[0] or None
        # The ANSI field at 0x0E is the canonical folder name. Only fall back
        # to an embedded UTF-16 string when it is missing or an 8.3 alias;
        # otherwise an odd-aligned scan can prepend a stray byte.
        if not name or "~" in name:
            long_name, source = _best_utf16_name(item)
            if long_name and (not name or "~" in name):
                name, name_source = long_name, source

    elif item_type == 0x2F:
        if len(item) >= 0x06:
            head = item[0x03:0x06]
            if len(head) == 3 and chr(head[0]).isalpha() and head[1:2] == b":":
                drive = chr(head[0]) + ":"
        if len(item) > 0x10:
            volume_label = _ansi(item[0x10:]) or None
        name = volume_label or (drive + "\\" if drive else None)
        name_source = "volume"
        is_dir = True

    elif item_type == 0x1F:
        is_dir = True
        sort_index = item[3] if len(item) > 3 else 0
        if sort_index == 0x50 and len(item) >= 0x14:
            # Named root folder: a real GUID follows the header.
            try:
                raw_guid = uuid.UUID(bytes_le=item[0x04:0x14])
            except ValueError:
                raw_guid = None
            if raw_guid is not None:
                guid = str(raw_guid)
                name = ROOT_GUIDS.get(guid.lower())
                name_source = "guid" if name else None
        # sort_index 0x00 items are property-store wrappers with no readable
        # folder name; their embedded strings are property names (e.g.
        # "AutoList"), so they must not be used as the node name.
        if name:
            is_device = False

    elif item_type == 0x2E:
        is_dir = True
        if len(item) >= 0x14:
            try:
                raw_guid = uuid.UUID(bytes_le=item[0x04:0x14])
                guid = str(raw_guid)
                name = KNOWN_FOLDER_GUIDS.get(guid.lower())
                name_source = "guid" if name else None
            except ValueError:
                pass
        if not name:
            name, name_source = _best_utf16_name(item)

    else:
        # 0x00 (portable/MTP storage), network, URI, control panel and any
        # unknown type: recover the name from embedded UTF-16 strings.
        name, name_source = _best_utf16_name(item)
        if name is None and is_device:
            # Device with only a path string: use a readable path fragment.
            for text in strings:
                if DEVICE_PATH_RE.match(text) and len(text) > 4:
                    name = text[:160]
                    name_source = "device_path"
                    break
        if item_type in (0x41, 0x42, 0x35, 0x39, 0x3A, 0x3D):
            is_dir = True
        if item_type == 0x00 and name:
            # Portable/MTP storage and folders appear as type 0x00 items and
            # behave as containers in the shell namespace.
            is_dir = True
        if item_type in TYPE_NAMES and TYPE_NAMES[item_type] in {
            "control_panel", "users_property_view"
        }:
            is_dir = True

    if item_type == 0x00 and name is None:
        warnings.append(
            "unnamed shell item (type 0x00); no readable name in the raw bytes"
        )
    if name and len(name) > 260:
        name = name[:260]
        warnings.append("name truncated to 260 characters")

    return ParsedItem(
        item_type=item_type,
        type_name=TYPE_NAMES.get(item_type, f"type_0x{item_type:02x}"),
        name=name,
        name_source=name_source,
        is_dir=is_dir,
        is_device=is_device,
        device_kind=device_kind,
        drive=drive,
        volume_label=volume_label,
        guid=guid,
        size_bytes=size_bytes,
        embedded_timestamps=stamps,
        device_path=device_path,
        warnings=warnings,
    )


def parse_mru_list(raw: bytes) -> list[int]:
    """Decode an ``MRUListEx`` value: little-endian u32 indexes, 0xFFFFFFFF end."""
    out: list[int] = []
    for offset in range(0, len(raw) - 3, 4):
        value = struct.unpack_from("<I", raw, offset)[0]
        if value == 0xFFFFFFFF:
            break
        out.append(value)
    return out
