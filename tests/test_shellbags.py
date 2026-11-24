from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

import pytest

from dfir_browser.core.shellbags.shellitems import (
    dos_datetime,
    parse_mru_list,
    parse_shell_item,
    utf16_strings,
)


def utf16(text: str, null: bool = True) -> bytes:
    data = text.encode("utf-16-le")
    return data + (b"\x00\x00" if null else b"")


def dir_item(name: str, *, attrs: int = 0x10, modified: int = 0) -> bytes:
    """A 0x31 directory item: ANSI name at 0x0E."""
    short = name.encode("cp1252")[:12]
    body = bytearray(0x0E + len(short) + 1)
    struct.pack_into("<H", body, 0, len(body))
    body[2] = 0x31
    body[3] = 0x00
    struct.pack_into("<I", body, 8, modified)
    struct.pack_into("<H", body, 0x0C, attrs)
    body[0x0E:0x0E + len(short)] = short
    return bytes(body)


def file_item(name: str) -> bytes:
    item = bytearray(dir_item(name, attrs=0x20))
    item[2] = 0x32
    return bytes(item)


def volume_item(drive: str, label: str | None = None) -> bytes:
    body = bytearray(0x20)
    struct.pack_into("<H", body, 0, len(body))
    body[2] = 0x2F
    body[3] = ord(drive)
    body[4] = ord(":")
    body[5] = ord("\\")
    if label:
        raw = label.encode("cp1252") + b"\x00"
        body[0x10:0x10 + len(raw)] = raw
        struct.pack_into("<H", body, 0, 0x10 + len(raw))
    return bytes(body[: struct.unpack_from("<H", body, 0)[0]])


def root_item(guid: str = "20d04fe0-3aea-1069-a2d8-08002b30309d") -> bytes:
    body = bytearray(0x14)
    struct.pack_into("<H", body, 0, len(body))
    body[2] = 0x1F
    body[3] = 0x50
    body[4:0x14] = uuid.UUID(guid).bytes_le
    return bytes(body)


def device_item(name: str, path: str) -> bytes:
    """A 0x2E device item with a UTF-16 name and device path."""
    body = bytearray(0x28)
    body[2] = 0x2E
    body[3] = 0x00
    body += utf16(name) + utf16(path)
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


def mtp_storage_item(name: str, identifier: str) -> bytes:
    """A 0x00 portable-storage item (the '<UNKNOWN: 0x00>' case)."""
    body = bytearray(0x08)
    body[2] = 0x00
    body += utf16(name) + utf16(identifier) + utf16("Generic hierarchical")
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


# ----------------------------------------------------------------------
# shell item parsing
# ----------------------------------------------------------------------
def test_parse_directory_item():
    item = parse_shell_item(dir_item("Windows"))
    assert item is not None
    assert item.item_type == 0x31
    assert item.type_name == "directory"
    assert item.name == "Windows"
    assert item.name_source == "ansi"
    assert item.is_dir is True


def test_parse_file_item():
    item = parse_shell_item(file_item("SDelete.zip"))
    assert item.item_type == 0x32
    assert item.name == "SDelete.zip"
    assert item.is_dir is False


def test_parse_volume_item_with_and_without_label():
    plain = parse_shell_item(volume_item("D"))
    assert plain.drive == "D:"
    assert plain.name == "D:\\"
    labelled = parse_shell_item(volume_item("E", "BACKUP"))
    assert labelled.drive == "E:"
    assert labelled.volume_label == "BACKUP"
    assert labelled.name == "BACKUP"


def test_parse_root_item_guid_name():
    item = parse_shell_item(root_item())
    assert item.item_type == 0x1F
    assert item.name == "My Computer"
    assert item.name_source == "guid"


def test_parse_root_item_without_sort_guid_is_unnamed():
    raw = bytearray(root_item())
    raw[3] = 0x00
    # Adds a property-store style string that must not become the name.
    raw += utf16("AutoList")
    struct.pack_into("<H", raw, 0, len(raw))
    item = parse_shell_item(bytes(raw))
    assert item.name is None
    assert item.item_type == 0x1F


def test_parse_known_folder_guid():
    body = bytearray(0x14)
    struct.pack_into("<H", body, 0, len(body))
    body[2] = 0x2E
    body[4:0x14] = uuid.UUID("088e3905-0323-4b02-9826-5d99428e115f").bytes_le
    item = parse_shell_item(bytes(body))
    assert item.name == "Downloads"
    assert item.name_source == "guid"


def test_parse_mtp_device_decodes_name_and_kind():
    path = (
        "\\\\?\\usb#vid_1004&pid_633e#lmq725k2c1b72a#"
        "{6ac27878-a6fa-4155-ba85-f98f491d4f33}"
    )
    item = parse_shell_item(device_item("LG Q7", path))
    assert item.name == "LG Q7"
    assert item.is_device is True
    assert item.device_kind == "mtp"
    assert "6ac27878" in (item.device_path or "")


def test_parse_usb_device_without_mtp_guid():
    item = parse_shell_item(
        device_item("SanDisk", "\\\\?\\usb#vid_0781&pid_5567#abc#{}")
    )
    assert item.is_device is True
    assert item.device_kind == "usb"


def test_parse_unknown_zero_type_recovers_name():
    """The 0x00 portable-storage case that regipy reports as <UNKNOWN: 0x00>."""
    item = parse_shell_item(
        mtp_storage_item("Internal storage", "SID-{10001,,22687535104}")
    )
    assert item.item_type == 0x00
    assert item.name == "Internal storage"
    assert item.name_source == "utf16"


def test_parse_zero_type_folder_name():
    for name in ("DCIM", "Camera", "Download"):
        item = parse_shell_item(
            mtp_storage_item(name, "{608B0C22-3382-2412-0000-000000000000}")
        )
        assert item.name == name


def test_unknown_item_without_text_is_flagged():
    raw = bytes([0x08, 0x00, 0x00, 0x00, 0, 0, 0, 0])
    item = parse_shell_item(raw)
    assert item.name is None
    assert any("unnamed shell item" in w for w in item.warnings)


def test_garbage_and_short_buffers_do_not_raise():
    assert parse_shell_item(b"") is None
    assert parse_shell_item(b"\x01") is None
    item = parse_shell_item(b"\xff\xff\x31\x00junk")
    assert item is not None


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def test_mru_list_parsing():
    raw = struct.pack("<IIII", 2, 0, 1, 0xFFFFFFFF)
    assert parse_mru_list(raw) == [2, 0, 1]
    assert parse_mru_list(b"") == []
    assert parse_mru_list(b"\x00\x00") == []


def test_dos_datetime():
    # 2021-04-29 18:22:18 encoded as packed DOS date/time.
    date = ((2021 - 1980) << 9) | (4 << 5) | 29
    time = (18 << 11) | (22 << 5) | 9
    assert dos_datetime((date << 16) | time) == "2021-04-29T18:22:18Z"
    assert dos_datetime(0) is None
    assert dos_datetime(0xFFFFFFFF) is None


def test_utf16_strings_finds_runs():
    data = b"\x00" + "hello".encode("utf-16-le") + b"\x00\x00"
    texts = [text for _offset, text in utf16_strings(data)]
    assert "hello" in texts


def test_shellitem_result_is_json_friendly():
    item = parse_shell_item(dir_item("Temp"))
    payload = item.to_dict()
    assert payload["name"] == "Temp"
    assert isinstance(payload["embedded_timestamps"], list)
