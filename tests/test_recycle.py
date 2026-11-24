"""Unit tests for Recycle Bin ``$I``/``$R`` metadata analysis."""
from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from dfir_browser.core.recycle import (
    classify,
    parse_info_file,
)

from preview_helpers import _row


def filetime(moment: datetime) -> int:
    return int(
        (moment - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()
        * 10_000_000
    )


def info_v2(original: str, *, deleted: datetime, size: int = 1234, null=True) -> bytes:
    name = original + ("\x00" if null else "")
    encoded = name.encode("utf-16-le")
    header = struct.pack(
        "<QQQI", 2, size, filetime(deleted), len(encoded) // 2
    )
    return header + encoded


def info_v1(original: str, *, deleted: datetime, size: int = 99) -> bytes:
    """Version 1: 24-byte header plus a fixed 520-character UTF-16LE path."""
    encoded = original.encode("utf-16-le").ljust(520 * 2, b"\x00")
    return struct.pack("<QQQ", 1, size, filetime(deleted)) + encoded


DECLARED = datetime(2021, 4, 29, 18, 22, 17, 598000, tzinfo=timezone.utc)


class FakeEntry:
    def __init__(self, path, *, entry_id=1):
        self.id = entry_id
        self.full_path = path
        self.basename = path.rsplit("/", 1)[-1]
        self.entry_type = "file"
        self.inode = None


# ----------------------------------------------------------------------
# path classification
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "path,kind",
    [
        ("partition/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IW9BJ2Z.txt", "info"),
        ("partition/$Recycle.Bin/S-1-5-21-1-2-3-1001/$RW9BJ2Z.txt", "content"),
        ("$Recycle.Bin/S-1-5-18/$IABC.docx", "info"),
        ("$Recycle.Bin/S-1-5-18/$RABC.docx", "content"),
    ],
)
def test_classify_info_and_content(path, kind):
    result = classify(FakeEntry(path))
    assert result is not None
    assert result["kind"] == kind


def test_classify_rejects_other_paths():
    assert classify(FakeEntry("Windows/System32/config/SYSTEM")) is None
    assert classify(FakeEntry("$Recycle.Bin")) is None
    assert classify(FakeEntry("Users/a/Recycle.Bin/x")) is None


def test_classify_extracts_sid_and_recycled_name():
    result = classify(
        FakeEntry("p/$Recycle.Bin/S-1-5-21-1-2-3-1001/$IW9BJ2Z.txt")
    )
    assert result["sid"] == "S-1-5-21-1-2-3-1001"
    assert result["recycled_name"] == "W9BJ2Z.txt"


def test_classify_flags_non_sid_directory():
    result = classify(FakeEntry("p/$Recycle.Bin/NotASid/$IABC.txt"))
    assert result["sid"] is None
    assert result["sid_raw"] == "NotASid"


# ----------------------------------------------------------------------
# $I parsing
# ----------------------------------------------------------------------
def test_parse_version2_record():
    data = info_v2(
        r"C:\Users\analyst\Downloads\tool.exe", deleted=DECLARED, size=57344
    )
    parsed = parse_info_file(data)
    assert parsed["version"] == 2
    assert parsed["original_path"] == r"C:\Users\analyst\Downloads\tool.exe"
    assert parsed["original_size"] == 57344
    assert parsed["deleted_time_utc"].startswith("2021-04-29T18:22:17.598")
    assert parsed["deleted_time_raw"] == str(filetime(DECLARED))
    assert parsed["warnings"] == []


def test_parse_version1_record():
    data = info_v1(r"C:\Temp\old.txt", deleted=DECLARED)
    parsed = parse_info_file(data)
    assert parsed["version"] == 1
    assert parsed["original_path"] == r"C:\Temp\old.txt"
    assert parsed["deleted_time_utc"].startswith("2021-04-29T18:22:17")


def test_trailing_nul_is_not_a_warning():
    """Version 2 stores a NUL, so length is visible+1. That is normal."""
    data = info_v2(r"C:\a\b.txt", deleted=DECLARED, null=True)
    parsed = parse_info_file(data)
    assert parsed["original_path"] == r"C:\a\b.txt"
    assert parsed["warnings"] == []


def test_short_record_is_reported_not_crashing():
    parsed = parse_info_file(b"\x02\x00\x00\x00")
    assert parsed["version"] is None
    assert parsed["deleted_time_utc"] is None
    assert any("shorter" in w for w in parsed["warnings"])


def test_version1_without_name_length_field():
    data = struct.pack("<QQQ", 1, 42, filetime(DECLARED)) + b"\x00" * 1040
    parsed = parse_info_file(data)
    assert parsed["version"] == 1
    assert parsed["original_size"] == 42
    assert parsed["deleted_time_utc"].startswith("2021-04-29T18:22:17")
    assert parsed["original_path"] is None


def test_truncated_header_keeps_version():
    data = struct.pack("<Q", 2) + b"\x00" * 12
    parsed = parse_info_file(data)
    assert parsed["version"] == 2
    assert parsed["deleted_time_utc"] is None
    assert any("required" in w for w in parsed["warnings"])


def test_unknown_version_is_rejected_cleanly():
    parsed = parse_info_file(struct.pack("<QQQQI", 7, 1, 1, 1, 4))
    assert parsed["version"] == 7
    assert parsed["deleted_time_utc"] is None
    assert any("unsupported" in w for w in parsed["warnings"])


def test_zero_filetime_gives_null_with_raw_value():
    data = struct.pack("<QQQI", 2, 10, 0, 0)
    parsed = parse_info_file(data)
    assert parsed["deleted_time_utc"] is None
    assert parsed["deleted_time_raw"] == "0"
    assert any("not a plausible FILETIME" in w for w in parsed["warnings"])


def test_out_of_range_filetime_is_null():
    data = struct.pack("<QQQI", 2, 10, 2**63, 0)
    parsed = parse_info_file(data)
    assert parsed["deleted_time_utc"] is None
    assert parsed["deleted_time_raw"] == str(2**63)


def test_declared_length_longer_than_payload_warns():
    header = struct.pack("<QQQI", 2, 5, filetime(DECLARED), 500)
    parsed = parse_info_file(header + b"a\x00b\x00")
    assert parsed["original_path"] == "ab"
    assert any("exceeds" in w for w in parsed["warnings"])


def test_byte_counted_length_is_tolerated():
    name = "abc.txt"
    encoded = name.encode("utf-16-le")
    # Some writers store the byte count.
    header = struct.pack("<QQQI", 2, 5, filetime(DECLARED), len(encoded))
    parsed = parse_info_file(header + encoded)
    assert parsed["original_path"] == name
    assert any("byte count" in w for w in parsed["warnings"])


def test_invalid_utf16_is_replaced_not_crashing():
    header = struct.pack("<QQQI", 2, 5, filetime(DECLARED), 2)
    parsed = parse_info_file(header + b"\x00\xd8A\x00")
    assert parsed["original_path"] is not None
    assert any("invalid UTF-16" in w for w in parsed["warnings"])


def test_unicode_original_path_roundtrip():
    name = r"C:\Users\Nguyễn Văn A\Tài liệu\báo cáo.txt"
    parsed = parse_info_file(info_v2(name, deleted=DECLARED))
    assert parsed["original_path"] == name


def test_empty_record_has_no_path():
    parsed = parse_info_file(struct.pack("<QQQI", 2, 0, filetime(DECLARED), 0))
    assert parsed["original_path"] is None
    assert any("no stored original path" in w for w in parsed["warnings"])
