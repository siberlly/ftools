from __future__ import annotations

import pytest

from dfir_browser.core.parsers import (
    FlsLineError,
    normalize_timestamp,
    parse_fls_index_line,
)

TS = "2020-01-02 03:04:05 (UTC)"


def make_line(
    fls_type: str,
    inode: str,
    name: str,
    size: str = "1",
    *,
    star: bool = False,
    realloc: bool = False,
) -> str:
    marker = "* " if star else ""
    realloc_marker = "(realloc)" if realloc else ""
    return (
        f"{fls_type} {marker}{inode}{realloc_marker}:\t{name}"
        f"\t{TS}\t{TS}\t{TS}\t{TS}\t{size}\t0\t0"
    )


def test_allocated_file_full_path() -> None:
    entry = parse_fls_index_line(
        make_line("r/r", "60734-128-1", "Users/IEUser/Report Final.docx", "408364")
    )
    assert entry.full_path == "Users/IEUser/Report Final.docx"
    assert entry.parent_path == "Users/IEUser"
    assert entry.basename == "Report Final.docx"
    assert entry.extension == "docx"
    assert entry.inode == 60734
    assert entry.attribute_id == 128
    assert entry.sequence == 1
    assert entry.fls_type == "r/r"
    assert entry.entry_type == "file"
    assert entry.allocated is True
    assert entry.deleted is False
    assert entry.size == 408364
    assert entry.reallocated is False


def test_deleted_file_with_star() -> None:
    entry = parse_fls_index_line(
        make_line(
            "-/r",
            "124567-128-4",
            "Users/Public/Downloads/SysInternals.exe",
            "57344",
            star=True,
        )
    )
    assert entry.full_path == "Users/Public/Downloads/SysInternals.exe"
    assert entry.basename == "SysInternals.exe"
    assert entry.inode == 124567
    assert entry.entry_type == "file"
    assert entry.allocated is False
    assert entry.deleted is True


def test_deleted_directory() -> None:
    entry = parse_fls_index_line(
        make_line("-/d", "125295-144-5", "Config.Msi", "48", star=True)
    )
    assert entry.entry_type == "directory"
    assert entry.deleted is True
    assert entry.allocated is False


def test_unicode_and_space_filename() -> None:
    entry = parse_fls_index_line(
        make_line("r/r", "42-128-1", "Users/IEUser/Báo cáo cuối kỳ.txt", "10")
    )
    assert entry.basename == "Báo cáo cuối kỳ.txt"
    assert entry.extension == "txt"
    assert "Báo cáo" in entry.full_path


def test_ads_name_is_preserved() -> None:
    entry = parse_fls_index_line(
        make_line(
            "r/r",
            "88605-128-8",
            "ProgramData/Windows/ConfigSecurityPolicy.exe:WofCompressedData",
            "156409",
        )
    )
    assert entry.full_path.endswith(
        "ConfigSecurityPolicy.exe:WofCompressedData"
    )
    assert entry.basename.endswith(":WofCompressedData")
    assert entry.extension == "exe"


def test_inode_only_deleted_entry() -> None:
    entry = parse_fls_index_line(
        make_line(
            "r/-",
            "0",
            "ProgramData/chocolatey/helpers/functions/Get-PackageParameters.ps1",
            "0",
            star=True,
        )
    )
    assert entry.inode == 0
    assert entry.attribute_id is None
    assert entry.sequence is None
    assert entry.deleted is True
    assert entry.entry_type == "file"


def test_virtual_orphan_directory() -> None:
    entry = parse_fls_index_line(
        make_line("V/V", "126976", "$OrphanFiles", "0")
    )
    assert entry.entry_type == "directory"
    assert entry.inode == 126976
    assert entry.attribute_id is None


def test_realloc_deleted_entry() -> None:
    entry = parse_fls_index_line(
        make_line(
            "r/r",
            "86396-128-4",
            "ProgramData/USOShared/Logs/UpdateSessionOrchestration.002.etl",
            "16384",
            star=True,
            realloc=True,
        )
    )
    assert entry.reallocated is True
    assert entry.deleted is True
    assert entry.inode == 86396


def test_zero_timestamps_become_none() -> None:
    zero = "0000-00-00 00:00:00 (UTC)"
    line = (
        "r/- * 0:\tProgramData/foo.ps1"
        f"\t{zero}\t{zero}\t{zero}\t{zero}\t0\t0\t0"
    )
    entry = parse_fls_index_line(line)
    assert entry.mtime is None
    assert entry.atime is None
    assert entry.ctime is None
    assert entry.crtime is None
    assert normalize_timestamp(zero) is None


def test_partial_line_is_rejected() -> None:
    with pytest.raises(FlsLineError, match="fewer than 6"):
        parse_fls_index_line(
            "r/r 123-128-1:\tPartial Name\t2020-01-02 03:04:05 (UTC)"
        )


def test_malformed_line_is_rejected() -> None:
    with pytest.raises(FlsLineError):
        parse_fls_index_line("this is not fls output")


def test_invalid_size_is_rejected() -> None:
    with pytest.raises(FlsLineError, match="invalid size"):
        parse_fls_index_line(
            make_line("r/r", "1-128-1", "Users/a.txt", "not-a-number")
        )
