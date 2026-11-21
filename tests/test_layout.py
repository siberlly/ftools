from __future__ import annotations

from pathlib import Path

import pytest

from dfir_browser.core.command import CommandResult
from dfir_browser.core.config import Settings
from dfir_browser.core.filesystem import (
    ExtractionError,
    FilesystemError,
    FilesystemService,
    detect_layout,
)
from dfir_browser.core.policy import PolicyError, SecurityPolicy

FSSTAT_NTFS = """FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: BAB00A24B009E7A9
Volume Name: Windows 10
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Sector Range: 0 - 28751870
"""

MMLS_PARTITION = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   00028751871   00028749824  NTFS / exFAT (0x07)
"""

MMLS_META_ONLY = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
"""

FLS_TEXT = (
    "d/d 1746-144-5:\tUsers"
    "\t2019-03-19 13:01:28 (UTC)\t2023-03-30 05:34:31 (UTC)"
    "\t2019-03-19 13:01:28 (UTC)\t2018-09-15 06:09:26 (UTC)\t56\t0\t0\n"
    "-/d * 125295-144-5:\tConfig.Msi"
    "\t2019-03-19 13:25:27 (UTC)\t2019-03-19 13:25:27 (UTC)"
    "\t2019-03-19 13:25:27 (UTC)\t2019-03-19 13:25:26 (UTC)\t48\t0\t0"
)

ISTAT_FILE = """MFT Entry Header Values:
Entry: 60734        Sequence: 2
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Read Only, Hidden, System, Archive
Created:\t2019-03-19 21:54:52.575672700 (UTC)
File Modified:\t2019-03-19 13:15:36.395700100 (UTC)
MFT Modified:\t2019-03-19 13:19:57.258797700 (UTC)
Accessed:\t2019-03-19 13:19:57.258797700 (UTC)

$FILE_NAME Attribute Values:
Flags: Archive
Name: bootmgr
Parent MFT Entry: 5 \tSequence: 5

Attributes: 
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 408364  init_size: 408364
"""

ISTAT_DIRECTORY = """MFT Entry Header Values:
Entry: 1746        Sequence: 1
Allocated Directory
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Read Only
Created:\t2018-09-15 06:09:26.473938300 (UTC)
File Modified:\t2019-03-19 13:01:28.696076300 (UTC)
MFT Modified:\t2019-03-19 13:01:28.696076300 (UTC)
Accessed:\t2023-03-30 05:34:31.067757400 (UTC)

$FILE_NAME Attribute Values:
Flags: Directory
Name: Users
Parent MFT Entry: 5 \tSequence: 5

Attributes: 
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
"""


def make_result(
    argv,
    stdout="",
    stderr="",
    exit_code=0,
    stdout_truncated=False,
    stdout_bytes_seen=None,
) -> CommandResult:
    return CommandResult(
        argv=list(argv),
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=1.0,
        stdout_truncated=stdout_truncated,
        stdout_bytes_seen=(
            stdout_bytes_seen
            if stdout_bytes_seen is not None
            else len(stdout.encode("utf-8"))
        ),
    )


class FakeRunner:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[list[str]] = []
        self.timeout = 60.0

    def run(self, argv, **kwargs) -> CommandResult:
        self.calls.append(list(argv))
        return self.handler(list(argv), kwargs)

    def version(self, binary: str) -> str:
        return "fake-tool 1.0"


def test_mmls_failure_falls_back_to_fsstat_at_sector_zero(tmp_path) -> None:
    image = tmp_path / "ewf1"
    image.write_bytes(b"x")

    def handler(argv, _kwargs):
        if argv[0] == "mmls":
            return make_result(
                argv, stderr="Cannot determine partition type", exit_code=1
            )
        if argv[0] == "fsstat":
            return make_result(argv, stdout=FSSTAT_NTFS)
        raise AssertionError(argv)

    runner = FakeRunner(handler)
    layout = detect_layout(runner, image)
    assert layout.scope == "volume"
    assert layout.filesystem == "NTFS"
    assert layout.offset_sectors == 0
    assert layout.method == "fsstat"
    assert any("mmls" in warning for warning in layout.warnings)
    assert runner.calls[1][:3] == ["fsstat", "-o", "0"]


def test_mmls_empty_output_falls_back(tmp_path) -> None:
    image = tmp_path / "ewf1"
    image.write_bytes(b"x")

    def handler(argv, _kwargs):
        if argv[0] == "mmls":
            return make_result(argv, stdout="", exit_code=0)
        return make_result(argv, stdout=FSSTAT_NTFS)

    layout = detect_layout(FakeRunner(handler), image)
    assert layout.scope == "volume"
    assert layout.method == "fsstat"
    assert any("empty output" in warning for warning in layout.warnings)


def test_mmls_partition_uses_detected_offset(tmp_path) -> None:
    image = tmp_path / "disk.img"
    image.write_bytes(b"x")

    def handler(argv, _kwargs):
        if argv[0] == "mmls":
            return make_result(argv, stdout=MMLS_PARTITION)
        if argv[0] == "fsstat":
            assert argv[1:3] == ["-o", "2048"]
            return make_result(argv, stdout=FSSTAT_NTFS)
        raise AssertionError(argv)

    layout = detect_layout(FakeRunner(handler), image)
    assert layout.scope == "partition"
    assert layout.filesystem == "NTFS"
    assert layout.offset_sectors == 2048
    assert layout.method == "mmls+fsstat"
    assert layout.details["partition_description"] == "NTFS / exFAT (0x07)"


def test_mmls_meta_only_falls_back(tmp_path) -> None:
    image = tmp_path / "disk.img"
    image.write_bytes(b"x")

    def handler(argv, _kwargs):
        if argv[0] == "mmls":
            return make_result(argv, stdout=MMLS_META_ONLY)
        return make_result(argv, stdout=FSSTAT_NTFS)

    layout = detect_layout(FakeRunner(handler), image)
    assert layout.scope == "volume"
    assert layout.offset_sectors == 0
    assert any("no data partitions" in warning for warning in layout.warnings)


def test_layout_failure_is_reported(tmp_path) -> None:
    image = tmp_path / "ewf1"
    image.write_bytes(b"x")

    def handler(argv, _kwargs):
        return make_result(argv, stderr="boom", exit_code=1)

    with pytest.raises(FilesystemError, match="fsstat"):
        detect_layout(FakeRunner(handler), image)


def make_service(tmp_path, handler):
    image = tmp_path / "ewf1"
    image.write_bytes(b"x")
    policy = SecurityPolicy([tmp_path], tmp_path / "var")
    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(tmp_path,),
        ewf_automount=False,
        command_timeout=5.0,
    )
    return FilesystemService(policy, FakeRunner(handler), settings), image


def test_filesystem_list_uses_inode_and_parses_entries(tmp_path) -> None:
    service, image = make_service(
        tmp_path, lambda argv, _kwargs: make_result(argv, stdout=FLS_TEXT)
    )
    listing = service.list_directory(image, "ev_0123456789ab", 5, 0)
    assert listing.inode == 5
    assert listing.complete is True
    assert listing.truncated is False
    assert listing.warning is None
    assert listing.cursor is None and listing.next_cursor is None
    assert listing.breadcrumb == [{"inode": 5, "name": "/"}]
    users = listing.entries[0]
    assert users.name == "Users"
    assert users.inode == 1746
    assert users.entry_type == "directory"
    deleted = listing.entries[1]
    assert deleted.deleted is True
    assert deleted.entry_type == "directory"
    assert service.runner.calls == [["fls", "-l", str(image), "5"]]


def test_filesystem_list_truncated_drops_partial_line(tmp_path) -> None:
    partial_line = (
        "r/r 999-128-1:\tPartial Entry Name"
        "\t2019-03-19 13:25:27 (UTC)\t2019-03-19 13:25:27 (UTC)"
        "\t2019-03-19 13:25:27 (UTC)\t2019-03-19 13:25:26 (UTC)"
        "\t1234\t0\t0"
    )
    stdout = FLS_TEXT + "\n" + partial_line

    def handler(argv, _kwargs):
        return make_result(
            argv,
            stdout=stdout,
            stdout_truncated=True,
            stdout_bytes_seen=999_999,
        )

    service, image = make_service(tmp_path, handler)
    listing = service.list_directory(image, "ev_0123456789ab", 5, 0)
    assert listing.complete is False
    assert listing.truncated is True
    assert listing.warning is not None
    assert "INCOMPLETE" in listing.warning
    assert "truncated at 999999 bytes" in listing.warning
    assert [entry.name for entry in listing.entries] == ["Users", "Config.Msi"]
    assert all(entry.name != "Partial Entry Name" for entry in listing.entries)
    assert any(
        "final partial line" in warning for warning in listing.warnings
    )
    payload = listing.to_dict()
    assert payload["complete"] is False
    assert payload["truncated"] is True
    assert payload["warning"] == listing.warning
    assert "cursor" in payload and "next_cursor" in payload
    assert payload["trust"] == "untrusted_evidence_data"


def test_filesystem_list_truncated_at_line_boundary(tmp_path) -> None:
    def handler(argv, _kwargs):
        return make_result(
            argv,
            stdout=FLS_TEXT + "\n",
            stdout_truncated=True,
            stdout_bytes_seen=5000,
        )

    service, image = make_service(tmp_path, handler)
    listing = service.list_directory(image, "ev_0123456789ab", 5, 0)
    assert listing.complete is False
    assert listing.truncated is True
    assert [entry.name for entry in listing.entries] == ["Users", "Config.Msi"]
    assert not any(
        "final partial line" in warning for warning in listing.warnings
    )


def test_stat_uses_offset_and_validates_inode(tmp_path) -> None:
    service, image = make_service(
        tmp_path, lambda argv, _kwargs: make_result(argv, stdout=ISTAT_FILE)
    )
    metadata = service.stat(image, "ev_0123456789ab", 60734, 2048)
    assert metadata.summary["name"] == "bootmgr"
    assert metadata.summary["data_size"] == 408364
    assert len(metadata.raw) <= service.settings.max_metadata_bytes
    assert service.runner.calls == [
        ["istat", "-o", "2048", str(image), "60734"]
    ]

    with pytest.raises(PolicyError):
        service.stat(image, "ev_0123456789ab", "5; rm -rf /", 0)
    assert len(service.runner.calls) == 1


def test_extract_rejects_directory_before_icat(tmp_path) -> None:
    service, image = make_service(
        tmp_path, lambda argv, _kwargs: make_result(argv, stdout=ISTAT_DIRECTORY)
    )
    with pytest.raises(ExtractionError, match="directory"):
        service.extract(image, "ev_0123456789ab", 1746, "case01", 0)
    assert all(call[0] == "istat" for call in service.runner.calls)


def test_extract_unknown_type_requires_explicit_assume_file(tmp_path) -> None:
    """Triage may opt in for deleted files; normal extraction still refuses.

    Deleted entries often have no determinable type from istat, so the triage
    service passes ``assume_file=True`` only after the index says the row is a
    file. The default path stays strict.
    """
    no_type = ISTAT_FILE.replace("Allocated File", "Unallocated Unknown")
    service, image = make_service(
        tmp_path, lambda argv, _kwargs: make_result(argv, stdout=no_type)
    )
    metadata = service.stat(image, "ev_0123456789ab", 900, 0)
    assert metadata.summary.get("is_directory") is None
    with pytest.raises(ExtractionError, match="could not be determined"):
        service.extract(image, "ev_0123456789ab", 900, "case01", 0)
