from __future__ import annotations

from dfir_browser.core.parsers import (
    normalize_timestamp,
    parse_ewfinfo,
    parse_fls,
    parse_fsstat,
    parse_img_stat,
    parse_istat,
    parse_mmls,
)

TS = "2019-03-19 13:01:28 (UTC)"


def fls_line(kind: str, inode: str, name: str, size: str, star: str = "") -> str:
    first, second = kind.split("/")
    marker = f" * {inode}" if star else f" {inode}"
    return (
        f"{first}/{second}{marker}:"
        f"\t{name}\t{TS}\t{TS}\t{TS}\t{TS}\t{size}\t0\t0"
    )


def test_parse_fls_basic_and_spaces() -> None:
    text = "\n".join(
        [
            fls_line("d/d", "1746-144-5", "Users", "56"),
            fls_line("r/r", "60734-128-1", "My Report Final.docx", "408364"),
            fls_line("r/r", "9-144-16", "$Secure:$SDH", "56"),
        ]
    )
    parsed = parse_fls(text)
    assert parsed.unparsed == []
    assert [entry.name for entry in parsed.entries] == [
        "Users",
        "My Report Final.docx",
        "$Secure:$SDH",
    ]
    users = parsed.entries[0]
    assert users.inode == 1746
    assert users.attribute_id == 144
    assert users.sequence == 5
    assert users.entry_type == "directory"
    assert users.allocated is True
    assert users.deleted is False
    assert users.size == 56
    assert users.mtime == "2019-03-19T13:01:28Z"
    assert parsed.entries[1].name == "My Report Final.docx"
    assert parsed.entries[1].entry_type == "file"


def test_parse_fls_deleted_directory_and_file() -> None:
    deleted_dir = (
        " -/d * 125295-144-5:\tConfig.Msi"
        f"\t{TS}\t{TS}\t{TS}\t{TS}\t48\t0\t0"
    ).lstrip()
    deleted_file = (
        "r/r * 999-128-1:\told file.log"
        f"\t{TS}\t{TS}\t{TS}\t{TS}\t1234\t0\t0"
    )
    parsed = parse_fls(deleted_dir + "\n" + deleted_file)
    assert len(parsed.entries) == 2
    directory = parsed.entries[0]
    assert directory.name == "Config.Msi"
    assert directory.deleted is True
    assert directory.allocated is False
    assert directory.entry_type == "directory"
    file_entry = parsed.entries[1]
    assert file_entry.name == "old file.log"
    assert file_entry.deleted is True
    assert file_entry.entry_type == "file"


def test_parse_fls_keeps_unparsed_lines() -> None:
    parsed = parse_fls("this is not fls output\n" + fls_line("r/r", "7-128-1", "a", "1"))
    assert len(parsed.entries) == 1
    assert parsed.unparsed == ["this is not fls output"]


def test_normalize_timestamp_fractional() -> None:
    assert normalize_timestamp("2019-03-19 21:54:52.575672700 (UTC)") == (
        "2019-03-19T21:54:52.575672700Z"
    )
    assert normalize_timestamp("not a timestamp") is None
    assert normalize_timestamp(None) is None


EWFINFO_TEXT = """ewfinfo 20140814

Acquiry information
\tCase number:\t\t 
\tDescription:\t\tuntitled
\tAcquisition date:\tThu Mar 30 05:39:43 2023

EWF information
\tFile format:\t\tFTK Imager
\tSectors per chunk:\t64
\tCompression method:\tdeflate

Media information
\tMedia type:\t\tfixed disk
\tBytes per sector:\t512
\tNumber of sectors:\t28751872
\tMedia size:\t\t13 GiB (14720958464 bytes)

Digest hash information
\tMD5:\t\t\tcc5807fa709ac4517160841f9480bad8
\tSHA1:\t\t\t7a905de84e1dcf37d3cbb72a18ddfce01e0c5729
"""


def test_parse_ewfinfo() -> None:
    info = parse_ewfinfo(EWFINFO_TEXT)
    assert info["format"] == "FTK Imager"
    assert info["sector_size"] == 512
    assert info["num_sectors"] == 28751872
    assert info["media_size"] == 14720958464
    assert info["md5"] == "cc5807fa709ac4517160841f9480bad8"
    assert info["sha1"] == "7a905de84e1dcf37d3cbb72a18ddfce01e0c5729"
    assert info["tool_version"] == "ewfinfo 20140814"


FSSTAT_TEXT = """FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: BAB00A24B009E7A9
OEM Name: NTFS    
Volume Name: Windows 10
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
Size of MFT Entries: 1024 bytes
Root Directory: 5

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
Total Cluster Range: 0 - 3593982
Total Sector Range: 0 - 28751870
"""


def test_parse_fsstat() -> None:
    info = parse_fsstat(FSSTAT_TEXT)
    assert info["filesystem"] == "NTFS"
    assert info["sector_size"] == 512
    assert info["cluster_size"] == 4096
    assert info["mft_entry_size"] == 1024
    assert info["root_inode"] == 5
    assert info["volume_name"] == "Windows 10"
    assert info["total_sectors"] == 28751871


IMG_STAT_TEXT = """IMAGE FILE INFORMATION
--------------------------------------------
Image Type: raw

Size in bytes: 14720958464
Sector size:\t512
"""


def test_parse_img_stat() -> None:
    info = parse_img_stat(IMG_STAT_TEXT)
    assert info["image_type"] == "raw"
    assert info["size_bytes"] == 14720958464
    assert info["sector_size"] == 512


MMLS_TEXT = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   00028751871   00028749824  NTFS / exFAT (0x07)
"""


def test_parse_mmls_partition_table() -> None:
    parsed = parse_mmls(MMLS_TEXT)
    assert parsed["offset_sector"] == 0
    assert parsed["unit_bytes"] == 512
    assert len(parsed["slots"]) == 3
    assert len(parsed["data_slots"]) == 1
    partition = parsed["data_slots"][0]
    assert partition["start_sectors"] == 2048
    assert partition["description"] == "NTFS / exFAT (0x07)"


def test_parse_mmls_empty_or_error_output() -> None:
    parsed = parse_mmls("")
    assert parsed["slots"] == []
    assert parsed["data_slots"] == []


ISTAT_FILE = """MFT Entry Header Values:
Entry: 60734        Sequence: 2
$LogFile Sequence Number: 403967116
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Read Only, Hidden, System, Archive
Owner ID: 0
Security ID: 765  (S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)
Created:\t2019-03-19 21:54:52.575672700 (UTC)
File Modified:\t2019-03-19 13:15:36.395700100 (UTC)
MFT Modified:\t2019-03-19 13:19:57.258797700 (UTC)
Accessed:\t2019-03-19 13:19:57.258797700 (UTC)

$FILE_NAME Attribute Values:
Flags: Archive
Name: bootmgr
Parent MFT Entry: 5 \tSequence: 5
Allocated Size: 409600   \tActual Size: 0

Attributes: 
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 80
Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 408364  init_size: 408364
"""


def test_parse_istat_file() -> None:
    summary, = (parse_istat(ISTAT_FILE),)
    assert summary["inode"] == 60734
    assert summary["sequence"] == 2
    assert summary["allocated"] is True
    assert summary["is_directory"] is False
    assert summary["name"] == "bootmgr"
    assert summary["parent_inode"] == 5
    assert summary["security_id"] == 765
    assert summary["data_size"] == 408364
    assert summary["timestamps"]["created"] == (
        "2019-03-19T21:54:52.575672700Z"
    )
    assert len(summary["attributes"]) == 3


ISTAT_DIRECTORY = ISTAT_FILE.replace(
    "Entry: 60734        Sequence: 2", "Entry: 1746        Sequence: 1"
).replace("Allocated File", "Allocated Directory").replace(
    "Name: bootmgr", "Name: Users"
).replace("Type: $DATA (128-1)   Name: N/A   Non-Resident   size: 408364  init_size: 408364", "")


def test_parse_istat_directory() -> None:
    summary = parse_istat(ISTAT_DIRECTORY)
    assert summary["inode"] == 1746
    assert summary["is_directory"] is True
    assert summary["name"] == "Users"
    assert summary["data_size"] is None


def test_parse_istat_unallocated() -> None:
    summary = parse_istat(ISTAT_FILE.replace("Allocated File", "Unallocated File"))
    assert summary["allocated"] is False
    assert summary["is_directory"] is False


ISTAT_EXT4_FILE = """inode: 1048756
Allocated
Group: 128
Generation Id: 2592402173
uid / gid: 0 / 0
mode: rrw-r--r--
Flags: Extents, 
size: 99
num of links: 1

Inode Times:
Accessed:\t2022-02-09 03:37:46.058909758 (UTC)
File Modified:\t2021-10-11 08:39:49.000000000 (UTC)
Inode Modified:\t2021-12-26 10:48:56.494079919 (UTC)
File Created:\t2021-12-26 10:48:56.494079919 (UTC)

Direct Blocks:
4227142 
"""


def test_parse_istat_ext4_file() -> None:
    summary = parse_istat(ISTAT_EXT4_FILE)
    assert summary["inode"] == 1048756
    assert summary["sequence"] is None
    assert summary["allocated"] is True
    assert summary["is_directory"] is False
    assert summary["data_size"] == 99
    assert summary["timestamps"]["created"].startswith("2021-12-26T10:48:56")
    assert summary["timestamps"]["modified"].startswith("2021-10-11T08:39:49")
    assert summary["timestamps"]["mft_modified"].startswith("2021-12-26")
    assert summary["timestamps"]["accessed"].startswith("2022-02-09T03:37:46")
    assert summary["attributes"] == []


def test_parse_istat_ext4_directory() -> None:
    summary = parse_istat(
        ISTAT_EXT4_FILE.replace("mode: rrw-r--r--", "mode: drwxr-xr-x")
    )
    assert summary["is_directory"] is True
    assert summary["inode"] == 1048756


def test_parse_istat_ext4_unallocated() -> None:
    summary = parse_istat(ISTAT_EXT4_FILE.replace("Allocated", "Not Allocated", 1))
    assert summary["allocated"] is False


def test_parse_istat_ntfs_still_wins_when_header_present() -> None:
    summary = parse_istat(ISTAT_FILE)
    assert summary["sequence"] == 2
    assert summary["name"] == "bootmgr"


def test_parse_istat_ext4_symlink_target() -> None:
    summary = parse_istat(
        """inode: 1048772
Allocated
symbolic link to: ../usr/lib/os-release
mode: lrwxrwxrwx
size: 21
Direct Blocks:
0
"""
    )
    assert summary["is_symlink"] is True
    assert summary["symlink_target"] == "../usr/lib/os-release"
    assert summary["is_directory"] is False
