from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import DirEntry

FLS_RE = re.compile(
    r"^(?P<kind>[a-zA-Z-])/(?P<metakind>[a-zA-Z-])\s+"
    r"(?P<star>\*\s+)?"
    r"(?P<inode>\d+)-(?P<attr>\d+)-(?P<seq>\d+):\t"
    r"(?P<rest>.*)$"
)

INDEX_FLS_RE = re.compile(
    r"^(?P<kind>[a-zA-Z-])/(?P<metakind>[a-zA-Z-])\s+"
    r"(?P<star>\*\s+)?"
    r"(?P<inode>\d+)"
    r"(?:-(?P<attr>\d+)-(?P<seq>\d+))?"
    r"(?:\((?P<realloc>realloc)\))?:"
    r"\t(?P<rest>.*)$"
)

MMLS_RE = re.compile(
    r"^\s*(?P<slot>\d{1,4}):\s+(?P<part>\S+)\s+"
    r"(?P<start>\d+)\s+(?P<end>\d+)\s+"
    r"(?P<length>\d+)\s+(?P<desc>.*?)\s*$"
)

ATTR_RE = re.compile(
    r"^Type:\s*(?P<type>\S+)\s*\((?P<id>\d+)-(?P<instance>\d+)\)\s+"
    r"Name:\s*(?P<name>.*?)\s{2,}"
    r"(?P<storage>Resident|Non-Resident)\s+size:\s*(?P<size>\d+)",
    re.MULTILINE,
)

TSK_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?"
    r"\s*(?:\(UTC\))?$"
)

EWFINFO_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /_-]{1,40}?):\s*(.*)$")
HEX_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
HEX_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


@dataclass(slots=True)
class ParsedListing:
    entries: list[DirEntry] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)


class FlsLineError(ValueError):
    """Raised when one recursive fls line cannot be parsed."""


@dataclass(slots=True)
class ParsedIndexLine:
    full_path: str
    parent_path: str
    basename: str
    extension: str
    inode: int
    sequence: int | None
    attribute_id: int | None
    fls_type: str
    entry_type: str
    allocated: bool
    deleted: bool
    size: int | None
    mtime: str | None
    atime: str | None
    ctime: str | None
    crtime: str | None
    reallocated: bool


def normalize_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    match = TSK_TS_RE.match(value.strip())
    if not match:
        return None
    date, clock, fraction = match.groups()
    if date == "0000-00-00":
        return None
    suffix = f".{fraction}" if fraction else ""
    return f"{date}T{clock}{suffix}Z"


def parse_fls_index_line(line: str) -> ParsedIndexLine:
    """Parse one ``fls -r -p -l`` line, including ADS / inode-only rows."""
    match = INDEX_FLS_RE.match(line.rstrip("\r"))
    if not match:
        raise FlsLineError("line does not match fls -r -p -l format")

    fields = match.group("rest").split("\t")
    if len(fields) < 6:
        raise FlsLineError("line has fewer than 6 tab-separated fields")

    name = fields[0]
    if not name:
        raise FlsLineError("line has an empty name")

    if name.startswith("/"):
        name = name[1:]
    parent_path, separator, basename = name.rpartition("/")
    if not separator:
        parent_path = ""
        basename = name
    if not basename:
        raise FlsLineError("line has an empty basename")

    base_for_extension = basename.split(":", 1)[0]
    extension = (
        base_for_extension.rsplit(".", 1)[1].lower()
        if "." in base_for_extension
        else ""
    )

    size_raw = fields[5].strip()
    if size_raw and not re.fullmatch(r"-?\d+", size_raw):
        raise FlsLineError("line has an invalid size field")
    size = int(size_raw) if size_raw else None

    kind = match.group("kind")
    metakind = match.group("metakind")
    deleted = bool(match.group("star")) or kind == "-"
    kind_lower = kind.lower()
    metakind_lower = metakind.lower()
    entry_type = (
        "directory"
        if "d" in {kind_lower, metakind_lower}
        or "v" in {kind_lower, metakind_lower}
        else "file"
    )

    return ParsedIndexLine(
        full_path=name,
        parent_path=parent_path,
        basename=basename,
        extension=extension,
        inode=int(match.group("inode")),
        sequence=(
            int(match.group("seq")) if match.group("seq") is not None else None
        ),
        attribute_id=(
            int(match.group("attr")) if match.group("attr") is not None else None
        ),
        fls_type=f"{kind}/{metakind}",
        entry_type=entry_type,
        allocated=not deleted,
        deleted=deleted,
        size=size,
        mtime=normalize_timestamp(fields[1]),
        atime=normalize_timestamp(fields[2]),
        ctime=normalize_timestamp(fields[3]),
        crtime=normalize_timestamp(fields[4]),
        reallocated=bool(match.group("realloc")),
    )


def _optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or not re.fullmatch(r"-?\d+", stripped):
        return None
    return int(stripped)


def parse_fls(text: str) -> ParsedListing:
    """Parse ``fls -l`` output.

    Columns are tab-separated, which is what keeps names containing spaces
    intact. Deleted entries are marked either with a ``*`` or by a leading
    ``-`` type (observed as ``-/d * 125295-144-5:``).
    """
    listing = ParsedListing()
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if not line.strip():
            continue
        match = FLS_RE.match(line)
        if not match:
            listing.unparsed.append(line)
            continue

        fields = match.group("rest").split("\t")
        name = fields[0]
        mtime = atime = ctime = crtime = None
        size = None
        if len(fields) >= 6:
            mtime = normalize_timestamp(fields[1])
            atime = normalize_timestamp(fields[2])
            ctime = normalize_timestamp(fields[3])
            crtime = normalize_timestamp(fields[4])
            size = _optional_int(fields[5])
        elif len(fields) >= 2:
            # Unexpected but parseable: no timestamp/size columns.
            listing.unparsed.append(line)

        kind = match.group("kind").lower()
        metakind = match.group("metakind").lower()
        deleted = bool(match.group("star")) or kind == "-"
        entry_type = "directory" if "d" in {kind, metakind} else "file"

        listing.entries.append(
            DirEntry(
                name=name,
                inode=int(match.group("inode")),
                attribute_id=int(match.group("attr")),
                sequence=int(match.group("seq")),
                entry_type=entry_type,
                allocated=not deleted,
                deleted=deleted,
                size=size,
                mtime=mtime,
                atime=atime,
                ctime=ctime,
                crtime=crtime,
            )
        )
    return listing


def parse_ewfinfo(text: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = EWFINFO_KV_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip()
        fields.setdefault(key, value)

    sector_size = _optional_int(fields.get("Bytes per sector"))
    num_sectors = _optional_int(fields.get("Number of sectors"))

    media_size: int | None = None
    media_value = fields.get("Media size") or ""
    size_match = re.search(r"\((\d[\d,]*)\s+bytes\)", media_value)
    if not size_match:
        size_match = re.search(r"(\d[\d,]*)\s+bytes", media_value)
    if size_match:
        media_size = int(size_match.group(1).replace(",", ""))
    if media_size is None and sector_size and num_sectors:
        media_size = sector_size * num_sectors

    md5 = (fields.get("MD5") or "").strip().lower() or None
    sha1 = (fields.get("SHA1") or "").strip().lower() or None
    if md5 and not HEX_MD5_RE.fullmatch(md5):
        md5 = None
    if sha1 and not HEX_SHA1_RE.fullmatch(sha1):
        sha1 = None

    tool_version = next(
        (line.strip() for line in text.splitlines() if line.strip()), None
    )

    return {
        "format": fields.get("File format", "unknown") or "unknown",
        "media_size": media_size,
        "sector_size": sector_size,
        "num_sectors": num_sectors,
        "md5": md5,
        "sha1": sha1,
        "media_type": fields.get("Media type"),
        "acquisition_date": fields.get("Acquisition date"),
        "tool_version": tool_version,
        "fields": fields,
    }


def parse_fsstat(text: str) -> dict[str, Any]:
    def grab(pattern: str) -> str | None:
        match = re.search(pattern, text, re.MULTILINE)
        return match.group(1).strip() if match else None

    total_range = grab(r"^Total Sector Range:\s*(.+)$")
    total_sectors = None
    if total_range:
        range_match = re.search(r"(\d+)\s*-\s*(\d+)", total_range)
        if range_match:
            total_sectors = int(range_match.group(2)) - int(range_match.group(1)) + 1

    return {
        "filesystem": grab(r"^File System Type:\s*(.+)$"),
        "volume_serial": grab(r"^Volume Serial Number:\s*(.+)$"),
        "volume_name": grab(r"^Volume Name:\s*(.+)$"),
        "oem_name": grab(r"^OEM Name:\s*(.+)$"),
        "sector_size": _optional_int(grab(r"^Sector Size:\s*(\d+)$")),
        "cluster_size": _optional_int(grab(r"^Cluster Size:\s*(\d+)$")),
        "mft_entry_size": _optional_int(
            grab(r"^Size of MFT Entries:\s*(\d+)\s+bytes$")
        ),
        "root_inode": _optional_int(grab(r"^Root Directory:\s*(\d+)$")),
        "total_sectors": total_sectors,
    }


def parse_img_stat(text: str) -> dict[str, Any]:
    def grab(pattern: str) -> str | None:
        match = re.search(pattern, text, re.MULTILINE)
        return match.group(1).strip() if match else None

    return {
        "image_type": grab(r"^Image Type:\s*(.+)$"),
        "size_bytes": _optional_int(grab(r"^Size in bytes:\s*(\d+)$")),
        "sector_size": _optional_int(grab(r"^Sector size:\s*(\d+)$")),
    }


def parse_mmls(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "offset_sector": None,
        "unit_bytes": 512,
        "slots": [],
        "data_slots": [],
    }
    offset_match = re.search(r"^Offset Sector:\s*(\d+)$", text, re.MULTILINE)
    if offset_match:
        result["offset_sector"] = int(offset_match.group(1))
    units_match = re.search(r"Units are in (\d+)-byte sectors", text)
    if units_match:
        result["unit_bytes"] = int(units_match.group(1))

    for line in text.splitlines():
        match = MMLS_RE.match(line)
        if not match:
            continue
        description = match.group("desc").strip()
        part = match.group("part").strip()
        slot = {
            "slot": int(match.group("slot")),
            "start_sectors": int(match.group("start")),
            "end_sectors": int(match.group("end")),
            "length_sectors": int(match.group("length")),
            "description": description,
        }
        result["slots"].append(slot)
        lowered_part = part.lower()
        lowered_desc = description.lower()
        is_metadata = (
            lowered_part == "meta"
            or set(part) <= {"-"}
            or lowered_desc.startswith("unallocated")
            or lowered_desc.startswith("meta")
            or lowered_desc.startswith("extended")
        )
        if not is_metadata and slot["length_sectors"] > 0:
            result["data_slots"].append(slot)

    result["data_slots"].sort(key=lambda item: item["start_sectors"])
    return result


def _parse_istat_unix(text: str) -> dict[str, Any] | None:
    """Ext4/Unix istat layout: ``inode:``, ``mode:``, ``size:``."""
    match = re.search(r"^inode:\s*(\d+)", text, re.MULTILINE)
    if match is None:
        return None

    def first(pattern: str) -> str | None:
        found = re.search(pattern, text, re.MULTILINE)
        return found.group(1).strip() if found else None

    mode = first(r"^mode:\s*(\S+)")
    is_directory = None
    if mode:
        is_directory = mode.startswith("d")
    allocated = None
    if re.search(r"^Allocated$", text, re.MULTILINE):
        allocated = True
    elif re.search(r"^Not Allocated$", text, re.MULTILINE):
        allocated = False
    size_raw = first(r"^size:\s*(\d+)")
    link_target = first(r"^symbolic link to:\s*(.+)$")
    return {
        "inode": int(match.group(1)),
        "sequence": None,
        "allocated": allocated,
        "is_directory": is_directory,
        "name": None,
        "parent_inode": None,
        "security_id": None,
        "flags": first(r"^Flags:\s*(.+)$"),
        "mode": mode,
        "is_symlink": bool(mode and mode.startswith("l")),
        "symlink_target": link_target,
        "timestamps": {
            "created": normalize_timestamp(first(r"^File Created:\s*(.+)$")),
            "modified": normalize_timestamp(first(r"^File Modified:\s*(.+)$")),
            "mft_modified": normalize_timestamp(first(r"^Inode Modified:\s*(.+)$")),
            "accessed": normalize_timestamp(first(r"^Accessed:\s*(.+)$")),
        },
        "data_size": int(size_raw) if size_raw else None,
        "attributes": [],
    }


def parse_istat(text: str) -> dict[str, Any]:
    unix = _parse_istat_unix(text)
    if unix is not None:
        return unix
    head = re.split(r"^Attributes:\s*$", text, maxsplit=1, flags=re.MULTILINE)[0]

    entry_match = re.search(r"^Entry:\s*(\d+)\s+Sequence:\s*(\d+)", text, re.MULTILINE)
    inode = int(entry_match.group(1)) if entry_match else None
    sequence = int(entry_match.group(2)) if entry_match else None

    state_match = re.search(
        r"^(Allocated|Unallocated)\s+(File|Directory)\b", head, re.MULTILINE
    )
    allocated: bool | None = None
    is_directory: bool | None = None
    if state_match:
        allocated = state_match.group(1) == "Allocated"
        is_directory = state_match.group(2) == "Directory"

    def first(pattern: str) -> str | None:
        match = re.search(pattern, head, re.MULTILINE)
        return match.group(1).strip() if match else None

    name = first(r"^Name:\s*(.*)$")
    if name == "":
        name = None
    parent_raw = first(r"^Parent MFT Entry:\s*(\d+)")
    security_raw = first(r"^Security ID:\s*(\d+)")

    timestamps = {
        "created": normalize_timestamp(first(r"^Created:\s*(.+)$")),
        "modified": normalize_timestamp(first(r"^File Modified:\s*(.+)$")),
        "mft_modified": normalize_timestamp(first(r"^MFT Modified:\s*(.+)$")),
        "accessed": normalize_timestamp(first(r"^Accessed:\s*(.+)$")),
    }

    attributes: list[dict[str, Any]] = []
    for match in ATTR_RE.finditer(text):
        attributes.append(
            {
                "type": match.group("type"),
                "id": int(match.group("id")),
                "instance": int(match.group("instance")),
                "name": match.group("name").strip(),
                "storage": match.group("storage"),
                "size": int(match.group("size")),
            }
        )

    data_size: int | None = None
    for attribute in attributes:
        if attribute["type"] == "$DATA" and attribute["name"] in {"N/A", ""}:
            data_size = attribute["size"]
            break
    if data_size is None:
        data_sizes = [attr["size"] for attr in attributes if attr["type"] == "$DATA"]
        if data_sizes:
            data_size = max(data_sizes)

    return {
        "inode": inode,
        "sequence": sequence,
        "allocated": allocated,
        "is_directory": is_directory,
        "name": name,
        "parent_inode": int(parent_raw) if parent_raw else None,
        "security_id": int(security_raw) if security_raw else None,
        "flags": first(r"^Flags:\s*(.+)$"),
        "timestamps": timestamps,
        "data_size": data_size,
        "attributes": attributes,
    }
