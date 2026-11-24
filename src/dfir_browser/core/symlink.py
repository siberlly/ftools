"""Resolve a symbolic-link entry to its target inside the evidence index."""
from __future__ import annotations

from typing import Any


def resolve_target(
    record, entry, *, filesystem, index_store
) -> tuple[Any | None, str | None]:
    """Return (target_entry, note) for a symlink entry.

    The link text comes from ``istat`` (``symbolic link to:``). Relative targets
    are resolved against the link's directory, ``..`` is normalised, and the
    result must stay inside the evidence and be present in the index. Anything
    else returns ``(None, reason)`` so callers can explain instead of returning
    empty bytes.
    """
    try:
        image = filesystem._image_for(record)
        metadata = filesystem.stat(
            image,
            record.evidence_id,
            inode=entry.inode,
            offset_sectors=record.layout.offset_sectors,
        )
        target = (metadata.summary or {}).get("symlink_target")
    except Exception as exc:  # noqa: BLE001 - link text is best effort
        return None, f"symbolic link target could not be read: {exc}"
    if not target:
        return None, "entry is a symbolic link but its target is unknown"
    text = str(target).replace("\\", "/")
    if text.startswith("/"):
        relative = text.lstrip("/")
    else:
        parts = [part for part in (entry.parent_path or "").split("/") if part]
        for part in text.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    return None, (
                        f"symbolic link target {target!r} escapes the evidence root"
                    )
                parts.pop()
            else:
                parts.append(part)
        relative = "/".join(parts)
    relative = relative.strip("/")
    if not relative:
        return None, f"symbolic link target {target!r} is empty"
    row = index_store.get_index_row(record.evidence_id) or {}
    scan_id = row.get("scan_id")
    if not scan_id:
        return None, f"entry is a symbolic link to {target}"
    found = index_store.find_entries_by_exact_path(
        record.evidence_id, str(scan_id), relative
    )
    if not found:
        return None, (
            f"entry is a symbolic link to {target!r}, which is not in the "
            "filesystem index"
        )
    target_entry = found[0]
    if str(target_entry.fls_type or "").startswith("l"):
        return None, f"symbolic link chain is not followed (target {target!r})"
    return target_entry, (
        f"entry is a symbolic link to {target!r}; using the target "
        f"({target_entry.full_path})"
    )
