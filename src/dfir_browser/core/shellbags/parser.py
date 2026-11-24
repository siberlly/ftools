"""Walk BagMRU keys of a UsrClass.dat / NTUSER.DAT hive into a flat node list."""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .shellitems import ParsedItem, parse_mru_list, parse_shell_item

logger = logging.getLogger("dfir_browser.shellbags")

BAGMRU_SUFFIXES = (
    r"\shell\bagmru",
    r"\shellnoroam\bagmru",
)
SID_CLASSES_RE = re.compile(r"^(S-\d-(?:\d+-)+\d+)_Classes\\", re.IGNORECASE)


class ShellbagParseError(RuntimeError):
    pass


@dataclass(slots=True)
class ParsedBagNode:
    index: int
    parent_index: int | None
    depth: int
    name: str | None
    path: str
    item_type: int
    type_name: str
    name_source: str | None
    is_dir: bool
    is_device: bool
    device_kind: str | None
    drive: str | None
    volume_label: str | None
    guid: str | None
    device_path: str | None
    size_bytes: int | None
    key_last_write_utc: str | None
    registry_key_path: str
    registry_value_name: str
    embedded_timestamps: list[str] = field(default_factory=list)
    user_sid: str | None = None
    mru_rank: int | None = None
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_index": self.parent_index,
            "depth": self.depth,
            "name": self.name,
            "path": self.path,
            "item_type": self.item_type,
            "type_name": self.type_name,
            "name_source": self.name_source,
            "is_dir": self.is_dir,
            "is_device": self.is_device,
            "device_kind": self.device_kind,
            "drive": self.drive,
            "volume_label": self.volume_label,
            "guid": self.guid,
            "device_path": self.device_path,
            "size_bytes": self.size_bytes,
            "key_last_write_utc": self.key_last_write_utc,
            "embedded_timestamps": list(self.embedded_timestamps),
            "registry_key_path": self.registry_key_path,
            "registry_value_name": self.registry_value_name,
            "user_sid": self.user_sid,
            "mru_rank": self.mru_rank,
            "warnings": list(self.warnings),
        }


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return (
            moment.astimezone(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    return None


def user_sid_for(key_path: str) -> str | None:
    match = SID_CLASSES_RE.match(key_path)
    return match.group(1) if match else None


def find_bagmru_keys(root) -> Iterator[Any]:
    """Yield every BagMRU key in a hive (bounded by the caller's deadline)."""
    stack = [root]
    while stack:
        key = stack.pop()
        path = key.path().replace("/", "\\").lower()
        if path.endswith(BAGMRU_SUFFIXES[0]) or path.endswith(BAGMRU_SUFFIXES[1]):
            yield key
            # BagMRU subtrees are walked separately.
            continue
        try:
            subkeys = key.subkeys()
        except Exception:  # noqa: BLE001 - corrupt key layout
            continue
        stack.extend(subkeys)


def _sorted_indexes(values: dict[str, bytes]) -> tuple[list[int], dict[int, int]]:
    numeric = sorted(
        int(name)
        for name in values
        if name.isdigit() and len(name) < 6
    )
    order = numeric
    ranks: dict[int, int] = {}
    raw = values.get("MRUListEx")
    if raw:
        mru = [index for index in parse_mru_list(raw) if index in numeric]
        order = mru + [index for index in numeric if index not in mru]
        ranks = {index: position for position, index in enumerate(mru)}
    return order, ranks


def parse_hive(
    path: Path,
    *,
    deadline: float,
    max_nodes: int = 20000,
    user_hint: str | None = None,
) -> list[ParsedBagNode]:
    """Parse every BagMRU subtree of one hive into a flat, ordered node list."""
    try:
        from Registry import Registry as RegistryModule
    except Exception as exc:  # pragma: no cover - dependency guard
        raise ShellbagParseError(f"python-registry is unavailable: {exc}") from exc

    registry = RegistryModule.Registry(str(path))
    root = registry.root()
    nodes: list[ParsedBagNode] = []

    def walk(
        key,
        parent_index: int | None,
        depth: int,
        parent_path: str,
        sid: str | None,
    ) -> None:
        if len(nodes) >= max_nodes or time.monotonic() > deadline:
            return
        try:
            values = {v.name(): v for v in key.values()}
        except Exception as exc:  # noqa: BLE001 - corrupt values
            logger.warning("shellbags: cannot read values at %s: %s", key.path(), exc)
            return
        raw_values: dict[str, bytes] = {}
        for name, value in values.items():
            if not name.isdigit():
                continue
            try:
                payload = value.value()
            except Exception:  # noqa: BLE001
                continue
            if isinstance(payload, bytes):
                raw_values[name] = payload
        raw_values["MRUListEx"] = b""
        try:
            mru_raw = values["MRUListEx"].value() if "MRUListEx" in values else b""
            if isinstance(mru_raw, bytes):
                raw_values["MRUListEx"] = mru_raw
        except Exception:  # noqa: BLE001
            pass

        order, ranks = _sorted_indexes(raw_values)
        try:
            subkeys = {sk.name(): sk for sk in key.subkeys()}
        except Exception:  # noqa: BLE001
            subkeys = {}

        key_write = _iso(_safe_timestamp(key))
        for number in order:
            if len(nodes) >= max_nodes or time.monotonic() > deadline:
                return
            raw = raw_values.get(str(number))
            if not raw:
                continue
            item: ParsedItem | None
            try:
                item = parse_shell_item(raw)
            except Exception as exc:  # noqa: BLE001 - never break the whole job
                item = None
                logger.debug("shellbags: item %s unparsable: %s", number, exc)
            if item is None:
                continue
            name = item.name or f"[item {number}]"
            if not parent_path:
                path_text = name
            elif parent_path.endswith("\\") or parent_path.endswith(":"):
                path_text = f"{parent_path}{name}"
            else:
                path_text = f"{parent_path}\\{name}"
            index = len(nodes)
            warning_list = list(item.warnings)
            if item.name is None:
                warning_list.append(
                    "no name decoded; item shown by registry value index"
                )
            nodes.append(
                ParsedBagNode(
                    index=index,
                    parent_index=parent_index,
                    depth=depth,
                    name=item.name,
                    path=path_text,
                    item_type=item.item_type,
                    type_name=item.type_name,
                    name_source=item.name_source,
                    is_dir=item.is_dir or str(number) in subkeys,
                    is_device=item.is_device,
                    device_kind=item.device_kind,
                    drive=item.drive,
                    volume_label=item.volume_label,
                    guid=item.guid,
                    device_path=item.device_path,
                    size_bytes=item.size_bytes,
                    key_last_write_utc=key_write,
                    embedded_timestamps=list(item.embedded_timestamps),
                    registry_key_path=key.path(),
                    registry_value_name=str(number),
                    user_sid=sid or user_hint,
                    mru_rank=ranks.get(number),
                    warnings=warning_list,
                )
            )
            child = subkeys.get(str(number))
            if child is not None:
                walk(child, index, depth + 1, path_text, sid or user_hint)

    for bag in find_bagmru_keys(root):
        if time.monotonic() > deadline or len(nodes) >= max_nodes:
            break
        walk(bag, None, 0, "", user_sid_for(bag.path()) or user_hint)
    return nodes


def _safe_timestamp(key) -> Any:
    try:
        return key.timestamp()
    except Exception:  # noqa: BLE001
        return None
