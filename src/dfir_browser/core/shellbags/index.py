"""SQLite storage for ShellBags nodes, devices and index state."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import (
    SHELLBAG_SCHEMA_VERSION,
    ShellbagDeviceRecord,
    ShellbagHiveRecord,
    ShellbagNodeRecord,
    ShellbagNotFound,
)

DDL = """
CREATE TABLE IF NOT EXISTS shellbag_meta (
  evidence_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  hives INTEGER NOT NULL DEFAULT 0,
  nodes INTEGER NOT NULL DEFAULT 0,
  devices INTEGER NOT NULL DEFAULT 0,
  errors_json TEXT,
  warnings_json TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS shellbag_hives (
  hive_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  hive_type TEXT NOT NULL,
  user_sid TEXT,
  state TEXT NOT NULL,
  error TEXT,
  node_count INTEGER NOT NULL DEFAULT 0,
  device_count INTEGER NOT NULL DEFAULT 0,
  extract_relpath TEXT,
  updated_at TEXT,
  warnings_json TEXT
);
CREATE TABLE IF NOT EXISTS shellbag_devices (
  device_id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  node_id INTEGER,
  name TEXT,
  kind TEXT NOT NULL,
  detail TEXT,
  drive TEXT,
  volume_label TEXT,
  user_sid TEXT,
  first_seen_utc TEXT,
  node_count INTEGER NOT NULL DEFAULT 0,
  warnings_json TEXT
);
CREATE TABLE IF NOT EXISTS shellbag_nodes (
  node_id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  hive_id TEXT NOT NULL,
  parent_id INTEGER,
  depth INTEGER NOT NULL,
  name TEXT,
  path TEXT,
  item_type INTEGER NOT NULL,
  type_name TEXT NOT NULL,
  name_source TEXT,
  is_dir INTEGER NOT NULL DEFAULT 0,
  is_device INTEGER NOT NULL DEFAULT 0,
  device_id INTEGER,
  drive TEXT,
  volume_label TEXT,
  guid TEXT,
  device_path TEXT,
  size_bytes INTEGER,
  key_last_write_utc TEXT,
  embedded_timestamps_json TEXT,
  registry_key_path TEXT,
  registry_value_name TEXT,
  registry_key_id INTEGER,
  user_sid TEXT,
  mru_rank INTEGER,
  warnings_json TEXT
);
CREATE INDEX IF NOT EXISTS shellbag_nodes_evidence ON shellbag_nodes(evidence_id, depth);
CREATE INDEX IF NOT EXISTS shellbag_nodes_parent ON shellbag_nodes(evidence_id, hive_id, parent_id);
CREATE INDEX IF NOT EXISTS shellbag_nodes_path ON shellbag_nodes(path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS shellbag_nodes_time ON shellbag_nodes(evidence_id, key_last_write_utc);
CREATE INDEX IF NOT EXISTS shellbag_devices_evidence ON shellbag_devices(evidence_id, kind);
"""

NODE_COLUMNS = (
    "node_id, evidence_id, hive_id, parent_id, depth, name, path, item_type, "
    "type_name, name_source, is_dir, is_device, device_id, drive, "
    "volume_label, guid, device_path, size_bytes, key_last_write_utc, "
    "embedded_timestamps_json, registry_key_path, registry_value_name, "
    "registry_key_id, user_sid, mru_rank, warnings_json"
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ShellbagStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(str(self.path), timeout=15.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return connection

    def ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(DDL)
            connection.execute(f"PRAGMA user_version = {SHELLBAG_SCHEMA_VERSION}")

    def recover_interrupted(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE shellbag_meta SET state='interrupted', updated_at=? "
                "WHERE state IN ('queued','running')",
                (_now(),),
            )
            return int(cursor.rowcount or 0)

    def mark_running(self, evidence_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO shellbag_meta (evidence_id, state, progress, updated_at) "
                "VALUES (?, 'running', 0, ?) "
                "ON CONFLICT(evidence_id) DO UPDATE SET state='running', "
                "progress=0, errors_json='[]', updated_at=excluded.updated_at",
                (evidence_id, _now()),
            )

    def set_progress(self, evidence_id: str, progress: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE shellbag_meta SET progress=?, updated_at=? WHERE evidence_id=?",
                (max(0, min(100, int(progress))), _now(), evidence_id),
            )

    def clear(self, evidence_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM shellbag_nodes WHERE evidence_id=?", (evidence_id,)
            )
            connection.execute(
                "DELETE FROM shellbag_devices WHERE evidence_id=?", (evidence_id,)
            )
            connection.execute(
                "DELETE FROM shellbag_hives WHERE evidence_id=?", (evidence_id,)
            )

    def finish(
        self,
        evidence_id: str,
        *,
        state: str,
        hives: int,
        nodes: int,
        devices: int,
        errors: Iterable[str] = (),
        warnings: Iterable[str] = (),
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO shellbag_meta (evidence_id, state, progress, hives, "
                "nodes, devices, errors_json, warnings_json, updated_at) "
                "VALUES (?, ?, 100, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(evidence_id) DO UPDATE SET state=excluded.state, "
                "progress=100, hives=excluded.hives, nodes=excluded.nodes, "
                "devices=excluded.devices, errors_json=excluded.errors_json, "
                "warnings_json=excluded.warnings_json, "
                "updated_at=excluded.updated_at",
                (
                    evidence_id,
                    state,
                    hives,
                    nodes,
                    devices,
                    _json(list(errors)),
                    _json(list(warnings)),
                    _now(),
                ),
            )

    def state(self, evidence_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM shellbag_meta WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "evidence_id": row["evidence_id"],
            "state": row["state"],
            "progress": int(row["progress"] or 0),
            "hives": int(row["hives"] or 0),
            "nodes": int(row["nodes"] or 0),
            "devices": int(row["devices"] or 0),
            "errors": _loads(row["errors_json"], []),
            "warnings": _loads(row["warnings_json"], []),
            "updated_at": row["updated_at"],
        }

    # ------------------------------------------------------------------
    def upsert_hive(self, hive: ShellbagHiveRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO shellbag_hives (hive_id, evidence_id, "
                "entry_id, path, name, hive_type, user_sid, state, error, "
                "node_count, device_count, extract_relpath, updated_at, "
                "warnings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hive.hive_id,
                    hive.evidence_id,
                    hive.entry_id,
                    hive.path,
                    hive.name,
                    hive.hive_type,
                    hive.user_sid,
                    hive.state,
                    hive.error,
                    hive.node_count,
                    hive.device_count,
                    hive.extract_relpath,
                    hive.updated_at or _now(),
                    _json(hive.warnings),
                ),
            )

    def list_hives(self, evidence_id: str) -> list[ShellbagHiveRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM shellbag_hives WHERE evidence_id=? "
                "ORDER BY user_sid COLLATE NOCASE, name COLLATE NOCASE",
                (evidence_id,),
            ).fetchall()
        return [
            ShellbagHiveRecord(
                hive_id=row["hive_id"],
                evidence_id=row["evidence_id"],
                entry_id=int(row["entry_id"]),
                path=row["path"],
                name=row["name"],
                hive_type=row["hive_type"],
                user_sid=row["user_sid"],
                state=row["state"],
                error=row["error"],
                node_count=int(row["node_count"] or 0),
                device_count=int(row["device_count"] or 0),
                extract_relpath=row["extract_relpath"],
                updated_at=row["updated_at"],
                warnings=_loads(row["warnings_json"], []),
            )
            for row in rows
        ]

    # ------------------------------------------------------------------
    def insert_nodes(
        self, rows: list[tuple[int, Any]]
    ) -> dict[int, int]:
        """Insert nodes; returns a map of parser index -> database node_id."""
        mapping: dict[int, int] = {}
        if not rows:
            return mapping
        with self._connect() as connection:
            for parser_index, node in rows:
                cursor = connection.execute(
                    "INSERT INTO shellbag_nodes (evidence_id, hive_id, parent_id, "
                    "depth, name, path, item_type, type_name, name_source, "
                    "is_dir, is_device, device_id, drive, volume_label, guid, "
                    "device_path, size_bytes, key_last_write_utc, "
                    "embedded_timestamps_json, registry_key_path, "
                    "registry_value_name, registry_key_id, user_sid, mru_rank, "
                    "warnings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        node.evidence_id,
                        node.hive_id,
                        None,
                        node.depth,
                        node.name,
                        node.path,
                        node.item_type,
                        node.type_name,
                        node.name_source,
                        1 if node.is_dir else 0,
                        1 if node.is_device else 0,
                        None,
                        node.drive,
                        node.volume_label,
                        node.guid,
                        node.device_path,
                        node.size_bytes,
                        node.key_last_write_utc,
                        _json(node.embedded_timestamps),
                        node.registry_key_path,
                        node.registry_value_name,
                        node.registry_key_id,
                        node.user_sid,
                        node.mru_rank,
                        _json(node.warnings),
                    ),
                )
                mapping[parser_index] = int(cursor.lastrowid)
        return mapping

    def set_parent(self, node_id: int, parent_id: int | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE shellbag_nodes SET parent_id=? WHERE node_id=?",
                (parent_id, node_id),
            )

    def insert_device(self, device: ShellbagDeviceRecord) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO shellbag_devices (evidence_id, node_id, name, kind, "
                "detail, drive, volume_label, user_sid, first_seen_utc, "
                "node_count, warnings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    device.evidence_id,
                    device.node_id,
                    device.name,
                    device.kind,
                    device.detail,
                    device.drive,
                    device.volume_label,
                    device.user_sid,
                    device.first_seen_utc,
                    device.node_count,
                    _json(device.warnings),
                ),
            )
            return int(cursor.lastrowid)

    def set_node_device(self, node_id: int, device_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE shellbag_nodes SET device_id=? WHERE node_id=?",
                (device_id, node_id),
            )

    # ------------------------------------------------------------------
    def _node_from_row(self, row: sqlite3.Row) -> ShellbagNodeRecord:
        return ShellbagNodeRecord(
            node_id=int(row["node_id"]),
            evidence_id=row["evidence_id"],
            hive_id=row["hive_id"],
            parent_id=int(row["parent_id"]) if row["parent_id"] is not None else None,
            depth=int(row["depth"]),
            name=row["name"],
            path=row["path"],
            item_type=int(row["item_type"]),
            type_name=row["type_name"],
            name_source=row["name_source"],
            is_dir=bool(row["is_dir"]),
            is_device=bool(row["is_device"]),
            device_id=int(row["device_id"]) if row["device_id"] is not None else None,
            drive=row["drive"],
            volume_label=row["volume_label"],
            guid=row["guid"],
            device_path=row["device_path"],
            size_bytes=int(row["size_bytes"]) if row["size_bytes"] is not None else None,
            key_last_write_utc=row["key_last_write_utc"],
            embedded_timestamps=_loads(row["embedded_timestamps_json"], []),
            registry_key_path=row["registry_key_path"],
            registry_value_name=row["registry_value_name"],
            registry_key_id=(
                int(row["registry_key_id"])
                if row["registry_key_id"] is not None
                else None
            ),
            user_sid=row["user_sid"],
            mru_rank=int(row["mru_rank"]) if row["mru_rank"] is not None else None,
            warnings=_loads(row["warnings_json"], []),
        )

    def children(
        self,
        evidence_id: str,
        parent_id: int | None,
        *,
        hive_id: str | None = None,
        page: int = 1,
        page_size: int = 200,
    ) -> tuple[list[ShellbagNodeRecord], int]:
        where = ["evidence_id = ?"]
        params: list[Any] = [evidence_id]
        if parent_id is None:
            where.append("parent_id IS NULL")
        else:
            where.append("parent_id = ?")
            params.append(parent_id)
        if hive_id:
            where.append("hive_id = ?")
            params.append(hive_id)
        clause = " AND ".join(where)
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM shellbag_nodes WHERE {clause}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT {NODE_COLUMNS} FROM shellbag_nodes WHERE {clause} "
                "ORDER BY is_device DESC, name COLLATE NOCASE, node_id "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        return [self._node_from_row(row) for row in rows], total

    def get_node(self, node_id: int) -> ShellbagNodeRecord:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {NODE_COLUMNS} FROM shellbag_nodes WHERE node_id=?",
                (node_id,),
            ).fetchone()
        if row is None:
            raise ShellbagNotFound(
                "shellbag node was not found", details={"node_id": node_id}
            )
        return self._node_from_row(row)

    def ancestors(self, node_id: int) -> list[ShellbagNodeRecord]:
        chain: list[ShellbagNodeRecord] = []
        current = node_id
        seen: set[int] = set()
        while current is not None and current not in seen:
            seen.add(current)
            node = self.get_node(current)
            chain.append(node)
            current = node.parent_id
        return list(reversed(chain))

    def devices(self, evidence_id: str) -> list[ShellbagDeviceRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM shellbag_devices WHERE evidence_id=? "
                "ORDER BY kind, name COLLATE NOCASE",
                (evidence_id,),
            ).fetchall()
        return [
            ShellbagDeviceRecord(
                device_id=int(row["device_id"]),
                evidence_id=row["evidence_id"],
                node_id=int(row["node_id"]) if row["node_id"] is not None else None,
                name=row["name"],
                kind=row["kind"],
                detail=row["detail"],
                drive=row["drive"],
                volume_label=row["volume_label"],
                user_sid=row["user_sid"],
                first_seen_utc=row["first_seen_utc"],
                node_count=int(row["node_count"] or 0),
                warnings=_loads(row["warnings_json"], []),
            )
            for row in rows
        ]

    def update_device_count(self, device_id: int, count: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE shellbag_devices SET node_count=? WHERE device_id=?",
                (count, device_id),
            )

    def search(
        self,
        evidence_id: str,
        *,
        query: str | None = None,
        device_id: int | None = None,
        user_sid: str | None = None,
        hive_id: str | None = None,
        kind: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[ShellbagNodeRecord], int]:
        where = ["evidence_id = ?"]
        params: list[Any] = [evidence_id]
        if query:
            needle = f"%{escape_like(query)}%"
            where.append(
                "(name LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' "
                "OR drive LIKE ? ESCAPE '\\' OR volume_label LIKE ? ESCAPE '\\')"
            )
            params.extend([needle] * 4)
        if device_id is not None:
            where.append("device_id = ?")
            params.append(device_id)
        if user_sid:
            where.append("user_sid = ?")
            params.append(user_sid)
        if hive_id:
            where.append("hive_id = ?")
            params.append(hive_id)
        if kind == "device":
            where.append("is_device = 1")
        elif kind == "folder":
            where.append("is_dir = 1 AND is_device = 0")
        elif kind == "file":
            where.append("is_dir = 0")
        if time_from:
            where.append("key_last_write_utc >= ?")
            params.append(time_from)
        if time_to:
            where.append("key_last_write_utc <= ?")
            params.append(time_to)
        clause = " AND ".join(where)
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM shellbag_nodes WHERE {clause}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT {NODE_COLUMNS} FROM shellbag_nodes WHERE {clause} "
                "ORDER BY key_last_write_utc DESC, node_id DESC LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        return [self._node_from_row(row) for row in rows], total

    def counts(self, evidence_id: str) -> dict[str, int]:
        with self._connect() as connection:
            nodes = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM shellbag_nodes WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()["n"]
            )
            devices = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM shellbag_devices WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()["n"]
            )
            hives = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM shellbag_hives WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()["n"]
            )
        return {"nodes": nodes, "devices": devices, "hives": hives}
