from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import (
    REGISTRY_SCHEMA_VERSION,
    AmcacheRecord,
    HiveNotFoundError,
    RegistryError,
    RegistryHiveRecord,
    RegistryKeyDetail,
    RegistryKeyNode,
    RegistryPage,
    RegistryValueItem,
)
from .reader import KeyRecord

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS registry_hives (
  hive_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  inode INTEGER,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  hive_type TEXT NOT NULL,
  owner TEXT,
  size INTEGER,
  sha256 TEXT,
  extract_relpath TEXT,
  state TEXT NOT NULL,
  phase TEXT NOT NULL,
  dirty INTEGER NOT NULL DEFAULT 0,
  sequence1 INTEGER,
  sequence2 INTEGER,
  recovered INTEGER NOT NULL DEFAULT 0,
  parser_version TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  sensitive INTEGER NOT NULL DEFAULT 0,
  signature_status TEXT,
  transaction_logs_json TEXT,
  warnings_json TEXT,
  error_code TEXT,
  error_message TEXT,
  key_count INTEGER NOT NULL DEFAULT 0,
  value_count INTEGER NOT NULL DEFAULT 0,
  amcache_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT,
  started_at TEXT,
  finished_at TEXT
);
CREATE TABLE IF NOT EXISTS registry_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hive_id TEXT NOT NULL,
  parent_id INTEGER,
  key_path TEXT NOT NULL,
  name TEXT NOT NULL,
  depth INTEGER NOT NULL,
  last_write_time TEXT,
  subkey_count INTEGER NOT NULL DEFAULT 0,
  value_count INTEGER NOT NULL DEFAULT 0,
  has_children INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS registry_values (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hive_id TEXT NOT NULL,
  key_id INTEGER NOT NULL,
  key_path TEXT NOT NULL,
  name TEXT NOT NULL,
  type_name TEXT NOT NULL,
  type_id INTEGER,
  text_value TEXT,
  raw_size INTEGER NOT NULL DEFAULT 0,
  raw_sha256 TEXT,
  preview_hex TEXT,
  truncated INTEGER NOT NULL DEFAULT 0,
  warnings_json TEXT
);
CREATE TABLE IF NOT EXISTS registry_amcache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hive_id TEXT NOT NULL,
  source_key_path TEXT NOT NULL,
  source_key_id INTEGER,
  source_value_names_json TEXT,
  schema TEXT NOT NULL,
  program_name TEXT,
  executable_name TEXT,
  executable_path TEXT,
  file_id_raw TEXT,
  hash_algorithm TEXT NOT NULL,
  hash_raw TEXT,
  hash_normalized TEXT,
  hash_valid INTEGER NOT NULL DEFAULT 0,
  normalization_method TEXT NOT NULL,
  size INTEGER,
  publisher TEXT,
  product_name TEXT,
  product_version TEXT,
  binary_version TEXT,
  compile_timestamp TEXT,
  key_mtime TEXT,
  first_run TEXT,
  last_modified TEXT,
  program_id TEXT,
  volume_id TEXT,
  warnings_json TEXT
);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_reg_hives_entry
  ON registry_hives(evidence_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_reg_keys_parent
  ON registry_keys(hive_id, parent_id, name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_keys_path
  ON registry_keys(hive_id, key_path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_values_key
  ON registry_values(hive_id, key_id);
CREATE INDEX IF NOT EXISTS idx_reg_values_name
  ON registry_values(hive_id, name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_values_text
  ON registry_values(hive_id, text_value COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_amcache_name
  ON registry_amcache(hive_id, executable_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_amcache_path
  ON registry_amcache(hive_id, executable_path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_reg_amcache_hash
  ON registry_amcache(hive_id, hash_normalized);
CREATE INDEX IF NOT EXISTS idx_reg_amcache_program
  ON registry_amcache(hive_id, program_name COLLATE NOCASE);
"""

HIVE_COLUMNS = (
    "hive_id, evidence_id, entry_id, inode, path, name, hive_type, owner, "
    "size, sha256, extract_relpath, state, phase, dirty, sequence1, sequence2, "
    "recovered, parser_version, schema_version, sensitive, signature_status, "
    "transaction_logs_json, warnings_json, error_code, error_message, "
    "key_count, value_count, amcache_count, created_at, started_at, finished_at"
)


def escape_like(value: str) -> str:
    return (
        value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
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


class RegistryStore:
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
            connection.executescript(SCHEMA_SQL)
            columns = {
                str(row[1])
                for row in connection.execute(
                    "PRAGMA table_info(registry_amcache)"
                )
            }
            if "source_key_id" not in columns:
                connection.execute(
                    "ALTER TABLE registry_amcache ADD COLUMN source_key_id INTEGER"
                )
            connection.executescript(INDEX_SQL)
            connection.execute(
                f"PRAGMA user_version = {REGISTRY_SCHEMA_VERSION}"
            )

    def recover_interrupted(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE registry_hives SET state='interrupted', phase='ready', "
                "error_code='registry_interrupted', "
                "error_message='server restarted before the registry index finished', "
                "finished_at=datetime('now') "
                "WHERE state IN ('queued','running')"
            )
            return int(cursor.rowcount or 0)

    # -- hives ---------------------------------------------------------
    def _hive_from_row(self, row: sqlite3.Row) -> RegistryHiveRecord:
        return RegistryHiveRecord(
            hive_id=str(row["hive_id"]),
            evidence_id=str(row["evidence_id"]),
            entry_id=int(row["entry_id"]),
            inode=int(row["inode"]) if row["inode"] is not None else None,
            path=str(row["path"]),
            name=str(row["name"]),
            hive_type=str(row["hive_type"]),
            owner=row["owner"],
            size=int(row["size"]) if row["size"] is not None else None,
            sha256=row["sha256"],
            extract_relpath=row["extract_relpath"],
            state=str(row["state"]),
            phase=str(row["phase"]),
            dirty=bool(row["dirty"]),
            sequence1=(
                int(row["sequence1"]) if row["sequence1"] is not None else None
            ),
            sequence2=(
                int(row["sequence2"]) if row["sequence2"] is not None else None
            ),
            recovered=bool(row["recovered"]),
            parser_version=str(row["parser_version"]),
            schema_version=int(row["schema_version"]),
            sensitive=bool(row["sensitive"]),
            signature_status=row["signature_status"],
            transaction_logs=_loads(row["transaction_logs_json"], []),
            warnings=_loads(row["warnings_json"], []),
            error_code=row["error_code"],
            error_message=row["error_message"],
            key_count=int(row["key_count"] or 0),
            value_count=int(row["value_count"] or 0),
            amcache_count=int(row["amcache_count"] or 0),
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    def counts(self) -> dict[str, int]:
        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM registry_hives"
                ).fetchone()["n"]
            )
            active = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM registry_hives "
                    "WHERE state IN ('queued','running')"
                ).fetchone()["n"]
            )
        return {"hives": total, "active": active}

    def get_hive(self, hive_id: str) -> RegistryHiveRecord:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {HIVE_COLUMNS} FROM registry_hives WHERE hive_id = ?",
                (hive_id,),
            ).fetchone()
            if row is None:
                raise HiveNotFoundError(
                    "registry hive was not indexed", details={"hive_id": hive_id}
                )
            return self._hive_from_row(row)

    def find_hive_by_entry(
        self, evidence_id: str, entry_id: int
    ) -> RegistryHiveRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {HIVE_COLUMNS} FROM registry_hives "
                "WHERE evidence_id = ? AND entry_id = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (evidence_id, entry_id),
            ).fetchone()
            return self._hive_from_row(row) if row is not None else None

    def upsert_hive(self, hive: RegistryHiveRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM registry_hives WHERE hive_id = ?", (hive.hive_id,)
            )
            connection.execute(
                f"INSERT INTO registry_hives ({HIVE_COLUMNS}) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hive.hive_id,
                    hive.evidence_id,
                    hive.entry_id,
                    hive.inode,
                    hive.path,
                    hive.name,
                    hive.hive_type,
                    hive.owner,
                    hive.size,
                    hive.sha256,
                    hive.extract_relpath,
                    hive.state,
                    hive.phase,
                    1 if hive.dirty else 0,
                    hive.sequence1,
                    hive.sequence2,
                    1 if hive.recovered else 0,
                    hive.parser_version,
                    hive.schema_version,
                    1 if hive.sensitive else 0,
                    hive.signature_status,
                    _json(hive.transaction_logs),
                    _json(hive.warnings),
                    hive.error_code,
                    hive.error_message,
                    hive.key_count,
                    hive.value_count,
                    hive.amcache_count,
                    hive.created_at,
                    hive.started_at,
                    hive.finished_at,
                ),
            )
            # A rebuild replaces the derived rows for this hive.
            connection.execute(
                "DELETE FROM registry_keys WHERE hive_id = ?", (hive.hive_id,)
            )
            connection.execute(
                "DELETE FROM registry_values WHERE hive_id = ?", (hive.hive_id,)
            )
            connection.execute(
                "DELETE FROM registry_amcache WHERE hive_id = ?", (hive.hive_id,)
            )

    def update_phase(self, hive_id: str, phase: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE registry_hives SET state='running', phase=?, "
                "started_at=COALESCE(started_at, datetime('now')) "
                "WHERE hive_id = ?",
                (phase, hive_id),
            )

    def finish_hive(self, hive: RegistryHiveRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE registry_hives SET state=?, phase=?, sha256=?, size=?, "
                "extract_relpath=?, dirty=?, sequence1=?, sequence2=?, "
                "recovered=?, signature_status=?, transaction_logs_json=?, "
                "warnings_json=?, error_code=?, error_message=?, key_count=?, "
                "value_count=?, amcache_count=?, schema_version=?, finished_at=? "
                "WHERE hive_id = ?",
                (
                    hive.state,
                    hive.phase,
                    hive.sha256,
                    hive.size,
                    hive.extract_relpath,
                    1 if hive.dirty else 0,
                    hive.sequence1,
                    hive.sequence2,
                    1 if hive.recovered else 0,
                    hive.signature_status,
                    _json(hive.transaction_logs),
                    _json(hive.warnings),
                    hive.error_code,
                    hive.error_message,
                    hive.key_count,
                    hive.value_count,
                    hive.amcache_count,
                    hive.schema_version,
                    hive.finished_at,
                    hive.hive_id,
                ),
            )

    def latest_for_entries(
        self, evidence_id: str, entry_ids: list[int]
    ) -> dict[int, dict[str, Any]]:
        if not entry_ids:
            return {}
        placeholders = ",".join("?" for _ in entry_ids)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT hive_id, entry_id, state, phase, key_count, value_count, "
                "amcache_count, dirty, sensitive, signature_status "
                f"FROM registry_hives WHERE evidence_id = ? "
                f"AND entry_id IN ({placeholders}) ORDER BY rowid",
                (evidence_id, *entry_ids),
            ).fetchall()
        result: dict[int, dict[str, Any]] = {}
        for row in rows:
            result[int(row["entry_id"])] = {
                "hive_id": row["hive_id"],
                "state": row["state"],
                "phase": row["phase"],
                "key_count": row["key_count"],
                "value_count": row["value_count"],
                "amcache_count": row["amcache_count"],
                "dirty": bool(row["dirty"]),
                "sensitive": bool(row["sensitive"]),
                "signature_status": row["signature_status"],
            }
        return result

    # -- index writing -------------------------------------------------
    def index_hive(
        self, hive_id: str, keys: Iterable[KeyRecord]
    ) -> tuple[int, int, list[AmcacheRecord], RegistryError | None]:
        key_ids: dict[str, int] = {}
        key_count = 0
        value_count = 0
        amcache: list[AmcacheRecord] = []
        error: RegistryError | None = None
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            for record in keys:
                parent_id = (
                    key_ids.get(record.parent_path)
                    if record.parent_path
                    else None
                )
                has_children = 1 if record.subkey_count else 0
                cursor = connection.execute(
                    "INSERT INTO registry_keys (hive_id, parent_id, key_path, "
                    "name, depth, last_write_time, subkey_count, value_count, "
                    "has_children) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        hive_id,
                        parent_id,
                        record.path,
                        record.name,
                        record.depth,
                        record.last_write_time,
                        record.subkey_count,
                        record.value_count,
                        has_children,
                    ),
                )
                key_id = int(cursor.lastrowid)
                key_ids[record.path] = key_id
                key_count += 1
                value_rows = [
                    (
                        hive_id,
                        key_id,
                        record.path,
                        value.name,
                        value.type_name,
                        value.type_id,
                        value.text_value,
                        value.raw_size,
                        value.raw_sha256,
                        value.preview_hex,
                        1 if value.truncated else 0,
                        _json(value.warnings),
                    )
                    for value in record.values
                ]
                if value_rows:
                    connection.executemany(
                        "INSERT INTO registry_values (hive_id, key_id, key_path, "
                        "name, type_name, type_id, text_value, raw_size, "
                        "raw_sha256, preview_hex, truncated, warnings_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        value_rows,
                    )
                    value_count += len(value_rows)
                if (
                    "\\inventoryapplicationfile\\" in record.path.lower()
                    or "\\root\\file\\" in record.path.lower()
                ):
                    from .amcache import parse_amcache_key

                    parsed = parse_amcache_key(
                        hive_id=hive_id,
                        key_path=record.path,
                        key_mtime=record.last_write_time,
                        values=record.values,
                    )
                    if parsed is not None:
                        parsed.source_key_id = key_id
                        amcache.append(parsed)
                if key_count % 1000 == 0:
                    connection.commit()
                    connection.execute("BEGIN")
        except RegistryError as exc:
            error = exc
        except Exception as exc:  # noqa: BLE001 - storage errors become job errors
            error = RegistryError(
                f"registry index write failed: {exc}"[:500],
                code="registry_index_write_failed",
            )
        finally:
            try:
                connection.commit()
            except sqlite3.Error:
                pass
            connection.close()
        if amcache:
            self.insert_amcache(hive_id, amcache)
        return key_count, value_count, amcache, error

    def insert_amcache(
        self, hive_id: str, records: list[AmcacheRecord]
    ) -> None:
        if not records:
            return
        rows = [
            (
                hive_id,
                record.source_key_path,
                record.source_key_id,
                _json(record.source_value_names),
                record.schema,
                record.program_name,
                record.executable_name,
                record.executable_path,
                record.file_id_raw,
                record.hash_algorithm,
                record.hash_raw,
                record.hash_normalized,
                1 if record.hash_valid else 0,
                record.normalization_method,
                record.size,
                record.publisher,
                record.product_name,
                record.product_version,
                record.binary_version,
                record.compile_timestamp,
                record.key_mtime,
                record.first_run,
                record.last_modified,
                record.program_id,
                record.volume_id,
                _json(record.warnings),
            )
            for record in records
        ]
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO registry_amcache (hive_id, source_key_path, "
                "source_key_id, source_value_names_json, schema, program_name, executable_name, "
                "executable_path, file_id_raw, hash_algorithm, hash_raw, "
                "hash_normalized, hash_valid, normalization_method, size, "
                "publisher, product_name, product_version, binary_version, "
                "compile_timestamp, key_mtime, first_run, last_modified, "
                "program_id, volume_id, warnings_json) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                " ?, ?, ?, ?, ?, ?)",
                rows,
            )

    # -- queries -------------------------------------------------------
    @staticmethod
    def _key_node(row: sqlite3.Row) -> RegistryKeyNode:
        return RegistryKeyNode(
            key_id=int(row["id"]),
            hive_id=str(row["hive_id"]),
            parent_key_id=(
                int(row["parent_id"]) if row["parent_id"] is not None else None
            ),
            key_path=str(row["key_path"]),
            name=str(row["name"]),
            depth=int(row["depth"]),
            last_write_time=row["last_write_time"],
            subkey_count=int(row["subkey_count"] or 0),
            value_count=int(row["value_count"] or 0),
            has_children=bool(row["has_children"]),
        )

    def root_key(self, hive_id: str) -> RegistryKeyNode:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM registry_keys WHERE hive_id = ? "
                "AND parent_id IS NULL ORDER BY id LIMIT 1",
                (hive_id,),
            ).fetchone()
            if row is None:
                raise RegistryError(
                    "registry hive has no root key",
                    code="registry_root_missing",
                    details={"hive_id": hive_id},
                )
            return self._key_node(row)

    def key_ancestors(
        self, hive_id: str, key_id: int
    ) -> list[RegistryKeyNode]:
        ancestors: list[RegistryKeyNode] = []
        seen: set[int] = set()
        current = key_id
        with self._connect() as connection:
            while True:
                row = connection.execute(
                    "SELECT * FROM registry_keys WHERE hive_id = ? AND id = ?",
                    (hive_id, current),
                ).fetchone()
                if row is None or current in seen:
                    break
                seen.add(current)
                node = self._key_node(row)
                if node.parent_key_id is None:
                    break
                ancestors.append(node)
                current = node.parent_key_id
        ancestors.reverse()
        # Drop the target's leaf ancestors; callers need the chain root->parent.
        return [node for node in ancestors if node.key_id != key_id]

    def list_subkeys(
        self,
        hive_id: str,
        parent_key_id: int | None,
        page: int,
        page_size: int,
    ) -> RegistryPage:
        where = "hive_id = ?"
        params: list[Any] = [hive_id]
        if parent_key_id is None:
            where += " AND parent_id IS NULL"
        else:
            where += " AND parent_id = ?"
            params.append(parent_key_id)
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM registry_keys WHERE {where}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM registry_keys "
                f"WHERE {where} ORDER BY name COLLATE NOCASE, id "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        return RegistryPage(
            items=[self._key_node(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
            kind="registry_keys",
        )

    def get_key(
        self, hive_id: str, key_id: int, preview_bytes: int
    ) -> RegistryKeyDetail:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM registry_keys WHERE hive_id = ? AND id = ?",
                (hive_id, key_id),
            ).fetchone()
            if row is None:
                raise RegistryError(
                    "registry key was not found",
                    code="registry_key_not_found",
                    details={"hive_id": hive_id, "key_id": key_id},
                )
            value_rows = connection.execute(
                "SELECT * FROM registry_values WHERE hive_id = ? AND key_id = ? "
                "ORDER BY name COLLATE NOCASE, id",
                (hive_id, key_id),
            ).fetchall()
        values = [
            RegistryValueItem(
                value_id=int(item["id"]),
                key_id=int(item["key_id"]),
                key_path=str(item["key_path"]),
                name=str(item["name"]),
                type_name=str(item["type_name"]),
                type_id=(
                    int(item["type_id"]) if item["type_id"] is not None else None
                ),
                text_value=item["text_value"],
                raw_size=int(item["raw_size"] or 0),
                raw_sha256=item["raw_sha256"],
                preview_hex=item["preview_hex"],
                truncated=bool(item["truncated"]),
                warnings=_loads(item["warnings_json"], []),
            )
            for item in value_rows
        ]
        return RegistryKeyDetail(
            key=self._key_node(row),
            values=values,
            binary_preview_bytes=preview_bytes,
        )

    def search(
        self,
        hive_id: str,
        query: str,
        *,
        search_key_names: bool,
        search_value_names: bool,
        search_string_values: bool,
        exact: bool,
        page: int,
        page_size: int,
    ) -> RegistryPage:
        arms: list[str] = []
        params: list[Any] = []

        def match(column: str) -> str:
            if exact:
                return f"{column} COLLATE NOCASE = ?"
            return f"{column} LIKE ? ESCAPE '\\'"

        def value_for(column: str) -> str:
            return query if exact else f"%{escape_like(query)}%"

        if search_key_names:
            arms.append(
                "SELECT 'key' AS kind, id AS key_id, key_path, name, "
                "NULL AS type_name, NULL AS text_value, last_write_time AS ts "
                "FROM registry_keys WHERE hive_id = ? AND ("
                + match("key_path")
                + " OR "
                + match("name")
                + ")"
            )
            params.extend(
                [hive_id, value_for("key_path"), value_for("name")]
            )
        if search_value_names:
            arms.append(
                "SELECT 'value' AS kind, key_id, key_path, name, type_name, "
                "text_value, NULL AS ts FROM registry_values "
                "WHERE hive_id = ? AND ("
                + match("name")
                + " OR "
                + match("key_path")
                + ")"
            )
            params.extend(
                [hive_id, value_for("name"), value_for("key_path")]
            )
        if search_string_values:
            arms.append(
                "SELECT 'value' AS kind, key_id, key_path, name, type_name, "
                "text_value, NULL AS ts FROM registry_values "
                "WHERE hive_id = ? AND text_value IS NOT NULL AND "
                + match("text_value")
            )
            params.append(hive_id)
            params.append(value_for("text_value"))
        if not arms:
            return RegistryPage(
                items=[],
                total=0,
                page=page,
                page_size=page_size,
                kind="registry_search",
            )
        union_sql = " UNION ".join(arms)
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM ({union_sql})", params
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT * FROM ({union_sql}) "
                "ORDER BY key_path COLLATE NOCASE, kind, name COLLATE NOCASE "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        items = [
            {
                "trust": "untrusted_evidence_data",
                "kind": row["kind"],
                "key_id": int(row["key_id"]),
                "key_path": row["key_path"],
                "name": row["name"],
                "type": row["type_name"],
                "value": row["text_value"],
                "timestamp": row["ts"],
            }
            for row in rows
        ]
        return RegistryPage(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            kind="registry_search",
        )

    def amcache_search(
        self, hive_id: str, query: str, exact: bool, page: int, page_size: int
    ) -> RegistryPage:
        pattern = query if exact else f"%{escape_like(query)}%"
        if exact:
            where = (
                "(executable_name COLLATE NOCASE = ? OR executable_path COLLATE NOCASE = ? "
                "OR program_name COLLATE NOCASE = ? OR publisher COLLATE NOCASE = ? "
                "OR product_name COLLATE NOCASE = ? OR hash_normalized = ? "
                "OR hash_raw = ? OR file_id_raw = ?)"
            )
            params = [query] * 8
        else:
            where = (
                "(executable_name LIKE ? ESCAPE '\\' OR executable_path LIKE ? ESCAPE '\\' "
                "OR program_name LIKE ? ESCAPE '\\' OR publisher LIKE ? ESCAPE '\\' "
                "OR product_name LIKE ? ESCAPE '\\' OR hash_normalized LIKE ? ESCAPE '\\' "
                "OR hash_raw LIKE ? ESCAPE '\\' OR file_id_raw LIKE ? ESCAPE '\\')"
            )
            params = [pattern] * 8
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM registry_amcache "
                    f"WHERE hive_id = ? AND {where}",
                    [hive_id, *params],
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM registry_amcache "
                f"WHERE hive_id = ? AND {where} "
                "ORDER BY executable_name COLLATE NOCASE, id LIMIT ? OFFSET ?",
                [hive_id, *params, page_size, offset],
            ).fetchall()
        return RegistryPage(
            items=[self._amcache_dict(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
            kind="amcache",
        )

    def get_amcache(self, hive_id: str, record_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM registry_amcache WHERE hive_id = ? AND id = ?",
                (hive_id, record_id),
            ).fetchone()
            if row is None:
                raise RegistryError(
                    "Amcache record was not found",
                    code="amcache_record_not_found",
                    details={"hive_id": hive_id, "record_id": record_id},
                )
            return self._amcache_dict(row)

    @staticmethod
    def _amcache_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "trust": "untrusted_evidence_data",
            "record_id": int(row["id"]),
            "hive_id": row["hive_id"],
            "source_key_path": row["source_key_path"],
            "source_key_id": row["source_key_id"],
            "source_value_names": _loads(row["source_value_names_json"], {}),
            "schema": row["schema"],
            "program_name": row["program_name"],
            "executable_name": row["executable_name"],
            "executable_path": row["executable_path"],
            "file_id_raw": row["file_id_raw"],
            "hash_algorithm": row["hash_algorithm"],
            "hash_raw": row["hash_raw"],
            "hash_normalized": row["hash_normalized"],
            "hash_valid": bool(row["hash_valid"]),
            "normalization_method": row["normalization_method"],
            "size": row["size"],
            "publisher": row["publisher"],
            "product_name": row["product_name"],
            "product_version": row["product_version"],
            "binary_version": row["binary_version"],
            "compile_timestamp": row["compile_timestamp"],
            "key_mtime": row["key_mtime"],
            "first_run": row["first_run"],
            "last_modified": row["last_modified"],
            "program_id": row["program_id"],
            "volume_id": row["volume_id"],
            "warnings": _loads(row["warnings_json"], []),
        }
