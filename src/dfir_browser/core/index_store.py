from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .index_models import (
    INDEX_SCHEMA_VERSION,
    ROOT_ENTRY_ID,
    EntryNotFoundError,
    IndexStoreError,
    IndexedEntry,
)
from .index_models import utc_now_iso

SCHEMA_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS evidence_indexes (
  evidence_id TEXT PRIMARY KEY,
  source_sha256 TEXT,
  raw_exposure_path TEXT,
  filesystem TEXT,
  offset_sectors INTEGER,
  fls_version TEXT,
  index_schema_version INTEGER NOT NULL,
  scanner_version TEXT NOT NULL,
  status TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0,
  scan_id TEXT,
  started_at TEXT,
  completed_at TEXT,
  entries_seen INTEGER NOT NULL DEFAULT 0,
  entries_indexed INTEGER NOT NULL DEFAULT 0,
  parse_errors INTEGER NOT NULL DEFAULT 0,
  deleted_files INTEGER NOT NULL DEFAULT 0,
  deleted_directories INTEGER NOT NULL DEFAULT 0,
  allocated_files INTEGER NOT NULL DEFAULT 0,
  allocated_directories INTEGER NOT NULL DEFAULT 0,
  current_path TEXT,
  error_code TEXT,
  error_message TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS filesystem_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  full_path TEXT NOT NULL,
  parent_path TEXT NOT NULL,
  basename TEXT NOT NULL,
  extension TEXT NOT NULL DEFAULT '',
  inode INTEGER,
  sequence INTEGER,
  attribute_id INTEGER,
  fls_type TEXT,
  entry_type TEXT NOT NULL,
  allocated INTEGER NOT NULL,
  deleted INTEGER NOT NULL,
  size INTEGER,
  created_time TEXT,
  modified_time TEXT,
  accessed_time TEXT,
  mft_modified_time TEXT,
  raw_line_hash TEXT
  ,backend_type TEXT
  ,source_ref TEXT
  ,stored_md5 TEXT
  ,stored_sha1 TEXT
);

CREATE TABLE IF NOT EXISTS filesystem_parse_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  line_no INTEGER,
  raw_line TEXT,
  error TEXT,
  created_at TEXT
);

"""

SCHEMA_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_entries_evidence_parent
  ON filesystem_entries(evidence_id, scan_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_deleted
  ON filesystem_entries(evidence_id, scan_id, deleted, entry_type);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_deleted_path
  ON filesystem_entries(evidence_id, scan_id, deleted, entry_type, full_path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_basename
  ON filesystem_entries(evidence_id, scan_id, basename COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_full_path
  ON filesystem_entries(evidence_id, scan_id, full_path COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_inode
  ON filesystem_entries(evidence_id, scan_id, inode);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_extension
  ON filesystem_entries(evidence_id, scan_id, extension);
CREATE INDEX IF NOT EXISTS idx_parse_errors_scan
  ON filesystem_parse_errors(evidence_id, scan_id);
"""

# Tree navigation indexes are created after a scan has been linked, not during
# bulk insert, so each indexed row is written once instead of seventeen times.
TREE_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_entries_evidence_parent_id
  ON filesystem_entries(evidence_id, scan_id, parent_id);
CREATE INDEX IF NOT EXISTS idx_entries_evidence_id
  ON filesystem_entries(evidence_id, scan_id, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_name
  ON filesystem_entries(evidence_id, scan_id, parent_id, basename COLLATE NOCASE, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_root_name
  ON filesystem_entries(evidence_id, scan_id, basename COLLATE NOCASE, id)
  WHERE parent_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_entries_tree_modified
  ON filesystem_entries(evidence_id, scan_id, parent_id, modified_time, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_size
  ON filesystem_entries(evidence_id, scan_id, parent_id, size, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_type
  ON filesystem_entries(evidence_id, scan_id, parent_id, entry_type, basename COLLATE NOCASE, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_status
  ON filesystem_entries(evidence_id, scan_id, parent_id, deleted, allocated, basename COLLATE NOCASE, id);
CREATE INDEX IF NOT EXISTS idx_entries_tree_deleted_name
  ON filesystem_entries(evidence_id, scan_id, parent_id, deleted, entry_type, basename COLLATE NOCASE, id);
"""

# Columns added after schema version 1. Older databases are upgraded in place
# by adding them and rebuilding the parent relation inside one transaction.
ADDED_COLUMNS = {
    "filesystem_entries": (
        ("parent_id", "INTEGER"),
        ("has_children", "INTEGER NOT NULL DEFAULT 0"),
        ("backend_type", "TEXT"),
        ("source_ref", "TEXT"),
        ("stored_md5", "TEXT"),
        ("stored_sha1", "TEXT"),
    ),
}

ENTRY_COLUMNS = (
    "id, evidence_id, full_path, parent_path, basename, extension, inode, "
    "sequence, attribute_id, fls_type, entry_type, allocated, deleted, size, "
    "created_time, modified_time, accessed_time, mft_modified_time, "
    "raw_line_hash, backend_type, source_ref, stored_md5, stored_sha1"
)

INSERT_ENTRY_SQL = f"""
INSERT INTO filesystem_entries (
  evidence_id, scan_id, full_path, parent_path, basename, extension, inode,
  sequence, attribute_id, fls_type, entry_type, allocated, deleted, size,
  created_time, modified_time, accessed_time, mft_modified_time,
  raw_line_hash, parent_id
  , backend_type, source_ref, stored_md5, stored_sha1
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

INSERT_PARSE_ERROR_SQL = """
INSERT INTO filesystem_parse_errors (
  evidence_id, scan_id, line_no, raw_line, error, created_at
) VALUES (?, ?, ?, ?, ?, ?)
"""

SORT_SQL = {
    "path": "full_path COLLATE NOCASE",
    "basename": "basename COLLATE NOCASE",
    "name": "basename COLLATE NOCASE",
    "type": "entry_type",
    "modified": "modified_time",
    "created": "created_time",
    "size": "size",
    "deleted": "deleted",
    "status": "deleted, allocated, basename COLLATE NOCASE, id",
}

TREE_SORT_SQL = {
    "path": "basename COLLATE NOCASE",
    "basename": "basename COLLATE NOCASE",
    "name": "basename COLLATE NOCASE",
    "type": "entry_type",
    "modified": "modified_time",
    "created": "created_time",
    "size": "size",
    "deleted": "deleted, entry_type, basename COLLATE NOCASE, id",
    "status": "deleted, allocated, basename COLLATE NOCASE, id",
}


def escape_like(value: str) -> str:
    """Escape SQLite LIKE wildcards for use with ``ESCAPE '\\'``."""
    return (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class IndexStore:
    """SQLite-backed filesystem index.

    All writes are transactional. Queries always filter on the active scan_id
    so rows from a previous or interrupted scan can never be mixed in.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(str(self.path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return connection

    def ensure_schema(self) -> None:
        connection = self._connect()
        try:
            version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if version > INDEX_SCHEMA_VERSION:
                raise IndexStoreError(
                    "filesystem index schema is newer than this application supports",
                    code="index_schema_newer",
                    details={
                        "path": str(self.path),
                        "version": version,
                        "supported": INDEX_SCHEMA_VERSION,
                    },
                )
            with connection:
                connection.executescript(SCHEMA_TABLES_SQL)
                self._add_missing_columns(connection)
                if version < INDEX_SCHEMA_VERSION:
                    self._backfill_tree_columns(connection)
                connection.executescript(SCHEMA_INDEXES_SQL)
                connection.execute(
                    f"PRAGMA user_version = {INDEX_SCHEMA_VERSION}"
                )
        except sqlite3.Error as exc:
            raise IndexStoreError(
                f"cannot initialize filesystem index database: {exc}",
                details={"path": str(self.path)},
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _add_missing_columns(connection: sqlite3.Connection) -> None:
        for table, columns in ADDED_COLUMNS.items():
            existing = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            for name, definition in columns:
                if name not in existing:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                    )

    def _backfill_tree_columns(self, connection: sqlite3.Connection) -> None:
        """Derive parent_id/has_children for an index built by schema v1.

        The index generation is preserved; only derived tree columns are
        populated. Evidence, registry and case data are untouched. A path with
        no matching directory row (orphans, malformed paths) becomes a root
        child instead of breaking the index.
        """
        rows = connection.execute(
            "SELECT id, evidence_id, scan_id, entry_type, deleted, full_path, "
            "parent_path FROM filesystem_entries"
        ).fetchall()

        best_dir: dict[tuple[str, str, str], tuple[int, int]] = {}
        for row_id, evidence_id, scan_id, entry_type, deleted, full_path, _p in rows:
            if entry_type != "directory":
                continue
            key = (evidence_id, scan_id, full_path)
            rank = (0 if not deleted else 1, row_id)
            if key not in best_dir or rank < best_dir[key]:
                best_dir[key] = rank
        directory_ids = {key: rank[1] for key, rank in best_dir.items()}

        updates: list[tuple[int | None, int, str, str]] = []
        parents: set[tuple[str, str, int]] = set()
        for row_id, evidence_id, scan_id, _type, _deleted, _path, parent_path in rows:
            parent_id = (
                directory_ids.get((evidence_id, scan_id, parent_path))
                if parent_path
                else None
            )
            updates.append((parent_id, row_id, evidence_id, scan_id))
            if parent_id is not None:
                parents.add((evidence_id, scan_id, parent_id))

        connection.executemany(
            "UPDATE filesystem_entries SET parent_id = ?, has_children = 0 "
            "WHERE id = ? AND evidence_id = ? AND scan_id = ?",
            updates,
        )
        connection.executemany(
            "UPDATE filesystem_entries SET has_children = 1 "
            "WHERE evidence_id = ? AND scan_id = ? AND id = ?",
            sorted(parents),
        )

    def get_index_row(self, evidence_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evidence_indexes WHERE evidence_id = ?",
                (evidence_id,),
            ).fetchone()
            return dict(row) if row is not None else None

    def list_running(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT evidence_id, scan_id FROM evidence_indexes "
                "WHERE status IN ('pending', 'running')"
            ).fetchall()
            return [dict(row) for row in rows]

    def begin_scan(
        self,
        evidence_id: str,
        scan_id: str,
        identity: Mapping[str, Any],
        started_at: str,
    ) -> None:
        now = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO evidence_indexes (
                  evidence_id, source_sha256, raw_exposure_path, filesystem,
                  offset_sectors, fls_version, index_schema_version,
                  scanner_version, status, stale, scan_id, started_at,
                  completed_at, entries_seen, entries_indexed, parse_errors,
                  deleted_files, deleted_directories, allocated_files,
                  allocated_directories, current_path, error_code,
                  error_message, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, ?, ?, NULL,
                          0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, ?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                  source_sha256 = excluded.source_sha256,
                  raw_exposure_path = excluded.raw_exposure_path,
                  filesystem = excluded.filesystem,
                  offset_sectors = excluded.offset_sectors,
                  fls_version = excluded.fls_version,
                  index_schema_version = excluded.index_schema_version,
                  scanner_version = excluded.scanner_version,
                  status = 'running',
                  stale = 0,
                  scan_id = excluded.scan_id,
                  started_at = excluded.started_at,
                  completed_at = NULL,
                  entries_seen = 0,
                  entries_indexed = 0,
                  parse_errors = 0,
                  deleted_files = 0,
                  deleted_directories = 0,
                  allocated_files = 0,
                  allocated_directories = 0,
                  current_path = NULL,
                  error_code = NULL,
                  error_message = NULL,
                  updated_at = excluded.updated_at
                """,
                (
                    evidence_id,
                    identity.get("source_sha256") or "",
                    identity.get("raw_exposure_path") or "",
                    identity.get("filesystem") or "",
                    int(identity.get("offset_sectors") or 0),
                    identity.get("fls_version") or "",
                    int(
                        identity.get("index_schema_version")
                        or INDEX_SCHEMA_VERSION
                    ),
                    identity.get("scanner_version") or "",
                    scan_id,
                    started_at,
                    now,
                ),
            )

    def update_progress(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        entries_seen: int,
        entries_indexed: int,
        parse_errors: int,
        deleted_files: int,
        deleted_directories: int,
        allocated_files: int,
        allocated_directories: int,
        current_path: str | None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE evidence_indexes SET
                  entries_seen = ?,
                  entries_indexed = ?,
                  parse_errors = ?,
                  deleted_files = ?,
                  deleted_directories = ?,
                  allocated_files = ?,
                  allocated_directories = ?,
                  current_path = ?,
                  updated_at = ?
                WHERE evidence_id = ? AND scan_id = ? AND status = 'running'
                """,
                (
                    entries_seen,
                    entries_indexed,
                    parse_errors,
                    deleted_files,
                    deleted_directories,
                    allocated_files,
                    allocated_directories,
                    current_path,
                    utc_now_iso(),
                    evidence_id,
                    scan_id,
                ),
            )

    def finish_scan(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        status: str,
        entries_seen: int,
        entries_indexed: int,
        parse_errors: int,
        deleted_files: int,
        deleted_directories: int,
        allocated_files: int,
        allocated_directories: int,
        error_code: str | None,
        error_message: str | None,
        current_path: str | None = None,
    ) -> None:
        completed_at = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE evidence_indexes SET
                  status = ?,
                  completed_at = ?,
                  entries_seen = ?,
                  entries_indexed = ?,
                  parse_errors = ?,
                  deleted_files = ?,
                  deleted_directories = ?,
                  allocated_files = ?,
                  allocated_directories = ?,
                  current_path = ?,
                  error_code = ?,
                  error_message = ?,
                  updated_at = ?
                WHERE evidence_id = ? AND scan_id = ?
                """,
                (
                    status,
                    completed_at,
                    entries_seen,
                    entries_indexed,
                    parse_errors,
                    deleted_files,
                    deleted_directories,
                    allocated_files,
                    allocated_directories,
                    current_path,
                    error_code,
                    error_message,
                    completed_at,
                    evidence_id,
                    scan_id,
                ),
            )
            if status in {"ready", "incomplete"}:
                # The completed scan is the only active generation. Rows from
                # prior or interrupted scans are removed in the same
                # transaction, so readers can never mix generations.
                connection.execute(
                    "DELETE FROM filesystem_entries "
                    "WHERE evidence_id = ? AND scan_id <> ?",
                    (evidence_id, scan_id),
                )
                connection.execute(
                    "DELETE FROM filesystem_parse_errors "
                    "WHERE evidence_id = ? AND scan_id <> ?",
                    (evidence_id, scan_id),
                )
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass

    def mark_interrupted(
        self, evidence_id: str, scan_id: str | None, message: str
    ) -> None:
        now = utc_now_iso()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE evidence_indexes SET
                  status = 'interrupted',
                  completed_at = ?,
                  current_path = NULL,
                  error_code = 'interrupted',
                  error_message = ?,
                  updated_at = ?
                WHERE evidence_id = ?
                  AND status IN ('pending', 'running')
                  AND (? IS NULL OR scan_id = ?)
                """,
                (now, message, now, evidence_id, scan_id, scan_id),
            )

    def mark_stale(self, evidence_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE evidence_indexes SET stale = 1, updated_at = ? "
                "WHERE evidence_id = ?",
                (utc_now_iso(), evidence_id),
            )

    def insert_entries(self, rows: Iterable[Sequence[Any]]) -> None:
        rows = [tuple(row) + (None, None, None, None) if len(row) == 20 else tuple(row) for row in rows]
        if not rows:
            return
        try:
            with self._connect() as connection:
                connection.executemany(INSERT_ENTRY_SQL, rows)
        except sqlite3.Error as exc:
            raise IndexStoreError(
                f"cannot insert filesystem index entries: {exc}",
                details={"rows": len(rows)},
            ) from exc

    def link_tree(self, evidence_id: str, scan_id: str) -> None:
        """Resolve parent_id/has_children for one completed scan generation.

        Parents are matched by normalized path inside the same evidence and
        scan. Duplicate directory paths (hardlinks/ADS) prefer an allocated
        row, then the lowest row id. Entries whose parent path has no directory
        row become root children. Runs in one transaction.
        """
        with self._connect() as connection:
            try:
                with connection:
                    directory_rows = connection.execute(
                        "SELECT id, full_path, deleted FROM filesystem_entries "
                        "WHERE evidence_id = ? AND scan_id = ? "
                        "AND entry_type = 'directory' ORDER BY deleted, id",
                        (evidence_id, scan_id),
                    ).fetchall()
                    directory_ids: dict[str, int] = {}
                    for row in directory_rows:
                        directory_ids.setdefault(
                            str(row["full_path"]), int(row["id"])
                        )

                    entry_rows = connection.execute(
                        "SELECT id, parent_path FROM filesystem_entries "
                        "WHERE evidence_id = ? AND scan_id = ?",
                        (evidence_id, scan_id),
                    ).fetchall()
                    updates: list[tuple[int | None, int]] = []
                    parents: set[int] = set()
                    for row in entry_rows:
                        parent_path = str(row["parent_path"] or "")
                        parent_id = (
                            directory_ids.get(parent_path)
                            if parent_path
                            else None
                        )
                        updates.append((parent_id, int(row["id"])))
                        if parent_id is not None:
                            parents.add(parent_id)

                    connection.executemany(
                        "UPDATE filesystem_entries SET parent_id = ?, "
                        "has_children = 0 WHERE id = ?",
                        updates,
                    )
                    connection.executemany(
                        "UPDATE filesystem_entries SET has_children = 1 "
                        "WHERE id = ?",
                        [(parent_id,) for parent_id in parents],
                    )
                    connection.executescript(TREE_INDEXES_SQL)
            except sqlite3.Error as exc:
                raise IndexStoreError(
                    f"cannot build tree relations for index: {exc}",
                    details={"evidence_id": evidence_id, "scan_id": scan_id},
                ) from exc

    def insert_parse_errors(self, rows: Iterable[Sequence[Any]]) -> None:
        rows = list(rows)
        if not rows:
            return
        try:
            with self._connect() as connection:
                connection.executemany(INSERT_PARSE_ERROR_SQL, rows)
        except sqlite3.Error as exc:
            raise IndexStoreError(
                f"cannot insert filesystem parse errors: {exc}",
                details={"rows": len(rows)},
            ) from exc

    def count_parse_errors(self, evidence_id: str, scan_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM filesystem_parse_errors "
                "WHERE evidence_id = ? AND scan_id = ?",
                (evidence_id, scan_id),
            ).fetchone()
            return int(row["n"])

    def list_parse_errors(
        self, evidence_id: str, scan_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT line_no, raw_line, error, created_at "
                "FROM filesystem_parse_errors "
                "WHERE evidence_id = ? AND scan_id = ? "
                "ORDER BY line_no LIMIT ?",
                (evidence_id, scan_id, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    def resolve_directory_path(
        self, evidence_id: str, scan_id: str, inode: int
    ) -> str | None:
        if inode == 5:
            return ""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT full_path FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? AND inode = ? "
                "AND entry_type = 'directory' "
                "ORDER BY full_path LIMIT 1",
                (evidence_id, scan_id, inode),
            ).fetchone()
            return str(row["full_path"]) if row is not None else None

    def resolve_directory_inode(
        self, evidence_id: str, scan_id: str, path: str
    ) -> int | None:
        if path in {"", "/"}:
            return 5
        with self._connect() as connection:
            row = connection.execute(
                "SELECT inode FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? AND full_path = ? "
                "AND entry_type = 'directory' LIMIT 1",
                (evidence_id, scan_id, path),
            ).fetchone()
            return int(row["inode"]) if row is not None and row["inode"] is not None else None

    def query_directory(
        self,
        evidence_id: str,
        scan_id: str,
        parent_path: str,
        limit: int,
        offset: int,
    ) -> tuple[list[IndexedEntry], int]:
        where = "evidence_id = ? AND scan_id = ? AND parent_path = ?"
        params: list[Any] = [evidence_id, scan_id, parent_path]
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM filesystem_entries WHERE {where}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS} FROM filesystem_entries "
                f"WHERE {where} "
                "ORDER BY CASE WHEN entry_type = 'directory' THEN 0 ELSE 1 END, "
                "basename COLLATE NOCASE, id LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows], total

    def _paginated_query(
        self,
        *,
        where: str,
        params: list[Any],
        sort: str,
        sort_dir: str,
        page: int,
        page_size: int,
    ) -> tuple[list[IndexedEntry], int]:
        order_column = SORT_SQL.get(sort, SORT_SQL["path"])
        direction = "DESC" if sort_dir == "desc" else "ASC"
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM filesystem_entries WHERE {where}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS} FROM filesystem_entries "
                f"WHERE {where} ORDER BY {order_column} {direction}, id "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows], total

    def query_all_under(
        self,
        evidence_id: str,
        scan_id: str,
        path: str,
        *,
        sort: str,
        sort_dir: str,
        page: int,
        page_size: int,
    ) -> tuple[list[IndexedEntry], int]:
        where = "evidence_id = ? AND scan_id = ?"
        params: list[Any] = [evidence_id, scan_id]
        if path not in {"", "/"}:
            where += " AND full_path LIKE ? ESCAPE '\\'"
            params.append(escape_like(path.rstrip("/")) + "/%")
        return self._paginated_query(
            where=where,
            params=params,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )

    def query_deleted(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        include_directories: bool,
        extension: str | None,
        search: str | None,
        sort: str,
        sort_dir: str,
        page: int,
        page_size: int,
    ) -> tuple[list[IndexedEntry], int]:
        where = "evidence_id = ? AND scan_id = ? AND deleted = 1"
        params: list[Any] = [evidence_id, scan_id]
        if not include_directories:
            where += " AND entry_type = 'file'"
        if extension:
            where += " AND extension = ?"
            params.append(extension)
        if search:
            pattern = "%" + escape_like(search) + "%"
            where += (
                " AND (full_path LIKE ? ESCAPE '\\' "
                "OR basename LIKE ? ESCAPE '\\')"
            )
            params.extend([pattern, pattern])
        return self._paginated_query(
            where=where,
            params=params,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )

    def search(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        query: str,
        exact: bool,
        extension: str | None,
        deleted_only: bool,
        allocated_only: bool,
        entry_type: str | None,
        sort: str,
        sort_dir: str,
        page: int,
        page_size: int,
    ) -> tuple[list[IndexedEntry], int]:
        filter_sql = ""
        filter_params: list[Any] = []
        if extension:
            filter_sql += " AND extension = ?"
            filter_params.append(extension)
        if deleted_only:
            filter_sql += " AND deleted = 1"
        if allocated_only:
            filter_sql += " AND deleted = 0"
        if entry_type:
            filter_sql += " AND entry_type = ?"
            filter_params.append(entry_type)

        if exact:
            # Separate indexed branches avoid SQLite scanning the whole
            # evidence when the two NOCASE indexes could each answer it.
            where_by_name = (
                "evidence_id = ? AND scan_id = ? "
                "AND basename COLLATE NOCASE = ?" + filter_sql
            )
            where_by_path = (
                "evidence_id = ? AND scan_id = ? "
                "AND full_path COLLATE NOCASE = ?" + filter_sql
            )
            params_by_name = [evidence_id, scan_id, query, *filter_params]
            params_by_path = [evidence_id, scan_id, query, *filter_params]
            union_sql = (
                f"SELECT {ENTRY_COLUMNS} FROM filesystem_entries "
                f"WHERE {where_by_name} "
                "UNION "
                f"SELECT {ENTRY_COLUMNS} FROM filesystem_entries "
                f"WHERE {where_by_path}"
            )
            order_column = SORT_SQL.get(sort, SORT_SQL["path"])
            direction = "DESC" if sort_dir == "desc" else "ASC"
            offset = (page - 1) * page_size
            with self._connect() as connection:
                total = int(
                    connection.execute(
                        f"SELECT COUNT(*) AS n FROM ({union_sql})",
                        [*params_by_name, *params_by_path],
                    ).fetchone()["n"]
                )
                rows = connection.execute(
                    f"{union_sql} ORDER BY {order_column} {direction}, id "
                    "LIMIT ? OFFSET ?",
                    [
                        *params_by_name,
                        *params_by_path,
                        page_size,
                        offset,
                    ],
                ).fetchall()
                return [IndexedEntry.from_row(row) for row in rows], total

        where = "evidence_id = ? AND scan_id = ?"
        params: list[Any] = [evidence_id, scan_id]
        pattern = "%" + escape_like(query) + "%"
        where += (
            " AND (full_path LIKE ? ESCAPE '\\' "
            "OR basename LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern, pattern])
        params.extend(filter_params)
        where += filter_sql
        return self._paginated_query(
            where=where,
            params=params,
            sort=sort,
            sort_dir=sort_dir,
            page=page,
            page_size=page_size,
        )

    # ------------------------------------------------------------------
    # tree navigation
    # ------------------------------------------------------------------

    def get_entry(
        self, evidence_id: str, scan_id: str, entry_id: int
    ) -> IndexedEntry:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? AND id = ?",
                (evidence_id, scan_id, entry_id),
            ).fetchone()
            if row is None:
                raise EntryNotFoundError(
                    f"index entry {entry_id} was not found in this evidence",
                    details={"entry_id": entry_id},
                )
            return IndexedEntry.from_row(row)

    def children_of(
        self,
        evidence_id: str,
        scan_id: str,
        parent_id: int | None,
        *,
        include_deleted: bool,
        directories_only: bool,
        filter_text: str | None,
        sort: str,
        sort_dir: str,
        page: int,
        page_size: int,
    ) -> tuple[list[IndexedEntry], int]:
        where = "evidence_id = ? AND scan_id = ?"
        params: list[Any] = [evidence_id, scan_id]
        if parent_id is None:
            where += " AND parent_id IS NULL"
        else:
            where += " AND parent_id = ?"
            params.append(parent_id)
        if not include_deleted:
            where += " AND deleted = 0"
        if directories_only:
            where += " AND entry_type = 'directory'"
        if filter_text:
            where += " AND basename LIKE ? ESCAPE '\\'"
            params.append("%" + escape_like(filter_text) + "%")

        order_column = TREE_SORT_SQL.get(sort, TREE_SORT_SQL["path"])
        direction = "DESC" if sort_dir == "desc" else "ASC"
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM filesystem_entries WHERE {where}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                f"WHERE {where} "
                f"ORDER BY {order_column} {direction}, id LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows], total

    def entry_ancestors(
        self, evidence_id: str, scan_id: str, entry_id: int
    ) -> tuple[IndexedEntry, list[IndexedEntry]]:
        entry = self.get_entry(evidence_id, scan_id, entry_id)
        ancestors: list[IndexedEntry] = []
        seen: set[int] = {entry.id}
        current = entry
        while current.parent_id is not None:
            if current.parent_id in seen:
                break
            seen.add(current.parent_id)
            try:
                parent = self.get_entry(
                    evidence_id, scan_id, current.parent_id
                )
            except EntryNotFoundError:
                break
            ancestors.append(parent)
            current = parent
        ancestors.reverse()
        return entry, ancestors

    def child_directory_paths(
        self,
        evidence_id: str,
        scan_id: str,
        parent_id: int | None,
        *,
        include_deleted: bool,
    ) -> list[tuple[int, str]]:
        where = "evidence_id = ? AND scan_id = ? AND entry_type = 'directory'"
        params: list[Any] = [evidence_id, scan_id]
        if parent_id is None:
            where += " AND parent_id IS NULL"
        else:
            where += " AND parent_id = ?"
            params.append(parent_id)
        if not include_deleted:
            where += " AND deleted = 0"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT id, full_path FROM filesystem_entries WHERE {where}",
                params,
            ).fetchall()
            return [(int(row["id"]), str(row["full_path"])) for row in rows]

    def child_page_of(
        self,
        evidence_id: str,
        scan_id: str,
        parent_id: int,
        child_id: int,
        page_size: int,
    ) -> int:
        """1-indexed page containing ``child_id`` in the default tree order."""
        child = self.get_entry(evidence_id, scan_id, child_id)
        with self._connect() as connection:
            position = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM filesystem_entries "
                    "WHERE evidence_id = ? AND scan_id = ? AND parent_id = ? "
                    "AND (basename COLLATE NOCASE < ? COLLATE NOCASE "
                    "OR (basename COLLATE NOCASE = ? COLLATE NOCASE AND id < ?))",
                    (
                        evidence_id,
                        scan_id,
                        parent_id,
                        child.basename,
                        child.basename,
                        child.id,
                    ),
                ).fetchone()["n"]
            )
        return max(1, (position // page_size) + 1)

    def get_entry_by_path(
        self, evidence_id: str, scan_id: str, full_path: str
    ) -> IndexedEntry:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? AND full_path = ? "
                "ORDER BY deleted, entry_type = 'directory' DESC, id LIMIT 1",
                (evidence_id, scan_id, full_path),
            ).fetchone()
            if row is None:
                raise EntryNotFoundError(
                    "index path was not found in this evidence",
                    details={"path": full_path},
                )
            return IndexedEntry.from_row(row)


    # ------------------------------------------------------------------
    # registry hive discovery helpers
    # ------------------------------------------------------------------

    REGISTRY_BASENAMES = (
        "system",
        "software",
        "sam",
        "security",
        "default",
        "ntuser.dat",
        "usrclass.dat",
        "amcache.hve",
    )

    def find_registry_candidates(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        include_deleted: bool,
    ) -> list[IndexedEntry]:
        placeholders = ",".join("?" for _ in self.REGISTRY_BASENAMES)
        where = (
            "evidence_id = ? AND scan_id = ? AND entry_type = 'file' "
            f"AND (basename COLLATE NOCASE IN ({placeholders}) "
            "OR basename COLLATE NOCASE LIKE '%.hve')"
        )
        params: list[Any] = [
            evidence_id,
            scan_id,
            *self.REGISTRY_BASENAMES,
        ]
        if not include_deleted:
            where += " AND deleted = 0"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                f"WHERE {where} ORDER BY full_path COLLATE NOCASE LIMIT 5000",
                params,
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]

    def find_transaction_logs(
        self, evidence_id: str, scan_id: str, parent_path: str, basename: str
    ) -> list[dict[str, Any]]:
        names = [f"{basename}.LOG", f"{basename}.LOG1", f"{basename}.LOG2"]
        placeholders = ",".join("?" for _ in names)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, inode, full_path, basename, size, deleted "
                "FROM filesystem_entries WHERE evidence_id = ? AND scan_id = ? "
                "AND parent_path = ? AND basename COLLATE NOCASE IN "
                f"({placeholders}) ORDER BY basename COLLATE NOCASE",
                (evidence_id, scan_id, parent_path, *names),
            ).fetchall()
            return [
                {
                    "entry_id": int(row["id"]),
                    "inode": int(row["inode"]) if row["inode"] is not None else None,
                    "name": row["basename"],
                    "path": row["full_path"],
                    "size": int(row["size"]) if row["size"] is not None else None,
                    "deleted": bool(row["deleted"]),
                }
                for row in rows
            ]


    BROWSER_NAME_PATTERNS = (
        "webcachev%.dat",
        "history",
        "places.sqlite",
        "downloads.sqlite",
    )

    CREDENTIAL_NAME_PATTERNS = (
        "Login Data",
        "Login Data For Account",
        "logins.json",
        "logins-backup.json",
        "signons.sqlite",
        "key4.db",
        "key3.db",
        "cookies.sqlite",
        "formhistory.sqlite",
        "Web Data",
        "Cookies",
        "Local State",
    )

    def find_browser_artifact_candidates(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        include_deleted: bool,
    ) -> list[IndexedEntry]:
        clauses = " OR ".join(
            "basename COLLATE NOCASE LIKE ?" for _ in self.BROWSER_NAME_PATTERNS
        )
        where = (
            "evidence_id = ? AND scan_id = ? AND entry_type = 'file' "
            f"AND ({clauses}) "
            "AND (full_path LIKE '%WebCache%' OR full_path LIKE '%User Data%' "
            "OR full_path LIKE '%Firefox%' OR full_path LIKE '%Mozilla%' "
            "OR full_path LIKE '%/.config/google-chrome/%' "
            "OR full_path LIKE '%/.config/chromium/%' "
            "OR full_path LIKE '%/.config/microsoft-edge/%' "
            "OR full_path LIKE '%/.config/BraveSoftware/%' "
            "OR full_path LIKE '%/.config/opera%' "
            "OR full_path LIKE '%Opera Software%' "
            "OR full_path LIKE '%BraveSoftware%' "
            "OR full_path LIKE '%/.mozilla/%' OR full_path LIKE '%/snap/%')"
        )
        params: list[Any] = [evidence_id, scan_id, *self.BROWSER_NAME_PATTERNS]
        if not include_deleted:
            where += " AND deleted = 0"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                f"WHERE {where} ORDER BY full_path COLLATE NOCASE LIMIT 2000",
                params,
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]

    def find_credential_artifact_candidates(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        include_deleted: bool = False,
    ) -> list[IndexedEntry]:
        clauses = " OR ".join(
            "basename COLLATE NOCASE = ?" for _ in self.CREDENTIAL_NAME_PATTERNS
        )
        where = (
            "evidence_id = ? AND scan_id = ? AND entry_type = 'file' "
            f"AND ({clauses}) "
            "AND (full_path LIKE '%User Data%' "
            "OR full_path LIKE '%Firefox%' OR full_path LIKE '%Mozilla%' "
            "OR full_path LIKE '%/.config/%' "
            "OR full_path LIKE '%Opera Software%' "
            "OR full_path LIKE '%BraveSoftware%' "
            "OR full_path LIKE '%/.mozilla/%' OR full_path LIKE '%/snap/%')"
        )
        params: list[Any] = [evidence_id, scan_id, *self.CREDENTIAL_NAME_PATTERNS]
        if not include_deleted:
            where += " AND deleted = 0"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                f"WHERE {where} ORDER BY full_path COLLATE NOCASE LIMIT 2000",
                params,
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]

    def find_entries_by_exact_path(
        self, evidence_id: str, scan_id: str, relpath: str
    ) -> list[IndexedEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? "
                "AND full_path COLLATE NOCASE = ? AND entry_type = 'file' "
                "ORDER BY deleted, id LIMIT 50",
                (evidence_id, scan_id, relpath),
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]

    def find_entries_by_basename(
        self, evidence_id: str, scan_id: str, basename: str, limit: int
    ) -> list[IndexedEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                "WHERE evidence_id = ? AND scan_id = ? "
                "AND basename COLLATE NOCASE = ? AND entry_type = 'file' "
                "ORDER BY deleted, full_path COLLATE NOCASE LIMIT ?",
                (evidence_id, scan_id, basename, max(1, int(limit))),
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]

    def find_evtx_candidates(
        self,
        evidence_id: str,
        scan_id: str,
        *,
        include_deleted: bool,
    ) -> list[IndexedEntry]:
        where = (
            "evidence_id = ? AND scan_id = ? AND entry_type = 'file' "
            "AND basename COLLATE NOCASE LIKE '%.evtx'"
        )
        params: list[Any] = [evidence_id, scan_id]
        if not include_deleted:
            where += " AND deleted = 0"
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ENTRY_COLUMNS}, parent_id FROM filesystem_entries "
                f"WHERE {where} ORDER BY full_path COLLATE NOCASE LIMIT 5000",
                params,
            ).fetchall()
            return [IndexedEntry.from_row(row) for row in rows]
