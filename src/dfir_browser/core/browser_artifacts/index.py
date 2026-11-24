from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import (
    BROWSER_SCHEMA_VERSION,
    ArtifactNotFound,
    BrowserArtifactError,
    BrowserProfileRow,
    CacheRecord,
    DownloadRecord,
    RecordPage,
    SourceArtifact,
    VisitRecord,
)
from .backends import normalize_url

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS browser_artifacts (
  artifact_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  inode INTEGER,
  evidence_path TEXT NOT NULL,
  filename TEXT NOT NULL,
  browser TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  user TEXT,
  profile_name TEXT,
  size INTEGER,
  sha256 TEXT,
  sidecars_json TEXT,
  sidecars_used_json TEXT,
  extract_relpath TEXT,
  backend TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  records_seen INTEGER NOT NULL DEFAULT 0,
  records_indexed INTEGER NOT NULL DEFAULT 0,
  parse_errors INTEGER NOT NULL DEFAULT 0,
  first_record_time TEXT,
  last_record_time TEXT,
  warnings_json TEXT,
  error_code TEXT,
  error_message TEXT,
  created_at TEXT,
  started_at TEXT,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS browser_profiles (
  profile_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  user TEXT,
  browser TEXT NOT NULL,
  profile_name TEXT,
  source_path TEXT NOT NULL,
  artifact_types_json TEXT,
  warnings_json TEXT
);
CREATE TABLE IF NOT EXISTS browser_visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  source_record_id TEXT,
  user TEXT,
  browser TEXT NOT NULL,
  url TEXT,
  url_norm TEXT,
  scheme TEXT,
  host TEXT,
  domain TEXT,
  title TEXT,
  visit_time TEXT,
  raw_timestamp TEXT,
  visit_type TEXT,
  referrer_url TEXT,
  visit_count INTEGER,
  typed_count INTEGER,
  hidden INTEGER,
  warnings_json TEXT,
  search_text TEXT
);
CREATE TABLE IF NOT EXISTS browser_downloads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  source_record_id TEXT,
  user TEXT,
  browser TEXT NOT NULL,
  start_time TEXT,
  end_time TEXT,
  start_raw TEXT,
  end_raw TEXT,
  url TEXT,
  url_norm TEXT,
  scheme TEXT,
  host TEXT,
  domain TEXT,
  final_url TEXT,
  url_chain_json TEXT,
  referrer TEXT,
  tab_url TEXT,
  target_path TEXT,
  filename TEXT,
  extension TEXT,
  received_bytes INTEGER,
  total_bytes INTEGER,
  state TEXT,
  danger_type TEXT,
  interrupt_reason TEXT,
  mime_type TEXT,
  opened INTEGER,
  hash_value TEXT,
  hash_algorithm TEXT,
  raw_metadata_json TEXT,
  warnings_json TEXT,
  search_text TEXT
);
CREATE TABLE IF NOT EXISTS browser_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  source_record_id TEXT,
  container TEXT,
  user TEXT,
  browser TEXT NOT NULL,
  url TEXT,
  url_norm TEXT,
  domain TEXT,
  local_path TEXT,
  content_type TEXT,
  created_time TEXT,
  accessed_time TEXT,
  modified_time TEXT,
  expiry_time TEXT,
  size INTEGER,
  allocated INTEGER,
  response_preview TEXT,
  warnings_json TEXT,
  search_text TEXT
);
CREATE TABLE IF NOT EXISTS browser_parse_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_id TEXT NOT NULL,
  record_id TEXT,
  error TEXT,
  created_at TEXT
);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_ba_artifacts_entry
  ON browser_artifacts(evidence_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_ba_visits_profile_time
  ON browser_visits(profile_id, visit_time);
CREATE INDEX IF NOT EXISTS idx_ba_visits_domain
  ON browser_visits(domain COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ba_downloads_profile_time
  ON browser_downloads(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_ba_downloads_domain
  ON browser_downloads(domain COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ba_downloads_state
  ON browser_downloads(state COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ba_cache_profile_time
  ON browser_cache(profile_id, accessed_time);
CREATE INDEX IF NOT EXISTS idx_ba_cache_domain
  ON browser_cache(domain COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ba_errors_artifact
  ON browser_parse_errors(artifact_id);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS browser_visits_fts USING fts5(
  text, content=''
);
CREATE VIRTUAL TABLE IF NOT EXISTS browser_downloads_fts USING fts5(
  text, content=''
);
CREATE VIRTUAL TABLE IF NOT EXISTS browser_cache_fts USING fts5(
  text, content=''
);
"""

ARTIFACT_COLUMNS = (
    "artifact_id, evidence_id, entry_id, inode, evidence_path, filename, "
    "browser, artifact_type, user, profile_name, size, sha256, sidecars_json, "
    "sidecars_used_json, extract_relpath, backend, parser_version, "
    "schema_version, status, phase, records_seen, records_indexed, "
    "parse_errors, first_record_time, last_record_time, warnings_json, "
    "error_code, error_message, created_at, started_at, completed_at"
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


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


class BrowserStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.fts_enabled = False

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
            connection.executescript(INDEX_SQL)
            try:
                connection.executescript(FTS_SQL)
                self.fts_enabled = True
            except sqlite3.Error:
                self.fts_enabled = False
            connection.execute(
                f"PRAGMA user_version = {BROWSER_SCHEMA_VERSION}"
            )

    def recover_interrupted(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE browser_artifacts SET status='interrupted', phase='ready', "
                "error_code='browser_interrupted', "
                "error_message='server restarted before the browser index finished', "
                "completed_at=? "
                "WHERE status IN ('queued','running')",
                (_now(),),
            )
            return int(cursor.rowcount or 0)

    # -- artifacts -----------------------------------------------------
    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> SourceArtifact:
        return SourceArtifact(
            artifact_id=str(row["artifact_id"]),
            evidence_id=str(row["evidence_id"]),
            entry_id=int(row["entry_id"]),
            inode=int(row["inode"]) if row["inode"] is not None else None,
            evidence_path=str(row["evidence_path"]),
            filename=str(row["filename"]),
            browser=str(row["browser"]),
            artifact_type=str(row["artifact_type"]),
            user=row["user"],
            profile_name=row["profile_name"],
            size=int(row["size"]) if row["size"] is not None else None,
            sha256=row["sha256"],
            sidecars=_loads(row["sidecars_json"], []),
            sidecars_used=_loads(row["sidecars_used_json"], []),
            extract_relpath=row["extract_relpath"],
            backend=str(row["backend"]),
            parser_version=str(row["parser_version"]),
            schema_version=int(row["schema_version"]),
            status=str(row["status"]),
            phase=str(row["phase"]),
            records_seen=int(row["records_seen"] or 0),
            records_indexed=int(row["records_indexed"] or 0),
            parse_errors=int(row["parse_errors"] or 0),
            first_record_time=row["first_record_time"],
            last_record_time=row["last_record_time"],
            warnings=_loads(row["warnings_json"], []),
            error_code=row["error_code"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
        )

    def get_artifact(self, artifact_id: str) -> SourceArtifact:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {ARTIFACT_COLUMNS} FROM browser_artifacts "
                "WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise ArtifactNotFound(
                    "browser artifact was not indexed",
                    details={"artifact_id": artifact_id},
                )
            return self._artifact_from_row(row)

    def find_by_entry(self, evidence_id: str, entry_id: int) -> SourceArtifact | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {ARTIFACT_COLUMNS} FROM browser_artifacts "
                "WHERE evidence_id = ? AND entry_id = ? ORDER BY rowid DESC LIMIT 1",
                (evidence_id, entry_id),
            ).fetchone()
            return self._artifact_from_row(row) if row is not None else None

    def list_artifacts(self, evidence_id: str) -> list[SourceArtifact]:
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {ARTIFACT_COLUMNS} FROM browser_artifacts "
                "WHERE evidence_id = ? ORDER BY evidence_path COLLATE NOCASE",
                (evidence_id,),
            ).fetchall()
            return [self._artifact_from_row(row) for row in rows]

    def upsert_artifact(self, artifact: SourceArtifact) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM browser_artifacts WHERE artifact_id = ?",
                (artifact.artifact_id,),
            )
            connection.execute(
                f"INSERT INTO browser_artifacts ({ARTIFACT_COLUMNS}) VALUES "
                "(" + ", ".join("?" for _ in ARTIFACT_COLUMNS.split(",")) + ")",
                (
                    artifact.artifact_id,
                    artifact.evidence_id,
                    artifact.entry_id,
                    artifact.inode,
                    artifact.evidence_path,
                    artifact.filename,
                    artifact.browser,
                    artifact.artifact_type,
                    artifact.user,
                    artifact.profile_name,
                    artifact.size,
                    artifact.sha256,
                    _json(artifact.sidecars),
                    _json(artifact.sidecars_used),
                    artifact.extract_relpath,
                    artifact.backend,
                    artifact.parser_version,
                    artifact.schema_version,
                    artifact.status,
                    artifact.phase,
                    artifact.records_seen,
                    artifact.records_indexed,
                    artifact.parse_errors,
                    artifact.first_record_time,
                    artifact.last_record_time,
                    _json(artifact.warnings),
                    artifact.error_code,
                    artifact.error_message,
                    artifact.created_at,
                    artifact.started_at,
                    artifact.completed_at,
                ),
            )
            connection.execute(
                "DELETE FROM browser_profiles WHERE artifact_id = ?",
                (artifact.artifact_id,),
            )
            for table in (
                "browser_visits",
                "browser_downloads",
                "browser_cache",
                "browser_parse_errors",
            ):
                connection.execute(
                    f"DELETE FROM {table} WHERE artifact_id = ?",
                    (artifact.artifact_id,),
                )
            if self.fts_enabled:
                for table in ("browser_visits", "browser_downloads", "browser_cache"):
                    connection.execute(
                        f"DELETE FROM {table}_fts WHERE rowid IN ("
                        f"SELECT id FROM {table} WHERE artifact_id = ?)",
                        (artifact.artifact_id,),
                    )

    def update_phase(self, artifact_id: str, phase: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE browser_artifacts SET status='running', phase=?, "
                "started_at=COALESCE(started_at, ?) WHERE artifact_id = ?",
                (phase, _now(), artifact_id),
            )

    def finish_artifact(self, artifact: SourceArtifact) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE browser_artifacts SET status=?, phase=?, sha256=?, size=?, "
                "sidecars_used_json=?, extract_relpath=?, records_seen=?, "
                "records_indexed=?, parse_errors=?, first_record_time=?, "
                "last_record_time=?, warnings_json=?, error_code=?, "
                "error_message=?, completed_at=? WHERE artifact_id = ?",
                (
                    artifact.status,
                    artifact.phase,
                    artifact.sha256,
                    artifact.size,
                    _json(artifact.sidecars_used),
                    artifact.extract_relpath,
                    artifact.records_seen,
                    artifact.records_indexed,
                    artifact.parse_errors,
                    artifact.first_record_time,
                    artifact.last_record_time,
                    _json(artifact.warnings),
                    artifact.error_code,
                    artifact.error_message,
                    artifact.completed_at,
                    artifact.artifact_id,
                ),
            )

    # -- profiles ------------------------------------------------------
    def upsert_profile(self, profile: BrowserProfileRow) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO browser_profiles (profile_id, "
                "evidence_id, artifact_id, user, browser, profile_name, "
                "source_path, artifact_types_json, warnings_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    profile.profile_id,
                    profile.evidence_id,
                    profile.artifact_id,
                    profile.user,
                    profile.browser,
                    profile.profile_name,
                    profile.source_path,
                    _json(profile.artifact_types),
                    _json(profile.warnings),
                ),
            )

    def list_profiles(
        self, evidence_id: str, browser: str | None = None
    ) -> list[BrowserProfileRow]:
        where = "evidence_id = ?"
        params: list[Any] = [evidence_id]
        if browser:
            where += " AND browser = ?"
            params.append(browser)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM browser_profiles WHERE " + where +
                " ORDER BY user COLLATE NOCASE, profile_name COLLATE NOCASE",
                params,
            ).fetchall()
        return [
            BrowserProfileRow(
                profile_id=str(row["profile_id"]),
                evidence_id=str(row["evidence_id"]),
                artifact_id=str(row["artifact_id"]),
                user=row["user"],
                browser=str(row["browser"]),
                profile_name=row["profile_name"],
                source_path=str(row["source_path"]),
                artifact_types=_loads(row["artifact_types_json"], []),
                warnings=_loads(row["warnings_json"], []),
            )
            for row in rows
        ]

    # -- records -------------------------------------------------------
    def insert_records(
        self,
        *,
        visits: Iterable[VisitRecord] = (),
        downloads: Iterable[DownloadRecord] = (),
        cache: Iterable[CacheRecord] = (),
    ) -> dict[str, int]:
        with self._connect() as connection:
            base_visit = int(
                connection.execute(
                    "SELECT COALESCE(MAX(id), 0) AS n FROM browser_visits"
                ).fetchone()["n"]
            )
            base_download = int(
                connection.execute(
                    "SELECT COALESCE(MAX(id), 0) AS n FROM browser_downloads"
                ).fetchone()["n"]
            )
            base_cache = int(
                connection.execute(
                    "SELECT COALESCE(MAX(id), 0) AS n FROM browser_cache"
                ).fetchone()["n"]
            )
        visit_rows = []
        next_visit = base_visit
        for item in visits:
            next_visit += 1
            search = " ".join(
                part for part in (item.url, item.title, item.host) if part
            )
            visit_rows.append(
                (
                    next_visit,
                    item.profile_id,
                    item.source_artifact_id,
                    item.source_record_id,
                    item.user,
                    item.browser,
                    item.url,
                    item.url,
                    item.scheme,
                    item.host,
                    item.registrable_domain,
                    item.title,
                    item.visit_time_utc,
                    item.raw_timestamp,
                    item.visit_type,
                    item.referrer_url,
                    item.visit_count,
                    item.typed_count,
                    (
                        1 if item.hidden else 0
                        if item.hidden is not None
                        else None
                    ),
                    _json(item.warnings),
                    search[:8192],
                )
            )
        download_rows = []
        next_download = base_download
        for item in downloads:
            next_download += 1
            search = " ".join(
                part
                for part in (
                    item.url,
                    item.final_url,
                    item.filename,
                    item.target_path,
                    item.referrer,
                    item.domain if hasattr(item, "domain") else None,
                )
                if part
            )
            ext = None
            if item.filename and "." in item.filename:
                ext = item.filename.rsplit(".", 1)[-1].lower()[:16]
            parsed = normalize_url(item.url, 8192)
            download_rows.append(
                (
                    next_download,
                    item.profile_id,
                    item.source_artifact_id,
                    item.source_record_id,
                    item.user,
                    item.browser,
                    item.start_time_utc,
                    item.end_time_utc,
                    item.start_raw,
                    item.end_raw,
                    item.url,
                    item.url,
                    parsed["scheme"],
                    parsed["host"],
                    parsed["registrable_domain"],
                    item.final_url,
                    _json(item.url_chain),
                    item.referrer,
                    item.tab_url,
                    item.target_path,
                    item.filename,
                    ext,
                    item.received_bytes,
                    item.total_bytes,
                    item.state,
                    item.danger_type,
                    item.interrupt_reason,
                    item.mime_type,
                    (
                        1 if item.opened else 0 if item.opened is not None else None
                    ),
                    item.hash_value,
                    item.hash_algorithm,
                    _json(item.raw_metadata),
                    _json(item.warnings),
                    search[:8192],
                )
            )
        cache_rows = []
        next_cache = base_cache
        for item in cache:
            next_cache += 1
            search = " ".join(
                part
                for part in (item.url, item.local_path, item.content_type)
                if part
            )
            parsed = normalize_url(item.url, 8192)
            cache_rows.append(
                (
                    next_cache,
                    item.profile_id,
                    item.source_artifact_id,
                    item.source_record_id,
                    item.container,
                    item.user,
                    item.browser,
                    item.url,
                    item.url,
                    parsed["registrable_domain"],
                    item.local_path,
                    item.content_type,
                    item.created_time_utc,
                    item.accessed_time_utc,
                    item.modified_time_utc,
                    item.expiry_time_utc,
                    item.size,
                    (
                        1
                        if item.allocated
                        else 0
                        if item.allocated is not None
                        else None
                    ),
                    item.response_preview,
                    _json(item.warnings),
                    search[:8192],
                )
            )
        with self._connect() as connection:
            if visit_rows:
                connection.executemany(
                    "INSERT INTO browser_visits (id, profile_id, artifact_id, "
                    "source_record_id, user, browser, url, url_norm, scheme, host, "
                    "domain, title, visit_time, raw_timestamp, visit_type, "
                    "referrer_url, visit_count, typed_count, hidden, "
                    "warnings_json, search_text) VALUES ("
                    + ", ".join("?" for _ in range(21)) + ")",
                    visit_rows,
                )
            if download_rows:
                connection.executemany(
                    "INSERT INTO browser_downloads (id, profile_id, artifact_id, "
                    "source_record_id, user, browser, start_time, end_time, "
                    "start_raw, end_raw, url, url_norm, scheme, host, domain, "
                    "final_url, url_chain_json, referrer, tab_url, target_path, "
                    "filename, extension, received_bytes, total_bytes, state, "
                    "danger_type, interrupt_reason, mime_type, opened, hash_value, "
                    "hash_algorithm, raw_metadata_json, warnings_json, search_text"
                    ") VALUES (" + ", ".join("?" for _ in range(34)) + ")",
                    download_rows,
                )
            if cache_rows:
                connection.executemany(
                    "INSERT INTO browser_cache (id, profile_id, artifact_id, "
                    "source_record_id, container, user, browser, url, url_norm, "
                    "domain, local_path, content_type, created_time, accessed_time, "
                    "modified_time, expiry_time, size, allocated, response_preview, "
                    "warnings_json, search_text) VALUES ("
                    + ", ".join("?" for _ in range(21)) + ")",
                    cache_rows,
                )
            if self.fts_enabled:
                if visit_rows:
                    connection.executemany(
                        "INSERT INTO browser_visits_fts (rowid, text) "
                        "VALUES (?, ?)",
                        [(row[0], row[20]) for row in visit_rows],
                    )
                if download_rows:
                    connection.executemany(
                        "INSERT INTO browser_downloads_fts (rowid, text) "
                        "VALUES (?, ?)",
                        [(row[0], row[33]) for row in download_rows],
                    )
                if cache_rows:
                    connection.executemany(
                        "INSERT INTO browser_cache_fts (rowid, text) "
                        "VALUES (?, ?)",
                        [(row[0], row[20]) for row in cache_rows],
                    )
        return {
            "visits": len(visit_rows),
            "downloads": len(download_rows),
            "cache": len(cache_rows),
        }

    def insert_errors(
        self, artifact_id: str, rows: Iterable[tuple[str | None, str]]
    ) -> None:
        payload = [
            (artifact_id, record_id, error[:500], _now())
            for record_id, error in rows
        ]
        if not payload:
            return
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO browser_parse_errors (artifact_id, record_id, "
                "error, created_at) VALUES (?, ?, ?, ?)",
                payload,
            )

    # -- queries -------------------------------------------------------
    def query_downloads(
        self,
        *,
        evidence_id: str,
        profile_ids: list[str] | None,
        query: str | None,
        domain: str | None,
        filename: str | None,
        extension: str | None,
        state: str | None,
        time_from: str | None,
        time_to: str | None,
        executable_only: bool,
        include_query_string: bool,
        page: int,
        page_size: int,
        sort_dir: str = "desc",
    ) -> RecordPage:
        where: list[str] = [
            "artifact_id IN (SELECT artifact_id FROM browser_artifacts "
            "WHERE evidence_id = ?)"
        ]
        params: list[Any] = [evidence_id]
        if profile_ids:
            where.append(
                "profile_id IN (" + ", ".join("?" for _ in profile_ids) + ")"
            )
            params.extend(profile_ids)
        if domain:
            where.append("domain COLLATE NOCASE = ?")
            params.append(domain.lower())
        if filename:
            where.append(
                "(filename LIKE ? ESCAPE '\\' OR target_path LIKE ? ESCAPE '\\')"
            )
            needle = f"%{escape_like(filename)}%"
            params.extend([needle, needle])
        if extension:
            where.append("extension COLLATE NOCASE = ?")
            params.append(extension.lower().lstrip("."))
        if state:
            where.append("state COLLATE NOCASE = ?")
            params.append(state.lower())
        if time_from:
            where.append("start_time >= ?")
            params.append(time_from)
        if time_to:
            where.append("start_time <= ?")
            params.append(time_to)
        if executable_only:
            where.append(
                "extension IN ('exe','dll','msi','scr','com','bat','cmd',"
                "'ps1','js','vbs','hta','zip','rar','7z','iso','img')"
            )
        if query:
            if self.fts_enabled:
                match = _fts_query(query)
                if match:
                    where.append(
                        "id IN (SELECT rowid FROM browser_downloads_fts "
                        "WHERE browser_downloads_fts MATCH ?)"
                    )
                    params.append(match)
            else:
                where.append("search_text LIKE ? ESCAPE '\\'")
                params.append(f"%{escape_like(query)}%")
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        order = "DESC" if sort_dir == "desc" else "ASC"
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM browser_downloads{clause}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM browser_downloads"
                f"{clause} ORDER BY start_time {order}, id {order} "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        items = [self._download_row(row, include_query_string) for row in rows]
        return RecordPage(
            kind="downloads",
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            sort_dir=sort_dir,
        )

    @staticmethod
    def _clip_url(url: str | None, include_query: bool) -> str | None:
        if not url or include_query:
            return url
        from urllib.parse import urlsplit, urlunsplit

        try:
            parts = urlsplit(url)
        except ValueError:
            return url
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, "", "")
        )

    def _download_row(self, row: sqlite3.Row, include_query: bool) -> dict[str, Any]:
        data = {
            "trust": "untrusted_evidence_data",
            "download_id": int(row["id"]),
            "profile_id": row["profile_id"],
            "source_artifact_id": row["artifact_id"],
            "source_record_id": row["source_record_id"],
            "user": row["user"],
            "browser": row["browser"],
            "start_time_utc": row["start_time"],
            "end_time_utc": row["end_time"],
            "scheme": row["scheme"],
            "host": row["host"],
            "domain": row["domain"],
            "url": self._clip_url(row["url"], include_query),
            "final_url": self._clip_url(row["final_url"], include_query),
            "url_chain": [
                self._clip_url(item, include_query)
                for item in _loads(row["url_chain_json"], [])
            ],
            "referrer": self._clip_url(row["referrer"], include_query),
            "tab_url": self._clip_url(row["tab_url"], include_query),
            "target_path": row["target_path"],
            "filename": row["filename"],
            "extension": row["extension"],
            "received_bytes": row["received_bytes"],
            "total_bytes": row["total_bytes"],
            "state": row["state"],
            "danger_type": row["danger_type"],
            "interrupt_reason": row["interrupt_reason"],
            "mime_type": row["mime_type"],
            "opened": (
                bool(row["opened"]) if row["opened"] is not None else None
            ),
            "hash_value": row["hash_value"],
            "hash_algorithm": row["hash_algorithm"],
            "warnings": _loads(row["warnings_json"], []),
        }
        return data

    def query_visits(
        self,
        *,
        evidence_id: str,
        profile_ids: list[str] | None,
        query: str | None,
        domain: str | None,
        time_from: str | None,
        time_to: str | None,
        include_query_string: bool,
        page: int,
        page_size: int,
        sort_dir: str = "desc",
    ) -> RecordPage:
        where: list[str] = [
            "artifact_id IN (SELECT artifact_id FROM browser_artifacts "
            "WHERE evidence_id = ?)"
        ]
        params: list[Any] = [evidence_id]
        if profile_ids:
            where.append(
                "profile_id IN (" + ", ".join("?" for _ in profile_ids) + ")"
            )
            params.extend(profile_ids)
        if domain:
            where.append("domain COLLATE NOCASE = ?")
            params.append(domain.lower())
        if time_from:
            where.append("visit_time >= ?")
            params.append(time_from)
        if time_to:
            where.append("visit_time <= ?")
            params.append(time_to)
        if query:
            if self.fts_enabled:
                match = _fts_query(query)
                if match:
                    where.append(
                        "id IN (SELECT rowid FROM browser_visits_fts "
                        "WHERE browser_visits_fts MATCH ?)"
                    )
                    params.append(match)
            else:
                where.append("search_text LIKE ? ESCAPE '\\'")
                params.append(f"%{escape_like(query)}%")
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        order = "DESC" if sort_dir == "desc" else "ASC"
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM browser_visits{clause}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM browser_visits"
                f"{clause} ORDER BY visit_time {order}, id {order} "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        items = [
            {
                "trust": "untrusted_evidence_data",
                "visit_id": int(row["id"]),
                "profile_id": row["profile_id"],
                "source_artifact_id": row["artifact_id"],
                "source_record_id": row["source_record_id"],
                "user": row["user"],
                "browser": row["browser"],
                "url": self._clip_url(row["url"], include_query_string),
                "scheme": row["scheme"],
                "host": row["host"],
                "domain": row["domain"],
                "title": row["title"],
                "visit_time_utc": row["visit_time"],
                "raw_timestamp": row["raw_timestamp"],
                "visit_type": row["visit_type"],
                "referrer_url": self._clip_url(
                    row["referrer_url"], include_query_string
                ),
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "hidden": (
                    bool(row["hidden"]) if row["hidden"] is not None else None
                ),
                "warnings": _loads(row["warnings_json"], []),
            }
            for row in rows
        ]
        return RecordPage(
            kind="history",
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            sort_dir=sort_dir,
        )

    def query_cache(
        self,
        *,
        evidence_id: str,
        profile_ids: list[str] | None,
        query: str | None,
        domain: str | None,
        time_from: str | None,
        time_to: str | None,
        include_query_string: bool,
        page: int,
        page_size: int,
        sort_dir: str = "desc",
    ) -> RecordPage:
        where: list[str] = [
            "artifact_id IN (SELECT artifact_id FROM browser_artifacts "
            "WHERE evidence_id = ?)"
        ]
        params: list[Any] = [evidence_id]
        if profile_ids:
            where.append(
                "profile_id IN (" + ", ".join("?" for _ in profile_ids) + ")"
            )
            params.extend(profile_ids)
        if domain:
            where.append("domain COLLATE NOCASE = ?")
            params.append(domain.lower())
        if time_from:
            where.append("accessed_time >= ?")
            params.append(time_from)
        if time_to:
            where.append("accessed_time <= ?")
            params.append(time_to)
        if query:
            if self.fts_enabled:
                match = _fts_query(query)
                if match:
                    where.append(
                        "id IN (SELECT rowid FROM browser_cache_fts "
                        "WHERE browser_cache_fts MATCH ?)"
                    )
                    params.append(match)
            else:
                where.append("search_text LIKE ? ESCAPE '\\'")
                params.append(f"%{escape_like(query)}%")
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        order = "DESC" if sort_dir == "desc" else "ASC"
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM browser_cache{clause}", params
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM browser_cache"
                f"{clause} ORDER BY accessed_time {order}, id {order} "
                "LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        items = [
            {
                "trust": "untrusted_evidence_data",
                "cache_id": int(row["id"]),
                "profile_id": row["profile_id"],
                "source_artifact_id": row["artifact_id"],
                "source_record_id": row["source_record_id"],
                "container": row["container"],
                "user": row["user"],
                "browser": row["browser"],
                "url": self._clip_url(row["url"], include_query_string),
                "domain": row["domain"],
                "local_path": row["local_path"],
                "content_type": row["content_type"],
                "created_time_utc": row["created_time"],
                "accessed_time_utc": row["accessed_time"],
                "modified_time_utc": row["modified_time"],
                "expiry_time_utc": row["expiry_time"],
                "size": row["size"],
                "allocated": (
                    bool(row["allocated"]) if row["allocated"] is not None else None
                ),
                "response_preview": row["response_preview"],
                "warnings": _loads(row["warnings_json"], []),
            }
            for row in rows
        ]
        return RecordPage(
            kind="cache",
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            sort_dir=sort_dir,
        )

    def get_record(self, record_type: str, record_id: int) -> dict[str, Any]:
        with self._connect() as connection:
            if record_type == "download":
                row = connection.execute(
                    "SELECT * FROM browser_downloads WHERE id = ?", (record_id,)
                ).fetchone()
                if row is None:
                    raise BrowserArtifactError(
                        "download record not found", code="browser_record_not_found"
                    )
                return self._download_row(row, True)
            if record_type == "visit":
                row = connection.execute(
                    "SELECT * FROM browser_visits WHERE id = ?", (record_id,)
                ).fetchone()
                if row is None:
                    raise BrowserArtifactError(
                        "visit record not found", code="browser_record_not_found"
                    )
                return {
                    "trust": "untrusted_evidence_data",
                    "record_type": "visit",
                    "visit_id": int(row["id"]),
                    "profile_id": row["profile_id"],
                    "source_artifact_id": row["artifact_id"],
                    "source_record_id": row["source_record_id"],
                    "url": row["url"],
                    "scheme": row["scheme"],
                    "host": row["host"],
                    "domain": row["domain"],
                    "title": row["title"],
                    "visit_time_utc": row["visit_time"],
                    "raw_timestamp": row["raw_timestamp"],
                    "visit_type": row["visit_type"],
                    "referrer_url": row["referrer_url"],
                    "visit_count": row["visit_count"],
                    "typed_count": row["typed_count"],
                    "hidden": (
                        bool(row["hidden"]) if row["hidden"] is not None else None
                    ),
                    "warnings": _loads(row["warnings_json"], []),
                }
            if record_type == "cache":
                row = connection.execute(
                    "SELECT * FROM browser_cache WHERE id = ?", (record_id,)
                ).fetchone()
                if row is None:
                    raise BrowserArtifactError(
                        "cache record not found", code="browser_record_not_found"
                    )
                return {
                    "trust": "untrusted_evidence_data",
                    "record_type": "cache",
                    "cache_id": int(row["id"]),
                    "profile_id": row["profile_id"],
                    "source_artifact_id": row["artifact_id"],
                    "container": row["container"],
                    "url": row["url"],
                    "domain": row["domain"],
                    "local_path": row["local_path"],
                    "content_type": row["content_type"],
                    "created_time_utc": row["created_time"],
                    "accessed_time_utc": row["accessed_time"],
                    "modified_time_utc": row["modified_time"],
                    "expiry_time_utc": row["expiry_time"],
                    "size": row["size"],
                    "allocated": (
                        bool(row["allocated"])
                        if row["allocated"] is not None
                        else None
                    ),
                    "warnings": _loads(row["warnings_json"], []),
                }
        raise BrowserArtifactError(
            "unknown record type", code="browser_invalid_record_type"
        )

    def get_download(self, download_id: int) -> dict[str, Any]:
        return self.get_record("download", download_id)

    def stats(self) -> dict[str, int]:
        with self._connect() as connection:
            return {
                "artifacts": int(
                    connection.execute(
                        "SELECT COUNT(*) AS n FROM browser_artifacts"
                    ).fetchone()["n"]
                ),
                "profiles": int(
                    connection.execute(
                        "SELECT COUNT(*) AS n FROM browser_profiles"
                    ).fetchone()["n"]
                ),
                "visits": int(
                    connection.execute(
                        "SELECT COUNT(*) AS n FROM browser_visits"
                    ).fetchone()["n"]
                ),
                "downloads": int(
                    connection.execute(
                        "SELECT COUNT(*) AS n FROM browser_downloads"
                    ).fetchone()["n"]
                ),
                "cache": int(
                    connection.execute(
                        "SELECT COUNT(*) AS n FROM browser_cache"
                    ).fetchone()["n"]
                ),
            }


_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:\\\\/%@-]{1,63}")


def _fts_query(text: str) -> str | None:
    tokens = [
        token
        for token in _TOKEN_RE.findall(text or "")
        if any(char.isalnum() for char in token)
    ]
    if not tokens:
        return None
    return " AND ".join('"' + token.replace('"', "") + '"' for token in tokens[:16])
