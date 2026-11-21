from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import (
    EVTX_SCHEMA_VERSION,
    ActivitySummary,
    EventPage,
    EventQuery,
    EvtxEvent,
    EvtxLog,
    EvtxLogNotFound,
    EvtxError,
)
from .detector import level_name

LOG_COLUMNS = (
    "log_id, evidence_id, entry_id, inode, evidence_path, filename, "
    "detected_channel, size, sha256, allocated, deleted, parser, "
    "parser_version, index_schema, status, phase, records_seen, "
    "records_indexed, parse_errors, first_event_time, last_event_time, "
    "extract_relpath, warnings_json, error_code, error_message, created_at, "
    "started_at, completed_at"
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS evtx_logs (
  log_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  inode INTEGER,
  evidence_path TEXT NOT NULL,
  filename TEXT NOT NULL,
  detected_channel TEXT,
  size INTEGER,
  sha256 TEXT,
  allocated INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  parser TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  index_schema INTEGER NOT NULL,
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  records_seen INTEGER NOT NULL DEFAULT 0,
  records_indexed INTEGER NOT NULL DEFAULT 0,
  parse_errors INTEGER NOT NULL DEFAULT 0,
  first_event_time TEXT,
  last_event_time TEXT,
  extract_relpath TEXT,
  warnings_json TEXT,
  error_code TEXT,
  error_message TEXT,
  created_at TEXT,
  started_at TEXT,
  completed_at TEXT
);
CREATE TABLE IF NOT EXISTS evtx_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL,
  record_id INTEGER NOT NULL,
  chunk_number INTEGER,
  timestamp_utc TEXT,
  timestamp_raw TEXT,
  channel TEXT,
  provider_name TEXT,
  provider_guid TEXT,
  event_id INTEGER,
  event_id_raw TEXT,
  qualifiers INTEGER,
  level INTEGER,
  level_name TEXT,
  task INTEGER,
  opcode INTEGER,
  keywords TEXT,
  computer TEXT,
  user_sid TEXT,
  process_id INTEGER,
  thread_id INTEGER,
  activity_id TEXT,
  related_activity_id TEXT,
  version INTEGER,
  event_data_json TEXT,
  user_data TEXT,
  rendering_info TEXT,
  message TEXT,
  message_status TEXT,
  summary TEXT,
  truncated INTEGER NOT NULL DEFAULT 0,
  warnings_json TEXT,
  raw_xml TEXT,
  raw_xml_sha256 TEXT,
  search_text TEXT
);
CREATE TABLE IF NOT EXISTS evtx_parse_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL,
  record_id INTEGER,
  error TEXT,
  created_at TEXT
);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_evtx_logs_entry
  ON evtx_logs(evidence_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_evtx_events_log_time
  ON evtx_events(log_id, timestamp_utc, record_id);
CREATE INDEX IF NOT EXISTS idx_evtx_events_event_id
  ON evtx_events(log_id, event_id);
CREATE INDEX IF NOT EXISTS idx_evtx_events_channel
  ON evtx_events(channel COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_evtx_events_provider
  ON evtx_events(provider_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_evtx_events_record
  ON evtx_events(log_id, record_id);
CREATE INDEX IF NOT EXISTS idx_evtx_events_computer
  ON evtx_events(computer COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_evtx_events_sid
  ON evtx_events(user_sid COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_evtx_errors_log
  ON evtx_parse_errors(log_id);
"""

FTS_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS evtx_events_fts USING fts5(
  search_text,
  content='evtx_events',
  content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS evtx_events_ai AFTER INSERT ON evtx_events BEGIN
  INSERT INTO evtx_events_fts(rowid, search_text)
  VALUES (new.id, new.search_text);
END;
CREATE TRIGGER IF NOT EXISTS evtx_events_ad AFTER DELETE ON evtx_events BEGIN
  INSERT INTO evtx_events_fts(evtx_events_fts, rowid, search_text)
  VALUES ('delete', old.id, old.search_text);
END;
CREATE TRIGGER IF NOT EXISTS evtx_events_au AFTER UPDATE ON evtx_events BEGIN
  INSERT INTO evtx_events_fts(evtx_events_fts, rowid, search_text)
  VALUES ('delete', old.id, old.search_text);
  INSERT INTO evtx_events_fts(rowid, search_text)
  VALUES (new.id, new.search_text);
END;
"""

SORT_FIELDS = {"timestamp": "timestamp_utc", "record_id": "record_id", "event_id": "event_id"}


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


class EvtxStore:
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
            connection.execute(f"PRAGMA user_version = {EVTX_SCHEMA_VERSION}")

    def recover_interrupted(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE evtx_logs SET status='interrupted', phase='ready', "
                "error_code='evtx_interrupted', "
                "error_message='server restarted before the EVTX index finished', "
                "completed_at=datetime('now') "
                "WHERE status IN ('queued','running')"
            )
            return int(cursor.rowcount or 0)

    # -- logs ----------------------------------------------------------
    def _log_from_row(self, row: sqlite3.Row) -> EvtxLog:
        return EvtxLog(
            log_id=str(row["log_id"]),
            evidence_id=str(row["evidence_id"]),
            entry_id=int(row["entry_id"]),
            inode=int(row["inode"]) if row["inode"] is not None else None,
            evidence_path=str(row["evidence_path"]),
            filename=str(row["filename"]),
            detected_channel=str(row["detected_channel"] or ""),
            size=int(row["size"]) if row["size"] is not None else None,
            sha256=row["sha256"],
            allocated=bool(row["allocated"]),
            deleted=bool(row["deleted"]),
            parser=str(row["parser"]),
            parser_version=str(row["parser_version"]),
            index_schema=int(row["index_schema"]),
            status=str(row["status"]),
            phase=str(row["phase"]),
            records_seen=int(row["records_seen"] or 0),
            records_indexed=int(row["records_indexed"] or 0),
            parse_errors=int(row["parse_errors"] or 0),
            first_event_time=row["first_event_time"],
            last_event_time=row["last_event_time"],
            extract_relpath=row["extract_relpath"],
            warnings=_loads(row["warnings_json"], []),
            error_code=row["error_code"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
        )

    def get_log(self, log_id: str) -> EvtxLog:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {LOG_COLUMNS} FROM evtx_logs WHERE log_id = ?",
                (log_id,),
            ).fetchone()
            if row is None:
                raise EvtxLogNotFound(
                    "EVTX log has not been indexed", details={"log_id": log_id}
                )
            return self._log_from_row(row)

    def find_by_entry(self, evidence_id: str, entry_id: int) -> EvtxLog | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {LOG_COLUMNS} FROM evtx_logs "
                "WHERE evidence_id = ? AND entry_id = ? ORDER BY rowid DESC LIMIT 1",
                (evidence_id, entry_id),
            ).fetchone()
            return self._log_from_row(row) if row is not None else None

    def list_for_evidence(self, evidence_id: str) -> list[EvtxLog]:
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {LOG_COLUMNS} FROM evtx_logs WHERE evidence_id = ? "
                "ORDER BY filename COLLATE NOCASE",
                (evidence_id,),
            ).fetchall()
            return [self._log_from_row(row) for row in rows]

    def upsert_log(self, log: EvtxLog) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM evtx_logs WHERE log_id = ?", (log.log_id,)
            )
            connection.execute(
                f"INSERT INTO evtx_logs ({LOG_COLUMNS}) VALUES "
                "(" + ", ".join("?" for _ in LOG_COLUMNS.split(",")) + ")",
                (
                    log.log_id,
                    log.evidence_id,
                    log.entry_id,
                    log.inode,
                    log.evidence_path,
                    log.filename,
                    log.detected_channel,
                    log.size,
                    log.sha256,
                    1 if log.allocated else 0,
                    1 if log.deleted else 0,
                    log.parser,
                    log.parser_version,
                    log.index_schema,
                    log.status,
                    log.phase,
                    log.records_seen,
                    log.records_indexed,
                    log.parse_errors,
                    log.first_event_time,
                    log.last_event_time,
                    log.extract_relpath,
                    _json(log.warnings),
                    log.error_code,
                    log.error_message,
                    log.created_at,
                    log.started_at,
                    log.completed_at,
                ),
            )
            connection.execute(
                "DELETE FROM evtx_events WHERE log_id = ?", (log.log_id,)
            )
            connection.execute(
                "DELETE FROM evtx_parse_errors WHERE log_id = ?", (log.log_id,)
            )

    def update_phase(self, log_id: str, phase: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE evtx_logs SET status='running', phase=?, "
                "started_at=COALESCE(started_at, datetime('now')) "
                "WHERE log_id = ?",
                (phase, log_id),
            )

    def finish_log(self, log: EvtxLog) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE evtx_logs SET status=?, phase=?, sha256=?, size=?, "
                "extract_relpath=?, records_seen=?, records_indexed=?, "
                "parse_errors=?, first_event_time=?, last_event_time=?, "
                "warnings_json=?, error_code=?, error_message=?, completed_at=? "
                "WHERE log_id = ?",
                (
                    log.status,
                    log.phase,
                    log.sha256,
                    log.size,
                    log.extract_relpath,
                    log.records_seen,
                    log.records_indexed,
                    log.parse_errors,
                    log.first_event_time,
                    log.last_event_time,
                    _json(log.warnings),
                    log.error_code,
                    log.error_message,
                    log.completed_at,
                    log.log_id,
                ),
            )

    # -- events --------------------------------------------------------
    def insert_events(
        self, log_id: str, events: Iterable[EvtxEvent]
    ) -> int:
        rows = []
        for event in events:
            search_text = " ".join(
                part
                for part in (
                    event.channel,
                    event.provider_name,
                    event.computer,
                    event.summary,
                    event.message,
                    _json(event.event_data),
                    event.user_data,
                )
                if part
            )
            rows.append(
                (
                    log_id,
                    event.record_id,
                    event.chunk_number,
                    event.timestamp_utc,
                    event.timestamp_raw,
                    event.channel,
                    event.provider_name,
                    event.provider_guid,
                    event.event_id,
                    event.event_id_raw,
                    event.qualifiers,
                    event.level,
                    event.level_name,
                    event.task,
                    event.opcode,
                    event.keywords,
                    event.computer,
                    event.user_sid,
                    event.process_id,
                    event.thread_id,
                    event.activity_id,
                    event.related_activity_id,
                    event.version,
                    _json(event.event_data),
                    event.user_data,
                    event.rendering_info,
                    event.message,
                    event.message_status,
                    event.summary,
                    1 if event.truncated else 0,
                    _json(event.parse_warnings),
                    event.raw_xml,
                    event.raw_xml_sha256,
                    search_text[:8192],
                )
            )
        if not rows:
            return 0
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO evtx_events (log_id, record_id, chunk_number, "
                "timestamp_utc, timestamp_raw, channel, provider_name, "
                "provider_guid, event_id, event_id_raw, qualifiers, level, "
                "level_name, task, opcode, keywords, computer, user_sid, "
                "process_id, thread_id, activity_id, related_activity_id, "
                "version, event_data_json, user_data, rendering_info, message, "
                "message_status, summary, truncated, warnings_json, raw_xml, "
                "raw_xml_sha256, search_text) VALUES ("
                + ", ".join("?" for _ in range(34))
                + ")",
                rows,
            )
        return len(rows)

    def insert_parse_errors(
        self, log_id: str, rows: Iterable[tuple[int | None, str]]
    ) -> None:
        payload = [
            (log_id, record_id, error[:500], _now()) for record_id, error in rows
        ]
        if not payload:
            return
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO evtx_parse_errors (log_id, record_id, error, "
                "created_at) VALUES (?, ?, ?, ?)",
                payload,
            )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> EvtxEvent:
        return EvtxEvent(
            log_id=str(row["log_id"]),
            record_id=int(row["record_id"]),
            chunk_number=(
                int(row["chunk_number"]) if row["chunk_number"] is not None else None
            ),
            timestamp_utc=row["timestamp_utc"],
            timestamp_raw=row["timestamp_raw"],
            channel=row["channel"],
            provider_name=row["provider_name"],
            provider_guid=row["provider_guid"],
            event_id=int(row["event_id"]) if row["event_id"] is not None else None,
            event_id_raw=row["event_id_raw"],
            qualifiers=(
                int(row["qualifiers"]) if row["qualifiers"] is not None else None
            ),
            level=int(row["level"]) if row["level"] is not None else None,
            level_name=row["level_name"],
            task=int(row["task"]) if row["task"] is not None else None,
            opcode=int(row["opcode"]) if row["opcode"] is not None else None,
            keywords=row["keywords"],
            computer=row["computer"],
            user_sid=row["user_sid"],
            process_id=(
                int(row["process_id"]) if row["process_id"] is not None else None
            ),
            thread_id=(
                int(row["thread_id"]) if row["thread_id"] is not None else None
            ),
            activity_id=row["activity_id"],
            related_activity_id=row["related_activity_id"],
            version=int(row["version"]) if row["version"] is not None else None,
            event_data=_loads(row["event_data_json"], {}),
            user_data=row["user_data"],
            rendering_info=row["rendering_info"],
            message=row["message"],
            message_status=str(row["message_status"] or "message_unavailable"),
            raw_xml=row["raw_xml"],
            raw_xml_sha256=row["raw_xml_sha256"],
            summary=row["summary"],
            truncated=bool(row["truncated"]),
            parse_warnings=_loads(row["warnings_json"], []),
        )

    def get_event(self, log_id: str, record_id: int) -> EvtxEvent:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM evtx_events WHERE log_id = ? AND record_id = ?",
                (log_id, record_id),
            ).fetchone()
            if row is None:
                raise EvtxLogNotFound(
                    "event was not found in this log",
                    details={"log_id": log_id, "record_id": record_id},
                )
            return self._event_from_row(row)

    def query_events(self, query: EventQuery) -> EventPage:
        where: list[str] = []
        params: list[Any] = []
        if query.log_ids:
            where.append(
                "log_id IN (" + ", ".join("?" for _ in query.log_ids) + ")"
            )
            params.extend(query.log_ids)
        if query.channels:
            where.append(
                "channel COLLATE NOCASE IN ("
                + ", ".join("?" for _ in query.channels)
                + ")"
            )
            params.extend(query.channels)
        if query.providers:
            where.append(
                "provider_name COLLATE NOCASE IN ("
                + ", ".join("?" for _ in query.providers)
                + ")"
            )
            params.extend(query.providers)
        if query.event_ids:
            where.append(
                "event_id IN (" + ", ".join("?" for _ in query.event_ids) + ")"
            )
            params.extend(query.event_ids)
        if query.levels:
            where.append(
                "level IN (" + ", ".join("?" for _ in query.levels) + ")"
            )
            params.extend(query.levels)
        if query.user_sid:
            where.append("user_sid COLLATE NOCASE = ?")
            params.append(query.user_sid)
        if query.computer:
            where.append("computer COLLATE NOCASE = ?")
            params.append(query.computer)
        if query.process_id is not None:
            where.append("process_id = ?")
            params.append(query.process_id)
        if query.time_from:
            where.append("timestamp_utc >= ?")
            params.append(query.time_from)
        if query.time_to:
            where.append("timestamp_utc <= ?")
            params.append(query.time_to)

        fts_join = ""
        if query.text and self.fts_enabled:
            match = _fts_query(query.text)
            if match:
                fts_join = (
                    " AND id IN (SELECT rowid FROM evtx_events_fts "
                    "WHERE evtx_events_fts MATCH ?)"
                )
                params.append(match)
        elif query.text:
            where.append(
                "(search_text LIKE ? ESCAPE '\\' OR raw_xml LIKE ? ESCAPE '\\')"
            )
            needle = f"%{escape_like(query.text)}%"
            params.extend([needle, needle])

        clause = (" WHERE " + " AND ".join(where)) if where else ""
        if fts_join:
            clause += fts_join
        order = "DESC" if query.sort_dir == "desc" else "ASC"
        offset = (query.page - 1) * query.page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM evtx_events{clause}", params
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT * FROM evtx_events"
                f"{clause} ORDER BY timestamp_utc {order}, record_id {order} "
                "LIMIT ? OFFSET ?",
                [*params, query.page_size, offset],
            ).fetchall()
        return EventPage(
            events=[self._event_from_row(row) for row in rows],
            total=total,
            page=query.page,
            page_size=query.page_size,
            sort_dir=query.sort_dir,
            log_ids=list(query.log_ids),
        )

    def context(
        self, log_id: str, record_id: int, before: int, after: int
    ) -> list[EvtxEvent]:
        with self._connect() as connection:
            target = connection.execute(
                "SELECT timestamp_utc, id FROM evtx_events "
                "WHERE log_id = ? AND record_id = ?",
                (log_id, record_id),
            ).fetchone()
            if target is None:
                return []
            before_rows = connection.execute(
                "SELECT * FROM evtx_events WHERE log_id = ? AND id < ? "
                "ORDER BY id DESC LIMIT ?",
                (log_id, int(target["id"]), before),
            ).fetchall()
            after_rows = connection.execute(
                "SELECT * FROM evtx_events WHERE log_id = ? AND id > ? "
                "ORDER BY id ASC LIMIT ?",
                (log_id, int(target["id"]), after),
            ).fetchall()
            middle = connection.execute(
                "SELECT * FROM evtx_events WHERE log_id = ? AND id = ?",
                (log_id, int(target["id"])),
            ).fetchone()
        rows = list(reversed(before_rows)) + ([middle] if middle else []) + list(after_rows)
        return [self._event_from_row(row) for row in rows]

    def summary(
        self,
        log_ids: list[str],
        *,
        time_from: str | None,
        time_to: str | None,
        top_n: int,
    ) -> ActivitySummary:
        where: list[str] = []
        params: list[Any] = []
        if log_ids:
            where.append(
                "log_id IN (" + ", ".join("?" for _ in log_ids) + ")"
            )
            params.extend(log_ids)
        if time_from:
            where.append("timestamp_utc >= ?")
            params.append(time_from)
        if time_to:
            where.append("timestamp_utc <= ?")
            params.append(time_to)
        clause = (" WHERE " + " AND ".join(where)) if where else ""

        def grouped(column: str, limit: int = 50) -> dict[str, int]:
            with self._connect() as connection:
                rows = connection.execute(
                    f"SELECT {column} AS k, COUNT(*) AS n FROM evtx_events"
                    f"{clause} GROUP BY k ORDER BY n DESC LIMIT ?",
                    [*params, limit],
                ).fetchall()
            return {
                str(row["k"]): int(row["n"])
                for row in rows
                if row["k"] is not None
            }

        with self._connect() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) AS n, MIN(timestamp_utc) AS lo, "
                f"MAX(timestamp_utc) AS hi FROM evtx_events{clause}",
                params,
            ).fetchone()
            total = int(row["n"])
            day_rows = connection.execute(
                "SELECT substr(timestamp_utc, 1, 10) AS d, COUNT(*) AS n "
                f"FROM evtx_events{clause} GROUP BY d ORDER BY d",
                params,
            ).fetchall()
            top_process = connection.execute(
                f"SELECT event_data_json FROM evtx_events{clause} LIMIT 5000",
                params,
            ).fetchall()

        processes: dict[str, int] = {}
        paths: dict[str, int] = {}
        for item in top_process:
            data = _loads(item["event_data_json"], {})
            if not isinstance(data, dict):
                continue
            for key in ("Image", "NewProcessName", "ProcessName", "ParentProcessName"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    processes[value] = processes.get(value, 0) + 1
            for key in ("TargetFilename", "CommandLine", "Image", "NewProcessName"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    paths[value] = paths.get(value, 0) + 1

        return ActivitySummary(
            total_events=total,
            time_from=row["lo"],
            time_to=row["hi"],
            by_channel=grouped("channel"),
            by_provider=grouped("provider_name"),
            by_event_id=grouped("event_id"),
            by_level=grouped("level_name"),
            by_user_sid=grouped("user_sid"),
            by_computer=grouped("computer"),
            by_day={str(item["d"]): int(item["n"]) for item in day_rows if item["d"]},
            top_processes=_top(processes, top_n),
            top_paths=_top(paths, top_n),
            log_ids=list(log_ids),
        )


def _top(values: dict[str, int], n: int) -> list[dict[str, Any]]:
    ranked = sorted(values.items(), key=lambda item: (-item[1], item[0]))[: max(1, n)]
    return [{"value": key, "count": count} for key, count in ranked]


_TOKEN_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:\\/%@-]{1,63}")


def _fts_query(text: str) -> str | None:
    tokens = [
        token
        for token in _TOKEN_RE.findall(text or "")
        if any(char.isalnum() for char in token)
    ]
    if not tokens:
        return None
    # Quote each token so FTS syntax characters cannot change the query.
    return " AND ".join('"' + token.replace('"', "") + '"' for token in tokens[:16])


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
