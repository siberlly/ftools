from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence

from .triage_models import (
    AnalyzerResult,
    TriageFinding,
    TriageJob,
    TriageNotFoundError,
    TriageStringsPage,
    utc_now_iso,
)

TRIAGE_SCHEMA_VERSION = 1
JOB_ID_RE = re.compile(r"^tr_[0-9a-f]{16}$")

SCHEMA_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS triage_jobs (
  job_id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL,
  entry_id INTEGER NOT NULL,
  inode INTEGER,
  case_id TEXT NOT NULL,
  profile_version TEXT NOT NULL,
  status TEXT NOT NULL,
  phase TEXT NOT NULL,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  cached_from_job_id TEXT,
  sha256 TEXT,
  md5 TEXT,
  sha1 TEXT,
  size INTEGER,
  file_type TEXT,
  mime_type TEXT,
  entropy REAL,
  extract_relpath TEXT,
  strings_count INTEGER NOT NULL DEFAULT 0,
  findings_count INTEGER NOT NULL DEFAULT 0,
  yara_status TEXT,
  pe_status TEXT,
  duration_ms REAL,
  error_code TEXT,
  error_message TEXT,
  warnings_json TEXT,
  errors_json TEXT,
  tool_versions_json TEXT
);
CREATE TABLE IF NOT EXISTS triage_analyzers (
  job_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_ms REAL NOT NULL DEFAULT 0,
  version TEXT,
  error TEXT,
  warnings_json TEXT,
  data_json TEXT,
  truncated INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (job_id, name)
);
CREATE TABLE IF NOT EXISTS triage_strings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  encoding TEXT NOT NULL,
  offset INTEGER,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  category TEXT NOT NULL,
  value TEXT NOT NULL,
  encoding TEXT NOT NULL,
  offset INTEGER,
  rule_id TEXT NOT NULL,
  reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_yara_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  rule TEXT NOT NULL,
  namespace TEXT,
  tags_json TEXT,
  meta_json TEXT,
  strings_json TEXT
);
"""

SCHEMA_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_triage_jobs_entry
  ON triage_jobs(evidence_id, entry_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_triage_jobs_status
  ON triage_jobs(status);
CREATE INDEX IF NOT EXISTS idx_triage_jobs_cache
  ON triage_jobs(evidence_id, entry_id, sha256, profile_version);
CREATE INDEX IF NOT EXISTS idx_triage_strings_job
  ON triage_strings(job_id, id);
CREATE INDEX IF NOT EXISTS idx_triage_strings_encoding
  ON triage_strings(job_id, encoding, id);
CREATE INDEX IF NOT EXISTS idx_triage_findings_job
  ON triage_findings(job_id, id);
CREATE INDEX IF NOT EXISTS idx_triage_yara_job
  ON triage_yara_matches(job_id, id);
"""

JOB_COLUMNS = (
    "job_id, evidence_id, entry_id, inode, case_id, profile_version, status, "
    "phase, created_at, started_at, finished_at, cached_from_job_id, sha256, "
    "md5, sha1, size, file_type, mime_type, entropy, extract_relpath, "
    "strings_count, findings_count, yara_status, pe_status, duration_ms, "
    "error_code, error_message, warnings_json, errors_json, tool_versions_json"
)


def new_job_id() -> str:
    return "tr_" + uuid.uuid4().hex[:16]


def validate_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise TriageNotFoundError("invalid triage job id", details={"job_id": str(job_id)})
    return job_id


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class TriageStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(str(self.path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return connection

    def ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA_TABLES_SQL)
            connection.executescript(SCHEMA_INDEXES_SQL)
            connection.execute(f"PRAGMA user_version = {TRIAGE_SCHEMA_VERSION}")

    def recover_interrupted(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE triage_jobs SET status = 'interrupted', phase = 'complete', "
                "finished_at = ?, error_code = 'triage_interrupted', "
                "error_message = 'server restarted before triage finished' "
                "WHERE status IN ('queued', 'running')",
                (utc_now_iso(),),
            )
            return int(cursor.rowcount or 0)

    def create_job(self, job: TriageJob) -> None:
        with self._connect() as connection:
            connection.execute(
                f"INSERT INTO triage_jobs ({JOB_COLUMNS}) VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job.job_id,
                    job.evidence_id,
                    job.entry_id,
                    job.inode,
                    job.case_id,
                    job.profile_version,
                    job.status,
                    job.phase,
                    job.created_at,
                    job.started_at,
                    job.finished_at,
                    job.cached_from_job_id,
                    job.sha256,
                    job.md5,
                    job.sha1,
                    job.size,
                    job.file_type,
                    job.mime_type,
                    job.entropy,
                    job.extract_relpath,
                    job.strings_count,
                    job.findings_count,
                    job.yara_status,
                    job.pe_status,
                    job.duration_ms,
                    job.error_code,
                    job.error_message,
                    _json(job.warnings),
                    _json(job.errors),
                    _json(job.tool_versions),
                ),
            )

    def update_progress(self, job_id: str, phase: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE triage_jobs SET status = 'running', phase = ? "
                "WHERE job_id = ? AND status IN ('queued', 'running')",
                (phase, job_id),
            )

    def finish_job(self, job: TriageJob) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE triage_jobs SET status = ?, phase = ?, started_at = ?, "
                "finished_at = ?, cached_from_job_id = ?, sha256 = ?, md5 = ?, "
                "sha1 = ?, size = ?, "
                "file_type = ?, mime_type = ?, entropy = ?, extract_relpath = ?, "
                "strings_count = ?, findings_count = ?, yara_status = ?, "
                "pe_status = ?, duration_ms = ?, error_code = ?, error_message = ?, "
                "warnings_json = ?, errors_json = ?, tool_versions_json = ? "
                "WHERE job_id = ?",
                (
                    job.status,
                    job.phase,
                    job.started_at,
                    job.finished_at or utc_now_iso(),
                    job.cached_from_job_id,
                    job.sha256,
                    job.md5,
                    job.sha1,
                    job.size,
                    job.file_type,
                    job.mime_type,
                    job.entropy,
                    job.extract_relpath,
                    job.strings_count,
                    job.findings_count,
                    job.yara_status,
                    job.pe_status,
                    job.duration_ms,
                    job.error_code,
                    job.error_message,
                    _json(job.warnings),
                    _json(job.errors),
                    _json(job.tool_versions),
                    job.job_id,
                ),
            )
            connection.executemany(
                "INSERT INTO triage_analyzers (job_id, name, status, duration_ms, "
                "version, error, warnings_json, data_json, truncated) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(job_id, name) DO UPDATE SET status=excluded.status, "
                "duration_ms=excluded.duration_ms, version=excluded.version, "
                "error=excluded.error, warnings_json=excluded.warnings_json, "
                "data_json=excluded.data_json, truncated=excluded.truncated",
                [
                    (
                        job.job_id,
                        analyzer.name,
                        analyzer.status,
                        analyzer.duration_ms,
                        analyzer.version,
                        analyzer.error,
                        _json(analyzer.warnings),
                        _json(analyzer.data),
                        1 if analyzer.truncated else 0,
                    )
                    for analyzer in job.analyzers
                ],
            )

    def mark_failed(
        self,
        job_id: str,
        *,
        code: str,
        message: str,
        phase: str = "complete",
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE triage_jobs SET status = 'failed', phase = ?, "
                "finished_at = ?, error_code = ?, error_message = ? "
                "WHERE job_id = ?",
                (phase, utc_now_iso(), code, message[:500], job_id),
            )

    def insert_strings(
        self, job_id: str, rows: Iterable[Sequence[Any]]
    ) -> None:
        rows = list(rows)
        if not rows:
            return
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO triage_strings (job_id, encoding, offset, value) "
                "VALUES (?, ?, ?, ?)",
                [(job_id, *row) for row in rows],
            )

    def insert_findings(
        self, job_id: str, findings: Iterable[TriageFinding]
    ) -> None:
        rows = [
            (
                job_id,
                finding.category,
                finding.value[:512],
                finding.encoding,
                finding.offset,
                finding.rule_id,
                finding.reason,
            )
            for finding in findings
        ]
        if not rows:
            return
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO triage_findings (job_id, category, value, encoding, "
                "offset, rule_id, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    def insert_yara_matches(
        self, job_id: str, matches: Iterable[dict[str, Any]]
    ) -> None:
        rows = [
            (
                job_id,
                str(match.get("rule") or "")[:256],
                str(match.get("namespace") or "default")[:128],
                _json(match.get("tags") or []),
                _json(match.get("meta") or {}),
                _json(match.get("strings") or []),
            )
            for match in matches
        ]
        if not rows:
            return
        with self._connect() as connection:
            connection.executemany(
                "INSERT INTO triage_yara_matches (job_id, rule, namespace, "
                "tags_json, meta_json, strings_json) VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )

    def _job_from_row(self, row: sqlite3.Row) -> TriageJob:
        return TriageJob(
            job_id=str(row["job_id"]),
            evidence_id=str(row["evidence_id"]),
            entry_id=int(row["entry_id"]),
            inode=int(row["inode"]) if row["inode"] is not None else None,
            case_id=str(row["case_id"]),
            profile_version=str(row["profile_version"]),
            status=str(row["status"]),
            phase=str(row["phase"]),
            created_at=str(row["created_at"]),
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            cached_from_job_id=row["cached_from_job_id"],
            sha256=row["sha256"],
            md5=row["md5"],
            sha1=row["sha1"],
            size=int(row["size"]) if row["size"] is not None else None,
            file_type=row["file_type"],
            mime_type=row["mime_type"],
            entropy=float(row["entropy"]) if row["entropy"] is not None else None,
            extract_relpath=row["extract_relpath"],
            strings_count=int(row["strings_count"] or 0),
            findings_count=int(row["findings_count"] or 0),
            yara_status=row["yara_status"],
            pe_status=row["pe_status"],
            duration_ms=(
                float(row["duration_ms"]) if row["duration_ms"] is not None else None
            ),
            error_code=row["error_code"],
            error_message=row["error_message"],
            warnings=_loads(row["warnings_json"], []),
            errors=_loads(row["errors_json"], []),
            tool_versions=_loads(row["tool_versions_json"], {}),
        )

    def get_job(self, job_id: str) -> TriageJob:
        validate_job_id(job_id)
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {JOB_COLUMNS} FROM triage_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise TriageNotFoundError(
                    "triage job was not found", details={"job_id": job_id}
                )
            job = self._job_from_row(row)
            source = job.cached_from_job_id or job.job_id
            analyzer_rows = connection.execute(
                "SELECT * FROM triage_analyzers WHERE job_id = ? ORDER BY name",
                (source,),
            ).fetchall()
            job.analyzers = [
                AnalyzerResult(
                    name=str(item["name"]),
                    status=str(item["status"]),
                    duration_ms=float(item["duration_ms"] or 0.0),
                    version=item["version"],
                    error=item["error"],
                    warnings=_loads(item["warnings_json"], []),
                    data=_loads(item["data_json"], {}),
                    truncated=bool(item["truncated"]),
                )
                for item in analyzer_rows
            ]
            return job

    def find_cached(
        self,
        evidence_id: str,
        entry_id: int,
        sha256: str,
        profile_version: str,
    ) -> TriageJob | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {JOB_COLUMNS} FROM triage_jobs "
                "WHERE evidence_id = ? AND entry_id = ? AND sha256 = ? "
                "AND profile_version = ? AND status IN ('complete', 'partial') "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (evidence_id, entry_id, sha256, profile_version),
            ).fetchone()
            if row is None:
                return None
            return self._job_from_row(row)

    def latest_for_entry(
        self, evidence_id: str, entry_id: int
    ) -> TriageJob | None:
        with self._connect() as connection:
            # rowid is monotonic per insert, so jobs created within the same
            # second still order newest-first.
            row = connection.execute(
                f"SELECT {JOB_COLUMNS} FROM triage_jobs "
                "WHERE evidence_id = ? AND entry_id = ? "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (evidence_id, entry_id),
            ).fetchone()
            return self._job_from_row(row) if row is not None else None

    def latest_completed_for_entry(
        self, evidence_id: str, entry_id: int, *, exclude_job_id: str | None = None
    ) -> TriageJob | None:
        """Newest complete/partial job with a recorded extraction copy."""
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {JOB_COLUMNS} FROM triage_jobs "
                "WHERE evidence_id = ? AND entry_id = ? "
                "AND status IN ('complete', 'partial') "
                "AND extract_relpath IS NOT NULL "
                "AND (? IS NULL OR job_id <> ?) "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (evidence_id, entry_id, exclude_job_id, exclude_job_id),
            ).fetchone()
            return self._job_from_row(row) if row is not None else None

    def latest_for_entries(
        self, evidence_id: str, entry_ids: Sequence[int]
    ) -> dict[int, dict[str, Any]]:
        if not entry_ids:
            return {}
        placeholders = ",".join("?" for _ in entry_ids)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT job_id, entry_id, status, phase, created_at, "
                "cached_from_job_id, sha256 FROM triage_jobs "
                f"WHERE evidence_id = ? AND entry_id IN ({placeholders}) "
                "ORDER BY created_at ASC",
                (evidence_id, *entry_ids),
            ).fetchall()
        latest: dict[int, dict[str, Any]] = {}
        for row in rows:
            latest[int(row["entry_id"])] = {
                "job_id": row["job_id"],
                "status": row["status"],
                "phase": row["phase"],
                "created_at": row["created_at"],
                "cached": row["cached_from_job_id"] is not None,
                "sha256": row["sha256"],
            }
        return latest

    def strings_page(
        self,
        job_id: str,
        *,
        page: int,
        page_size: int,
        encoding: str | None = None,
        query: str | None = None,
    ) -> TriageStringsPage:
        where = "job_id = ?"
        params: list[Any] = [job_id]
        if encoding:
            where += " AND encoding = ?"
            params.append(encoding)
        if query:
            escaped = (
                query.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            where += " AND value LIKE ? ESCAPE '\\'"
            params.append(f"%{escaped}%")
        offset = (page - 1) * page_size
        with self._connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) AS n FROM triage_strings WHERE {where}",
                    params,
                ).fetchone()["n"]
            )
            rows = connection.execute(
                "SELECT offset, encoding, value FROM triage_strings "
                f"WHERE {where} ORDER BY id LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()
        return TriageStringsPage(
            job_id=job_id,
            strings=[
                {
                    "offset": row["offset"],
                    "encoding": row["encoding"],
                    "value": row["value"],
                }
                for row in rows
            ],
            total=total,
            page=page,
            page_size=page_size,
            encoding=encoding,
            query=query,
        )

    def findings(self, job_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT category, value, encoding, offset, rule_id, reason "
                "FROM triage_findings WHERE job_id = ? ORDER BY id",
                (job_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def yara_matches(self, job_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT rule, namespace, tags_json, meta_json, strings_json "
                "FROM triage_yara_matches WHERE job_id = ? ORDER BY id",
                (job_id,),
            ).fetchall()
        return [
            {
                "rule": row["rule"],
                "namespace": row["namespace"],
                "tags": _loads(row["tags_json"], []),
                "meta": _loads(row["meta_json"], {}),
                "strings": _loads(row["strings_json"], []),
            }
            for row in rows
        ]

    def counts(self) -> dict[str, int]:
        with self._connect() as connection:
            total = int(
                connection.execute("SELECT COUNT(*) AS n FROM triage_jobs").fetchone()["n"]
            )
            running = int(
                connection.execute(
                    "SELECT COUNT(*) AS n FROM triage_jobs WHERE status IN ('queued','running')"
                ).fetchone()["n"]
            )
        return {"jobs": total, "active": running}
