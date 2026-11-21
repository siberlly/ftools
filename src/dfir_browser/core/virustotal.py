from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .errors import DFIRError

VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"
VT_ALLOWED_HOST = "www.virustotal.com"
VT_GUI_URL = "https://www.virustotal.com/gui/file/"
HASH_PATTERNS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}
HASH_RE = re.compile(r"^[A-Fa-f0-9]+$")
USER_AGENT = "dfir-browser/0.5 (local forensic static triage)"
SCHEMA_VERSION = 1


class VirusTotalError(DFIRError):
    default_code = "virustotal_error"


class VirusTotalNotConfigured(VirusTotalError):
    default_code = "virustotal_not_configured"


class VirusTotalInvalidKey(VirusTotalError):
    default_code = "virustotal_invalid_key"


class VirusTotalForbidden(VirusTotalError):
    default_code = "virustotal_forbidden"


class VirusTotalRateLimited(VirusTotalError):
    default_code = "virustotal_rate_limited"

    def __init__(self, message: str, *, retry_after: int | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class VirusTotalTransient(VirusTotalError):
    default_code = "virustotal_unavailable"


class VirusTotalTimeout(VirusTotalError):
    default_code = "virustotal_timeout"


class VirusTotalNetworkError(VirusTotalError):
    default_code = "virustotal_network_error"


class VirusTotalTlsError(VirusTotalError):
    default_code = "virustotal_tls_error"


class VirusTotalInvalidResponse(VirusTotalError):
    default_code = "virustotal_invalid_response"


class VirusTotalResponseTooLarge(VirusTotalError):
    default_code = "virustotal_response_too_large"


class VirusTotalRedirectRejected(VirusTotalError):
    default_code = "virustotal_redirect_rejected"


class VirusTotalUnexpectedHost(VirusTotalError):
    default_code = "virustotal_unexpected_host"


def hash_type(value: str) -> str | None:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        return None
    return HASH_PATTERNS.get(len(value))


def normalize_hash(value: str) -> tuple[str, str]:
    value = (value or "").strip().lower()
    kind = hash_type(value)
    if kind is None:
        raise VirusTotalError(
            "hash must be MD5, SHA-1 or SHA-256 hexadecimal",
            code="virustotal_invalid_hash",
        )
    return value, kind


def _iso(epoch: int | float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return (
            datetime.fromtimestamp(int(epoch), tz=timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return None


def _text(value: Any, limit: int = 512) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class VirusTotalReport:
    status: str
    http_status: int
    report: dict[str, Any] | None


class VirusTotalClient:
    """Strictly one outbound endpoint: GET /api/v3/files/{hash}."""

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        max_response_bytes: int = 2_000_000,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.timeout = float(timeout)
        self.max_response_bytes = int(max_response_bytes)
        self._transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=min(5.0, self.timeout)),
            verify=True,
            follow_redirects=False,
            transport=self._transport,
        )

    @staticmethod
    def url_for(hash_value: str) -> str:
        return VT_BASE_URL + quote(hash_value, safe="")

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != VT_ALLOWED_HOST:
            raise VirusTotalUnexpectedHost(
                "VirusTotal requests are restricted to https://www.virustotal.com"
            )

    def _request(self, url: str, api_key: str) -> tuple[int, dict[str, str], bytes]:
        self._validate_url(url)
        headers = {
            "x-apikey": api_key,
            "accept": "application/json",
            "user-agent": USER_AGENT,
        }
        with self._client() as client:
            with client.stream("GET", url, headers=headers) as response:
                status = response.status_code
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
                if status != 200:
                    return status, response_headers, b""
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise VirusTotalResponseTooLarge(
                            "VirusTotal response exceeded the configured limit",
                            details={"limit": self.max_response_bytes},
                        )
                    chunks.append(chunk)
                return status, response_headers, b"".join(chunks)

    def lookup(self, hash_value: str, api_key: str) -> VirusTotalReport:
        value, _kind = normalize_hash(hash_value)
        if not api_key:
            raise VirusTotalNotConfigured("VirusTotal API key is not configured")
        url = self.url_for(value)
        attempts = 0
        while True:
            attempts += 1
            try:
                status, headers, body = self._request(url, api_key)
            except httpx.TimeoutException as exc:
                raise VirusTotalTimeout(
                    "VirusTotal request timed out"
                ) from exc
            except httpx.ConnectError as exc:
                text = str(exc).lower()
                if "certificate" in text or "ssl" in text or "tls" in text:
                    raise VirusTotalTlsError(
                        "TLS verification failed for VirusTotal"
                    ) from exc
                raise VirusTotalNetworkError(
                    "could not connect to VirusTotal"
                ) from exc
            except httpx.HTTPError as exc:
                raise VirusTotalNetworkError(
                    "VirusTotal request failed"
                ) from exc

            if status in (503, 504) and attempts < 2:
                time.sleep(0.5)
                continue
            if 300 <= status < 400:
                raise VirusTotalRedirectRejected(
                    "VirusTotal returned an unexpected redirect",
                    details={"http_status": status},
                )
            if status == 200:
                return VirusTotalReport(
                    status="found",
                    http_status=200,
                    report=self._parse(body),
                )
            if status == 404:
                return VirusTotalReport(
                    status="not_found", http_status=404, report=None
                )
            if status == 401:
                raise VirusTotalInvalidKey(
                    "VirusTotal rejected the API key",
                    details={"http_status": 401},
                )
            if status == 403:
                raise VirusTotalForbidden(
                    "VirusTotal denied access to this lookup",
                    details={"http_status": 403},
                )
            if status == 429:
                retry_after = headers.get("retry-after")
                retry = _int(retry_after) if retry_after else None
                raise VirusTotalRateLimited(
                    "VirusTotal rate limit or quota exhausted",
                    retry_after=retry,
                    details={"http_status": 429, "retry_after": retry},
                )
            if status in (503, 504):
                raise VirusTotalTransient(
                    "VirusTotal is temporarily unavailable",
                    details={"http_status": status},
                )
            raise VirusTotalError(
                f"unexpected VirusTotal HTTP status {status}",
                details={"http_status": status},
            )

    def _parse(self, body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise VirusTotalInvalidResponse(
                "VirusTotal returned invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise VirusTotalInvalidResponse(
                "VirusTotal response was not a JSON object"
            )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise VirusTotalInvalidResponse(
                "VirusTotal response had no data object"
            )
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            raise VirusTotalInvalidResponse(
                "VirusTotal response had no attributes object"
            )
        sha256 = _text(attributes.get("sha256"), 64)
        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            stats = {}
        normalized_stats = {
            key: _int(stats.get(key)) or 0
            for key in (
                "malicious",
                "suspicious",
                "undetected",
                "harmless",
                "timeout",
                "failure",
                "type-unsupported",
            )
        }
        tags = attributes.get("tags")
        if not isinstance(tags, list):
            tags = []
        names = attributes.get("names")
        if not isinstance(names, list):
            names = []
        report = {
            "hash": sha256,
            "md5": _text(attributes.get("md5"), 64),
            "sha1": _text(attributes.get("sha1"), 64),
            "sha256": sha256,
            "meaningful_name": _text(attributes.get("meaningful_name"), 512),
            "names": [_text(name, 256) for name in names[:10] if name],
            "type_description": _text(attributes.get("type_description"), 256),
            "type_tag": _text(attributes.get("type_tag"), 128),
            "size": _int(attributes.get("size")),
            "reputation": _int(attributes.get("reputation")),
            "last_analysis_stats": normalized_stats,
            "times_submitted": _int(attributes.get("times_submitted")),
            "first_submission_date": _iso(attributes.get("first_submission_date")),
            "last_submission_date": _iso(attributes.get("last_submission_date")),
            "last_analysis_date": _iso(attributes.get("last_analysis_date")),
            "tags": [_text(tag, 64) for tag in tags[:20] if tag],
            "permalink": VT_GUI_URL + (sha256 or ""),
        }
        return report


class VirusTotalStore:
    """Persistent report cache. Never stores the API key."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.path, timeout=10.0)
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
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS vt_reports (
                  hash TEXT PRIMARY KEY,
                  hash_type TEXT NOT NULL,
                  status TEXT NOT NULL,
                  http_status INTEGER NOT NULL,
                  fetched_at TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  report_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_vt_expires ON vt_reports(expires_at);
                CREATE TABLE IF NOT EXISTS vt_entry_hashes (
                  evidence_id TEXT NOT NULL,
                  entry_id INTEGER NOT NULL,
                  sha256 TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  PRIMARY KEY (evidence_id, entry_id)
                );
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def get(self, hash_value: str) -> dict[str, Any] | None:
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM vt_reports WHERE hash = ?", (hash_value,)
            ).fetchone()
            if row is None:
                return None
            if int(row["expires_at"]) <= now:
                return None
            report = None
            if row["report_json"]:
                try:
                    report = json.loads(row["report_json"])
                except ValueError:
                    report = None
            return {
                "hash": row["hash"],
                "hash_type": row["hash_type"],
                "status": row["status"],
                "http_status": int(row["http_status"]),
                "fetched_at": row["fetched_at"],
                "expires_at": int(row["expires_at"]),
                "report": report,
            }

    def put(
        self,
        hash_value: str,
        hash_kind: str,
        status: str,
        http_status: int,
        report: dict[str, Any] | None,
        ttl: int,
    ) -> dict[str, Any]:
        now = int(time.time())
        fetched_at = (
            datetime.fromtimestamp(now, tz=timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        expires_at = now + max(1, int(ttl))
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO vt_reports (hash, hash_type, status, http_status, "
                "fetched_at, expires_at, report_json) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(hash) DO UPDATE SET hash_type=excluded.hash_type, "
                "status=excluded.status, http_status=excluded.http_status, "
                "fetched_at=excluded.fetched_at, expires_at=excluded.expires_at, "
                "report_json=excluded.report_json",
                (
                    hash_value,
                    hash_kind,
                    status,
                    http_status,
                    fetched_at,
                    expires_at,
                    json.dumps(report, ensure_ascii=False) if report else None,
                ),
            )
        return {
            "hash": hash_value,
            "hash_type": hash_kind,
            "status": status,
            "http_status": http_status,
            "fetched_at": fetched_at,
            "expires_at": expires_at,
            "report": report,
        }

    def remember_hash(
        self, evidence_id: str, entry_id: int, sha256: str
    ) -> None:
        now = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO vt_entry_hashes (evidence_id, entry_id, sha256, "
                "updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(evidence_id, entry_id) DO UPDATE SET "
                "sha256=excluded.sha256, updated_at=excluded.updated_at",
                (evidence_id, int(entry_id), sha256, now),
            )

    def entry_hash(self, evidence_id: str, entry_id: int) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT sha256 FROM vt_entry_hashes "
                "WHERE evidence_id = ? AND entry_id = ?",
                (evidence_id, int(entry_id)),
            ).fetchone()
            return str(row["sha256"]) if row is not None else None

    def purge_expired(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM vt_reports WHERE expires_at <= ?",
                (int(time.time()),),
            )
            return int(cursor.rowcount or 0)


class VirusTotalService:
    def __init__(
        self,
        *,
        settings,
        secret_store,
        store: VirusTotalStore,
        evidence,
        indexer,
        triage,
        audit,
        client: VirusTotalClient | None = None,
        clock=time.time,
    ) -> None:
        self.settings = settings
        self.secrets = secret_store
        self.store = store
        self.evidence = evidence
        self.indexer = indexer
        self.triage = triage
        self.audit = audit
        self.client = client or VirusTotalClient(
            timeout=settings.virustotal_timeout,
            max_response_bytes=settings.virustotal_max_response_bytes,
        )
        self._clock = clock
        self._lock = threading.Lock()
        self._calls: deque[float] = deque()
        self._inflight: dict[str, threading.Event] = {}
        self._last_errors: dict[str, tuple[float, Exception]] = {}
        self._last_error_ttl = 120.0
        self._upstream_blocked_until = 0.0
        self.store.ensure_schema()
        try:
            self.store.purge_expired()
        except Exception:  # noqa: BLE001 - cache cleanup is best effort
            pass

    # -- configuration -------------------------------------------------
    def status(self) -> dict[str, Any]:
        status = self.secrets.status()
        status["rate_limit_per_minute"] = int(
            self.settings.virustotal_rate_limit
        )
        status["cache_ttl_seconds"] = int(self.settings.virustotal_cache_ttl)
        return status

    def save_key(self, key: str) -> dict[str, Any]:
        self.secrets.save(key)
        status = self.status()
        self.audit.event(
            "virustotal_key_saved",
            details={"source": status.get("source")},
        )
        return status

    def remove_key(self) -> dict[str, Any]:
        removed = self.secrets.remove()
        status = self.status()
        self.audit.event(
            "virustotal_key_removed",
            details={
                "removed": bool(removed),
                "source": status.get("source"),
            },
        )
        return status

    def known_hash_for_entry(
        self, evidence_id: str, entry_id: int
    ) -> str | None:
        try:
            latest = self.triage.store.latest_for_entry(evidence_id, entry_id)
            if latest is not None and latest.sha256:
                return latest.sha256
        except Exception:  # noqa: BLE001
            pass
        try:
            return self.store.entry_hash(evidence_id, entry_id)
        except Exception:  # noqa: BLE001
            return None

    def cached_result(self, value: str) -> dict[str, Any] | None:
        hash_value, _kind = normalize_hash(value)
        cached = self.store.get(hash_value)
        if cached is None:
            return None
        _key, source = self.secrets.resolve_key()
        return self._result_from_cache(cached, source)

    # -- hash resolution ----------------------------------------------
    def sha256_for_entry(self, record, entry_id: int) -> dict[str, Any]:
        return self.triage.sha256_for_entry(record, entry_id)

    # -- lookup --------------------------------------------------------
    def lookup_entry(
        self,
        record,
        entry_id: int,
        *,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        entry = self.indexer.tree_entry(record, entry_id)
        if entry.entry_type != "file":
            raise VirusTotalError(
                "VirusTotal lookup only applies to files",
                code="virustotal_directory_rejected",
            )
        resolved = self.sha256_for_entry(record, entry.id)
        try:
            self.store.remember_hash(
                record.evidence_id, entry.id, resolved["sha256"]
            )
        except Exception:  # noqa: BLE001 - cache hint is best effort
            pass
        result = self.lookup_hash(
            resolved["sha256"],
            force_refresh=force_refresh,
            context={
                "evidence_id": record.evidence_id,
                "entry_id": entry.id,
            },
        )
        result["entry_id"] = entry.id
        result["evidence_id"] = record.evidence_id
        result["entry_path"] = entry.full_path
        return result

    def lookup_hash(
        self,
        value: str,
        *,
        force_refresh: bool = False,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        hash_value, kind = normalize_hash(value)
        key, source = self.secrets.resolve_key()
        if not key:
            raise VirusTotalNotConfigured(
                "VirusTotal API key is not configured",
                details={"source": "none"},
            )

        cached = None if force_refresh else self.store.get(hash_value)
        if cached is not None:
            result = self._result_from_cache(cached, source)
            self._audit(context, hash_value, kind, result, force_refresh)
            return result

        # Coalesce concurrent lookups for the same hash.
        with self._lock:
            event = self._inflight.get(hash_value)
            if event is not None:
                waiter = event
            else:
                waiter = None
                event = threading.Event()
                self._inflight[hash_value] = event
        if waiter is not None:
            waiter.wait(timeout=self.settings.virustotal_timeout + 5.0)
            cached = self.store.get(hash_value)
            if cached is not None:
                result = self._result_from_cache(cached, source)
                self._audit(context, hash_value, kind, result, force_refresh)
                return result
            with self._lock:
                failure = self._last_errors.get(hash_value)
                if failure is not None and self._clock() - failure[0] > self._last_error_ttl:
                    failure = None
            if failure is not None:
                raise failure[1]
            raise VirusTotalTransient(
                "a concurrent VirusTotal lookup did not produce a cached result"
            )

        try:
            self._enforce_rate_limit()
            try:
                report = self.client.lookup(hash_value, key)
            finally:
                self._record_call()
            if report.status == "found":
                cached = self.store.put(
                    hash_value,
                    kind,
                    "found",
                    200,
                    report.report,
                    self.settings.virustotal_cache_ttl,
                )
            elif report.status == "not_found":
                cached = self.store.put(
                    hash_value,
                    kind,
                    "not_found",
                    404,
                    None,
                    self.settings.virustotal_notfound_ttl,
                )
            else:  # pragma: no cover - defensive
                raise VirusTotalInvalidResponse(
                    "VirusTotal returned an unknown result status"
                )
            result = self._result_from_cache(cached, source)
            result["cached"] = False
            self._audit(context, hash_value, kind, result, force_refresh)
            return result
        except VirusTotalRateLimited as exc:
            cooldown = exc.retry_after if exc.retry_after else 60
            with self._lock:
                self._upstream_blocked_until = max(
                    self._upstream_blocked_until,
                    self._clock() + max(1, int(cooldown)),
                )
                self._last_errors[hash_value] = (self._clock(), exc)
            self._audit(
                context,
                hash_value,
                kind,
                {
                    "status": "error",
                    "http_status": getattr(exc, "details", {}).get(
                        "http_status"
                    ),
                    "cached": False,
                    "error_code": getattr(exc, "code", "virustotal_error"),
                },
                force_refresh,
            )
            raise
        except Exception as exc:
            with self._lock:
                self._last_errors[hash_value] = (self._clock(), exc)
            self._audit(
                context,
                hash_value,
                kind,
                {
                    "status": "error",
                    "http_status": getattr(exc, "details", {}).get(
                        "http_status"
                    ),
                    "cached": False,
                    "error_code": getattr(exc, "code", "virustotal_error"),
                },
                force_refresh,
            )
            raise
        finally:
            with self._lock:
                self._inflight.pop(hash_value, None)
            event.set()

    # -- helpers -------------------------------------------------------
    def _enforce_rate_limit(self) -> None:
        limit = max(1, int(self.settings.virustotal_rate_limit))
        now = self._clock()
        with self._lock:
            if self._upstream_blocked_until > now:
                retry_after = max(1, int(math.ceil(self._upstream_blocked_until - now)))
                raise VirusTotalRateLimited(
                    "VirusTotal asked us to back off; try again later",
                    retry_after=retry_after,
                    details={"retry_after": retry_after, "limit": limit},
                )
            while self._calls and now - self._calls[0] >= 60.0:
                self._calls.popleft()
            if len(self._calls) >= limit:
                retry_after = max(
                    1, int(math.ceil(60.0 - (now - self._calls[0])))
                )
                raise VirusTotalRateLimited(
                    "local VirusTotal rate limit reached; try again later",
                    retry_after=retry_after,
                    details={"retry_after": retry_after, "limit": limit},
                )

    def _record_call(self) -> None:
        with self._lock:
            self._calls.append(self._clock())

    def _result_from_cache(
        self, cached: dict[str, Any], source: str
    ) -> dict[str, Any]:
        now = int(self._clock())
        age = 0
        try:
            fetched = datetime.fromisoformat(
                str(cached.get("fetched_at") or "").replace("Z", "+00:00")
            )
            age = max(0, now - int(fetched.timestamp()))
        except (TypeError, ValueError):
            age = 0
        return {
            "status": cached["status"],
            "cached": True,
            "http_status": cached["http_status"],
            "hash": cached["hash"],
            "hash_type": cached["hash_type"],
            "fetched_at": cached["fetched_at"],
            "expires_at": cached["expires_at"],
            "cache_age_seconds": age,
            "report": cached.get("report"),
            "key_source": source,
            "rate_limit": int(self.settings.virustotal_rate_limit),
        }

    def _audit(
        self,
        context: dict[str, Any] | None,
        hash_value: str,
        kind: str,
        result: dict[str, Any],
        force_refresh: bool,
    ) -> None:
        from .audit import get_correlation_id

        details = {
            "hash_type": kind,
            "hash": hash_value,
            "requested_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "result_status": result.get("status"),
            "cache": bool(result.get("cached")),
            "http_status": result.get("http_status"),
            "force_refresh": bool(force_refresh),
        }
        if result.get("error_code"):
            details["error_code"] = result["error_code"]
        if context:
            details["evidence_id"] = context.get("evidence_id")
            details["entry_id"] = context.get("entry_id")
        try:
            self.audit.event(
                "virustotal_lookup",
                evidence_id=(context or {}).get("evidence_id"),
                request_id=get_correlation_id(),
                details=details,
            )
        except Exception:  # noqa: BLE001 - audit must not break lookup
            pass
