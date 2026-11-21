from __future__ import annotations

import os
import re
import shutil
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from .models import (
    BackendUnavailable,
    BrowserArtifactError,
    CacheRecord,
    DownloadRecord,
    VisitRecord,
)
from .timestamp import (
    Timestamp,
    from_chromium,
    from_ese,
    from_unix_microseconds,
    from_unix_seconds,
)

CHROMIUM_STATES = {
    0: "in_progress",
    1: "complete",
    2: "cancelled",
    3: "interrupted",
    4: "interrupted",
}
CHROMIUM_DANGER = {
    0: "not_dangerous",
    1: "dangerous_file",
    2: "dangerous_url",
    3: "dangerous_content",
    4: "maybe_dangerous_content",
    5: "uncommon_content",
    6: "user_validated",
    7: "dangerous_host",
    8: "potentially_unwanted",
    9: "allowlisted_by_policy",
}
CHROMIUM_INTERRUPT = {
    0: "none",
    1: "file_failed",
    2: "file_access_denied",
    3: "file_no_space",
    4: "file_name_too_long",
    5: "file_too_large",
    6: "file_virus_infected",
    7: "file_transient_error",
    8: "file_blocked",
    9: "file_security_check_failed",
    10: "file_too_short",
    20: "network_failed",
    21: "network_timeout",
    22: "network_disconnected",
    23: "network_server_down",
    30: "server_failed",
    31: "server_no_range",
    32: "server_bad_content",
    33: "server_unauthorized",
    34: "server_certificate_problem",
    35: "server_forbidden",
    36: "server_unreachable",
    37: "server_content_length_mismatch",
    38: "server_cross_origin_redirect",
    39: "server_canceled",
    40: "user_canceled",
    41: "user_shutdown",
    50: "crash",
}
PRIVATE_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    text = str(value)
    return text


def _truncate(value: str | None, limit: int) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if len(value) <= limit:
        return value, False
    return value[:limit], True


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_url(raw: str | None, limit: int) -> dict[str, Any]:
    """Parse a URL without touching the network."""
    text, truncated = _truncate(raw, limit)
    result = {
        "url": text,
        "scheme": None,
        "host": None,
        "registrable_domain": None,
        "truncated": truncated,
    }
    if not text:
        return result
    candidate = text.strip()
    # WebCache prefixes records with "Visited: user@" or ":2022111520221116: user@".
    stripped = re.match(
        r"^.*?@(?=[A-Za-z][A-Za-z0-9+.\-]*://)", candidate, re.DOTALL
    )
    if stripped:
        candidate = candidate[stripped.end():]
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return result
    scheme = (parts.scheme or "").lower() or None
    host = (parts.hostname or "").lower() or None
    result["url"] = candidate if candidate != text.strip() else text
    result["scheme"] = scheme
    result["host"] = host
    if host:
        result["registrable_domain"] = registrable_domain(host)
    return result


def registrable_domain(host: str) -> str | None:
    """Conservative offline eTLD+1 for the common multi-part suffixes."""
    host = host.strip().strip(".").lower()
    if not host:
        return None
    if PRIVATE_HOST_RE.match(host) or host.startswith("["):
        return host
    labels = host.split(".")
    if len(labels) < 2:
        return host
    two_part = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.jp", "or.jp", "ne.jp", "com.br", "com.cn", "co.in", "co.nz",
        "com.tr", "com.mx", "co.za", "com.sg", "com.hk",
    }
    tail = ".".join(labels[-2:])
    if tail in two_part and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


@dataclass(slots=True)
class ParseOutcome:
    visits: list[VisitRecord] = field(default_factory=list)
    downloads: list[DownloadRecord] = field(default_factory=list)
    cache: list[CacheRecord] = field(default_factory=list)
    profile: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[tuple[str | None, str]] = field(default_factory=list)
    records_seen: int = 0


class BrowserBackend:
    name = "none"
    version = "0"
    supported = True

    def __init__(self, path: Path, *, settings, profile_id: str, artifact_id: str) -> None:
        self.path = Path(path)
        self.settings = settings
        self.profile_id = profile_id
        self.artifact_id = artifact_id

    def parse(self, deadline: float) -> ParseOutcome:
        raise NotImplementedError


class ChromiumHistoryBackend(BrowserBackend):
    name = "chromium-sqlite"
    version = "1"

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        # Read-only, immutable so SQLite never creates WAL/SHM on the copy.
        uri = f"file:{path}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        connection.row_factory = sqlite3.Row
        return connection

    def parse(self, deadline: float) -> ParseOutcome:
        outcome = ParseOutcome()
        max_url = int(self.settings.browser_max_url_length)
        max_title = int(self.settings.browser_max_title_length)
        try:
            connection = self._connect(self.path)
        except sqlite3.Error as exc:
            outcome.warnings.append("database cannot be opened read-only")
            outcome.errors.append((None, f"sqlite open failed: {exc}"[:300]))
            return outcome
        try:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "urls" not in tables:
                outcome.errors.append((None, "missing urls table"))
                outcome.warnings.append("schema mismatch: no urls table")
                return outcome
            urls = {
                row["id"]: (row["url"], row["title"], row["visit_count"], row["typed_count"])
                for row in connection.execute(
                    "SELECT id, url, title, visit_count, typed_count FROM urls"
                )
            }
            outcome.records_seen += len(urls)
            if "visits" in tables:
                for row in connection.execute(
                    "SELECT id, url, visit_time, from_visit, transition FROM visits"
                    " ORDER BY visit_time"
                ):
                    if time.monotonic() > deadline:
                        outcome.warnings.append("parser timeout during visits")
                        break
                    url_id = row["url"]
                    url, title, visit_count, typed_count = urls.get(
                        url_id, (None, None, None, None)
                    )
                    ts = from_chromium(row["visit_time"])
                    normalized = normalize_url(url, max_url)
                    title_text, _ = _truncate(title, max_title)
                    referrer = None
                    from_visit = row["from_visit"]
                    if from_visit:
                        ref = connection.execute(
                            "SELECT url FROM visits WHERE id = ?", (from_visit,)
                        ).fetchone()
                        if ref is not None:
                            referrer = urls.get(ref["url"], (None,))[0]
                    transition_raw = row["transition"]
                    outcome.visits.append(
                        VisitRecord(
                            visit_id=0,
                            profile_id=self.profile_id,
                            source_artifact_id=self.artifact_id,
                            source_record_id=f"visit:{row['id']}",
                            user=None,
                            browser="chromium",
                            url=normalized["url"],
                            scheme=normalized["scheme"],
                            host=normalized["host"],
                            registrable_domain=normalized["registrable_domain"],
                            title=title_text,
                            visit_time_utc=ts.utc,
                            raw_timestamp=ts.raw,
                            visit_type=(
                                f"transition:{transition_raw}"
                                if transition_raw is not None
                                else None
                            ),
                            referrer_url=referrer,
                            visit_count=_int(visit_count),
                            typed_count=_int(typed_count),
                            hidden=None,
                            warnings=(
                                [ts.warning] if ts.warning else []
                            ),
                        )
                    )
            if "downloads" in tables:
                columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(downloads)")
                }
                chain_by_id: dict[int, list[str]] = {}
                if "downloads_url_chains" in tables:
                    for row in connection.execute(
                        "SELECT id, chain_index, url FROM downloads_url_chains"
                        " ORDER BY id, chain_index"
                    ):
                        chain_by_id.setdefault(int(row["id"]), []).append(
                            row["url"]
                        )
                for row in connection.execute("SELECT * FROM downloads"):
                    if time.monotonic() > deadline:
                        outcome.warnings.append("parser timeout during downloads")
                        break
                    start = from_chromium(row["start_time"]) if "start_time" in columns else Timestamp(None, None, "missing")
                    end = (
                        from_chromium(row["end_time"])
                        if "end_time" in columns
                        else Timestamp(None, None, "missing")
                    )
                    state_raw = _int(row["state"]) if "state" in columns else None
                    danger_raw = _int(row["danger_type"]) if "danger_type" in columns else None
                    interrupt_raw = (
                        _int(row["interrupt_reason"])
                        if "interrupt_reason" in columns
                        else None
                    )
                    target = _str(row["target_path"]) if "target_path" in columns else None
                    target_text, _ = _truncate(target, int(self.settings.browser_max_path_length))
                    warnings: list[str] = []
                    for ts_value in (start, end):
                        if ts_value.warning:
                            warnings.append(ts_value.warning)
                    chain = chain_by_id.get(int(row["id"]), [])
                    url_raw = chain[0] if chain else None
                    final_raw = chain[-1] if chain else url_raw
                    normalized = normalize_url(url_raw, max_url)
                    filename = None
                    if "current_path" in columns and row["current_path"]:
                        filename = os.path.basename(
                            str(row["current_path"]).replace("\\", "/")
                        )
                    if not filename and target_text:
                        filename = os.path.basename(target_text.replace("\\", "/"))
                    outcome.downloads.append(
                        DownloadRecord(
                            download_id=0,
                            profile_id=self.profile_id,
                            source_artifact_id=self.artifact_id,
                            source_record_id=f"download:{row['id']}",
                            user=None,
                            browser="chromium",
                            start_time_utc=start.utc,
                            end_time_utc=end.utc,
                            start_raw=start.raw,
                            end_raw=end.raw,
                            url=normalized["url"],
                            final_url=normalize_url(final_raw, max_url)["url"],
                            url_chain=[u for u in chain if u][:20],
                            referrer=(
                                _str(row["referrer"]) if "referrer" in columns else None
                            ),
                            tab_url=(
                                _str(row["tab_url"]) if "tab_url" in columns else None
                            ),
                            target_path=target_text,
                            filename=filename,
                            received_bytes=(
                                _int(row["received_bytes"])
                                if "received_bytes" in columns
                                else None
                            ),
                            total_bytes=(
                                _int(row["total_bytes"])
                                if "total_bytes" in columns
                                else None
                            ),
                            state=CHROMIUM_STATES.get(state_raw, f"state:{state_raw}"),
                            danger_type=CHROMIUM_DANGER.get(
                                danger_raw, f"danger:{danger_raw}"
                            ),
                            interrupt_reason=CHROMIUM_INTERRUPT.get(
                                interrupt_raw, f"interrupt:{interrupt_raw}"
                            ),
                            mime_type=(
                                _str(row["mime_type"]) if "mime_type" in columns else None
                            ),
                            opened=(
                                bool(row["opened"]) if "opened" in columns else None
                            ),
                            hash_value=(
                                _str(row["hash"])
                                if "hash" in columns and row["hash"]
                                else None
                            ),
                            hash_algorithm=None,
                            raw_metadata={},
                            warnings=warnings,
                        )
                    )
            outcome.profile = {
                "user": None,
                "browser": "chromium",
                "profile_name": None,
                "artifact_types": ["chromium_history"],
            }
        except sqlite3.DatabaseError as exc:
            outcome.warnings.append("database is corrupt or truncated")
            outcome.errors.append((None, f"sqlite error: {exc}"[:300]))
        finally:
            connection.close()
        return outcome


class FirefoxPlacesBackend(BrowserBackend):
    name = "firefox-sqlite"
    version = "1"

    def _connect(self, path: Path) -> sqlite3.Connection:
        uri = f"file:{path}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        connection.row_factory = sqlite3.Row
        return connection

    def parse(self, deadline: float) -> ParseOutcome:
        outcome = ParseOutcome()
        max_url = int(self.settings.browser_max_url_length)
        max_title = int(self.settings.browser_max_title_length)
        try:
            connection = self._connect(self.path)
        except sqlite3.Error as exc:
            outcome.errors.append((None, f"sqlite open failed: {exc}"[:300]))
            outcome.warnings.append("database cannot be opened read-only")
            return outcome
        try:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "moz_places" not in tables:
                outcome.errors.append((None, "missing moz_places table"))
                return outcome
            places = {
                row["id"]: row
                for row in connection.execute("SELECT * FROM moz_places")
            }
            outcome.records_seen += len(places)
            if "moz_historyvisits" in tables:
                for row in connection.execute(
                    "SELECT * FROM moz_historyvisits ORDER BY visit_date"
                ):
                    if time.monotonic() > deadline:
                        outcome.warnings.append("parser timeout during visits")
                        break
                    place = places.get(row["place_id"])
                    url = place["url"] if place is not None else None
                    title = place["title"] if place is not None else None
                    ts = from_unix_microseconds(row["visit_date"])
                    normalized = normalize_url(url, max_url)
                    title_text, _ = _truncate(title, max_title)
                    referrer = None
                    from_visit = row["from_visit"] if "from_visit" in row.keys() else None
                    if from_visit:
                        ref = connection.execute(
                            "SELECT place_id FROM moz_historyvisits WHERE id = ?",
                            (from_visit,),
                        ).fetchone()
                        if ref is not None:
                            ref_place = places.get(ref["place_id"])
                            referrer = ref_place["url"] if ref_place is not None else None
                    outcome.visits.append(
                        VisitRecord(
                            visit_id=0,
                            profile_id=self.profile_id,
                            source_artifact_id=self.artifact_id,
                            source_record_id=f"visit:{row['id']}",
                            user=None,
                            browser="firefox",
                            url=normalized["url"],
                            scheme=normalized["scheme"],
                            host=normalized["host"],
                            registrable_domain=normalized["registrable_domain"],
                            title=title_text,
                            visit_time_utc=ts.utc,
                            raw_timestamp=ts.raw,
                            visit_type=(
                                f"transition:{row['visit_type']}"
                                if "visit_type" in row.keys()
                                else None
                            ),
                            referrer_url=referrer,
                            visit_count=_int(
                                place["visit_count"] if place is not None else None
                            ),
                            typed_count=None,
                            hidden=(
                                bool(place["hidden"]) if place is not None else None
                            ),
                            warnings=[ts.warning] if ts.warning else [],
                        )
                    )
            outcome.profile = {
                "user": None,
                "browser": "firefox",
                "profile_name": None,
                "artifact_types": ["firefox_places"],
            }
        except sqlite3.DatabaseError as exc:
            outcome.warnings.append("database is corrupt or truncated")
            outcome.errors.append((None, f"sqlite error: {exc}"[:300]))
        finally:
            connection.close()
        return outcome


class WebCacheBackend(BrowserBackend):
    name = "webcache-ese"
    version = "1"

    @staticmethod
    def available() -> bool:
        try:
            import dissect.esedb  # noqa: F401
            return True
        except Exception:
            return False

    def parse(self, deadline: float) -> ParseOutcome:
        if not self.available():
            raise BackendUnavailable(
                "WebCache ESE backend is unavailable (dissect.esedb not installed)",
                details={"backend": self.name},
            )
        from dissect.esedb import EseDB  # type: ignore

        outcome = ParseOutcome()
        if not self.path.is_file():
            outcome.errors.append((None, "ESE database file is missing"))
            outcome.warnings.append("ESE database could not be opened")
            return outcome
        max_url = int(self.settings.browser_max_url_length)
        max_path = int(self.settings.browser_max_path_length)
        with open(self.path, "rb") as handle:
            try:
                db = EseDB(handle)
            except Exception as exc:
                outcome.warnings.append("ESE database cannot be opened")
                outcome.errors.append((None, f"ese open failed: {exc}"[:300]))
                return outcome
            try:
                containers: dict[int, dict[str, Any]] = {}
                try:
                    for row in db.table("Containers").records():
                        cid = _int(row.get("ContainerId"))
                        if cid is None:
                            continue
                        containers[cid] = {
                            "name": _str(row.get("Name")),
                            "partition": _str(row.get("PartitionId")),
                            "directory": _str(row.get("Directory")),
                        }
                except Exception as exc:
                    outcome.warnings.append("Containers table unreadable")
                    outcome.errors.append((None, f"containers: {exc}"[:200]))
                for table in db.tables():
                    if not table.name.startswith("Container_"):
                        continue
                    try:
                        container_id = int(table.name.split("_", 1)[1])
                    except (IndexError, ValueError):
                        continue
                    meta = containers.get(container_id, {})
                    container_name = meta.get("name") or table.name
                    try:
                        columns = {c.name for c in table.columns}
                    except Exception as exc:
                        outcome.errors.append((table.name, f"columns: {exc}"[:200]))
                        continue
                    if "Url" not in columns:
                        continue
                    try:
                        records = table.records()
                    except Exception as exc:
                        outcome.errors.append((table.name, f"records: {exc}"[:200]))
                        continue
                    while True:
                        if time.monotonic() > deadline:
                            outcome.warnings.append(
                                f"parser timeout in {table.name}"
                            )
                            break
                        try:
                            row = next(records)
                        except StopIteration:
                            break
                        except Exception as exc:  # noqa: BLE001 - corrupt record
                            outcome.records_seen += 1
                            outcome.errors.append(
                                (table.name, f"record: {exc}"[:200])
                            )
                            continue
                        outcome.records_seen += 1
                        self._consume_row(
                            outcome,
                            row,
                            columns,
                            container_name,
                            container_id,
                            max_url,
                            max_path,
                        )
            finally:
                try:
                    handle.close()
                except Exception:
                    pass
        outcome.profile = {
            "user": None,
            "browser": "webcache",
            "profile_name": None,
            "artifact_types": ["webcache"],
        }
        return outcome

    def _consume_row(
        self,
        outcome: ParseOutcome,
        row,
        columns: set[str],
        container_name: str,
        container_id: int,
        max_url: int,
        max_path: int,
    ) -> None:
        url_raw = _str(row.get("Url"))
        filename = _str(row.get("Filename"))
        redirect = _str(row.get("RedirectUrl"))
        timestamp_fields = {
            "AccessedTime": row.get("AccessedTime") if "AccessedTime" in columns else None,
            "ModifiedTime": row.get("ModifiedTime") if "ModifiedTime" in columns else None,
            "CreationTime": row.get("CreationTime") if "CreationTime" in columns else None,
            "ExpiryTime": row.get("ExpiryTime") if "ExpiryTime" in columns else None,
        }
        stamps = {key: from_ese(value) for key, value in timestamp_fields.items()}
        url_trunc, _ = _truncate(url_raw, max_url)
        normalized = normalize_url(url_trunc, max_url)
        name = container_name.lower()
        is_download = bool(filename) and (
            "download" in name or "content" in name
        )
        size = _int(row.get("FileSize"))
        warnings: list[str] = [
            stamp.warning for stamp in stamps.values() if stamp.warning
        ]

        if is_download:
            chain = [u for u in (normalized["url"], redirect) if u][:10]
            target = filename
            target_text, _ = _truncate(target, max_path)
            state = "complete"
            if size is None:
                state = "unknown"
            outcome.downloads.append(
                DownloadRecord(
                    download_id=0,
                    profile_id=self.profile_id,
                    source_artifact_id=self.artifact_id,
                    source_record_id=f"container{container_id}:{row.get('EntryId')}",
                    user=None,
                    browser="webcache",
                    start_time_utc=stamps["CreationTime"].utc
                    or stamps["ModifiedTime"].utc,
                    end_time_utc=stamps["AccessedTime"].utc,
                    start_raw=stamps["CreationTime"].raw,
                    end_raw=stamps["AccessedTime"].raw,
                    url=normalized["url"],
                    final_url=normalize_url(redirect, max_url)["url"]
                    if redirect
                    else normalized["url"],
                    url_chain=chain,
                    referrer=None,
                    tab_url=None,
                    target_path=target_text,
                    filename=os.path.basename(str(filename).replace("\\", "/"))
                    if filename
                    else None,
                    received_bytes=size,
                    total_bytes=size,
                    state=state,
                    danger_type=None,
                    interrupt_reason=None,
                    mime_type=None,
                    opened=None,
                    hash_value=None,
                    hash_algorithm=None,
                    raw_metadata={
                        "container": container_name,
                        "type": _int(row.get("Type")),
                        "flags": _int(row.get("Flags")),
                    },
                    warnings=warnings,
                )
            )
            return

        if not normalized["url"] or not normalized["scheme"]:
            return
        if normalized["scheme"] in {"iedownload", "res"} and not filename:
            return
        outcome.visits.append(
            VisitRecord(
                visit_id=0,
                profile_id=self.profile_id,
                source_artifact_id=self.artifact_id,
                source_record_id=f"container{container_id}:{row.get('EntryId')}",
                user=None,
                browser="webcache",
                url=normalized["url"],
                scheme=normalized["scheme"],
                host=normalized["host"],
                registrable_domain=normalized["registrable_domain"],
                title=filename,
                visit_time_utc=stamps["AccessedTime"].utc,
                raw_timestamp=stamps["AccessedTime"].raw,
                visit_type=container_name,
                referrer_url=redirect,
                visit_count=_int(row.get("AccessCount")),
                typed_count=None,
                hidden=None,
                warnings=warnings,
            )
        )
        if filename:
            outcome.cache.append(
                CacheRecord(
                    cache_id=0,
                    profile_id=self.profile_id,
                    source_artifact_id=self.artifact_id,
                    source_record_id=f"container{container_id}:{row.get('EntryId')}",
                    container=container_name,
                    user=None,
                    browser="webcache",
                    url=normalized["url"],
                    local_path=_truncate(filename, max_path)[0],
                    content_type=None,
                    created_time_utc=stamps["CreationTime"].utc,
                    accessed_time_utc=stamps["AccessedTime"].utc,
                    modified_time_utc=stamps["ModifiedTime"].utc,
                    expiry_time_utc=stamps["ExpiryTime"].utc,
                    size=size,
                    allocated=True,
                    response_preview=None,
                    warnings=warnings,
                )
            )


class FirefoxDownloadsBackend(BrowserBackend):
    name = "firefox-downloads-sqlite"
    version = "1"
    supported = True

    def parse(self, deadline: float) -> ParseOutcome:
        outcome = ParseOutcome()
        try:
            connection = sqlite3.connect(
                f"file:{self.path}?mode=ro&immutable=1", uri=True, timeout=10.0
            )
            connection.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            outcome.errors.append((None, f"sqlite open failed: {exc}"[:300]))
            return outcome
        try:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "moz_annos" not in tables:
                outcome.warnings.append("no moz_annos table (downloads unsupported)")
                return outcome
            for row in connection.execute(
                "SELECT * FROM moz_annos WHERE anno_attribute_id IN ("
                "SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%')"
            ):
                outcome.records_seen += 1
        except sqlite3.DatabaseError as exc:
            outcome.warnings.append("database is corrupt or truncated")
            outcome.errors.append((None, f"sqlite error: {exc}"[:300]))
        finally:
            connection.close()
        return outcome


BACKENDS = {
    "chromium_history": ChromiumHistoryBackend,
    "firefox_places": FirefoxPlacesBackend,
    "webcache": WebCacheBackend,
}


def backend_for(artifact_type: str) -> type[BrowserBackend]:
    return BACKENDS.get(artifact_type, BrowserBackend)


def sqlite_copy_for_analysis(source: Path, target_dir: Path) -> tuple[Path, list[str]]:
    """Copy a SQLite artifact, replaying WAL only onto the copy."""
    target_dir.mkdir(parents=True, exist_ok=True)
    destination = target_dir / source.name
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)
    used: list[str] = []
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = source.with_name(source.name + suffix)
        if not sidecar.is_file():
            continue
        copy = destination.with_name(destination.name + suffix)
        shutil.copyfile(sidecar, copy)
        os.chmod(copy, 0o600)
        used.append(sidecar.name)
    return destination, used
