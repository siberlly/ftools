"""Synthetic browser-artifact fixtures.

Everything here is generated from scratch: small SQLite databases with a
realistic Chromium `History` / Firefox `places.sqlite` schema and synthetic
rows. No real browsing history, URL, user or credential from the evidence image
is committed. WebCache ESE data cannot be generated, so ESE coverage is limited
to signature checks, corrupt-file handling and the real-evidence integration
test.
"""
from __future__ import annotations

import dataclasses
import os
import sqlite3
import struct
from pathlib import Path
from types import SimpleNamespace

from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import INDEX_SCHEMA_VERSION
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.services import build_services

EVIDENCE = "ev_0123456789ab"
SCAN = "scan_browser"
SOURCE_SHA = "d" * 64
SCANNER = "browser-test-scanner"

WEB_CACHE_PATH = (
    "Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
)
CHROMIUM_PATH = (
    "Users/IEUser/AppData/Local/Google/Chrome/User Data/Default/History"
)
EDGE_PATH = (
    "Users/IEUser/AppData/Local/Microsoft/Edge/User Data/Profile 1/History"
)
FIREFOX_PATH = (
    "Users/IEUser/AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default/"
    "places.sqlite"
)
DECOY_PATH = "Users/IEUser/Documents/History"
DOWNLOAD_PATH = "Users/Public/Downloads/SysInternals.exe"

ROWS = [
    (WEB_CACHE_PATH, "WebCacheV01.dat", 400, 23068672, False),
    (
        "Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.jfm",
        "WebCacheV01.jfm",
        401,
        16384,
        False,
    ),
    (
        "Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/V01.log",
        "V01.log",
        402,
        524288,
        False,
    ),
    (CHROMIUM_PATH, "History", 410, 262144, False),
    (f"{CHROMIUM_PATH}-wal", "History-wal", 411, 4096, False),
    (EDGE_PATH, "History", 412, 131072, False),
    (FIREFOX_PATH, "places.sqlite", 420, 98304, False),
    (DECOY_PATH, "History", 430, 1024, False),
    (DOWNLOAD_PATH, "SysInternals.exe", 124567, 57344, True),
    ("Users/Public/Downloads/notes.txt", "notes.txt", 500, 64, False),
    (
        "Users/IEUser/AppData/Local/Microsoft/Edge/User Data/Old/History",
        "History",
        440,
        2048,
        True,
    ),
]


def _row(full_path, name, inode, size, deleted):
    parent = full_path.rsplit("/", 1)[0] if "/" in full_path else ""
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return (
        EVIDENCE,
        SCAN,
        full_path,
        parent,
        name,
        extension,
        inode,
        1,
        128,
        "-/r" if deleted else "-/-",
        "file",
        0 if deleted else 1,
        1 if deleted else 0,
        size,
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "hash",
        None,
    )


def make_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EVIDENCE,
        resolved_source_path="/evidence/sample.E01",
        filename="sample.E01",
        extension=".e01",
        source_sha256=SOURCE_SHA,
        source_size=1024,
        source_mtime_ns=1,
        format="EWF",
        media_size=1024,
        sector_size=512,
        md5=None,
        sha1=None,
        ewfinfo_version="20200101",
        ewfinfo_duration_ms=1.0,
        ewfinfo_command={},
        raw_exposure_path="/raw/exposure",
        exposure_mode="explicit",
        exposure_verified_at="2020-01-01T00:00:00Z",
        exposure_details={},
        layout=Layout(
            scope="volume", filesystem="NTFS", offset_sectors=0, method="fsstat"
        ),
        registered_at="2020-01-01T00:00:00Z",
        status="ready",
        warnings=[],
    )


def build_browser_services(tmp_path: Path, *, rows=None):
    index_path = tmp_path / "index" / "filesystem.db"
    store = IndexStore(index_path)
    store.ensure_schema()
    store.begin_scan(
        EVIDENCE,
        SCAN,
        {
            "source_sha256": SOURCE_SHA,
            "raw_exposure_path": "/raw/exposure",
            "filesystem": "NTFS",
            "offset_sectors": 0,
            "fls_version": "",
            "index_schema_version": INDEX_SCHEMA_VERSION,
            "scanner_version": SCANNER,
        },
        "2020-01-01T00:00:00Z",
    )
    data = rows if rows is not None else ROWS
    inserted = [_row(*item) for item in data]
    store.insert_entries(inserted)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(inserted),
        entries_indexed=len(inserted),
        parse_errors=0,
        deleted_files=sum(1 for row in inserted if row[12]),
        deleted_directories=0,
        allocated_files=sum(1 for row in inserted if not row[12]),
        allocated_directories=0,
        error_code=None,
        error_message=None,
    )
    settings = dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=index_path,
        triage_db_path=tmp_path / "var" / "cases" / "triage.db",
        virustotal_db_path=tmp_path / "var" / "cases" / "virustotal.db",
        virustotal_secret_dir=tmp_path / "var" / "secrets",
        registry_db_path=tmp_path / "var" / "cases" / "registry.db",
        evtx_db_path=tmp_path / "var" / "cases" / "evtx.db",
        browser_db_path=tmp_path / "var" / "cases" / "browser_artifacts.db",
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        secret_key_path=tmp_path / "var" / "secret.key",
        auto_index=False,
        index_scanner_version=SCANNER,
        browser_max_records=1000,
        browser_max_query_length=256,
        browser_page_size_max=500,
    )
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    return services, make_record()


def entry_id(services, path):
    return services.indexer.resolve_entry_path(make_record(), path).id


def synthetic_chromium_history(
    path: Path,
    *,
    base_time: int = 13313020720000000,
    with_downloads: bool = True,
) -> Path:
    """Build a small Chromium History database with synthetic rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.executescript(
        """
        CREATE TABLE urls(
          id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
          visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER,
          hidden INTEGER
        );
        CREATE TABLE visits(
          id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
          visit_time INTEGER NOT NULL, from_visit INTEGER,
          transition INTEGER DEFAULT 0 NOT NULL,
          segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL
        );
        CREATE TABLE downloads(
          id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR,
          target_path LONGVARCHAR, start_time INTEGER, received_bytes INTEGER,
          total_bytes INTEGER, state INTEGER, danger_type INTEGER,
          interrupt_reason INTEGER, hash BLOB, end_time INTEGER, opened INTEGER,
          last_access_time INTEGER, transient INTEGER, referrer VARCHAR,
          site_url VARCHAR, tab_url VARCHAR, tab_referrer_url VARCHAR,
          http_method VARCHAR, by_ext_id VARCHAR, by_ext_name VARCHAR,
          etag VARCHAR, last_modified VARCHAR, mime_type VARCHAR,
          original_mime_type VARCHAR
        );
        CREATE TABLE downloads_url_chains(
          id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR
        );
        """
    )
    urls = [
        (1, "https://www.sysinternals.com/SysInternals.exe", "SysInternals", 3, 1, base_time, 0),
        (2, "https://example.test/download", "Example download", 2, 0, base_time + 10, 0),
        (3, "http://198.51.100.7/payload.zip", "Payload", 1, 0, base_time + 20, 0),
        (4, "https://example.test/\u00fcber-unicode-\U0001f600", "Unicode \u00e9\u00e8", 1, 0, base_time + 30, 0),
    ]
    connection.executemany(
        "INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?, ?)", urls
    )
    visits = [
        (1, 1, base_time, 0, 805306368, 1, 5000),
        (2, 2, base_time + 10, 0, 805306368, 1, 1000),
        (3, 2, base_time + 11, 2, 805306368, 1, 2000),
        (4, 3, base_time + 20, 0, 805306368, 1, 500),
        (5, 4, base_time + 30, 0, 805306368, 1, 100),
    ]
    connection.executemany(
        "INSERT INTO visits (id, url, visit_time, from_visit, transition,"
        " segment_id, visit_duration) VALUES (?, ?, ?, ?, ?, ?, ?)",
        visits,
    )
    if with_downloads:
        downloads = [
            (
                1, "guid-1", "C:\\Users\\IEUser\\Downloads\\SysInternals.exe",
                "C:\\Users\\IEUser\\Downloads\\SysInternals.exe", base_time,
                57344, 57344, 1, 0, 0, None, base_time + 500, 1,
                base_time + 600, 0, "https://www.example.test/ref",
                "https://www.example.test/", "https://www.example.test/",
                None, "GET", None, None, None, None,
                "application/x-msdownload", "application/x-msdownload",
            ),
            (
                2, "guid-2", "C:\\Users\\IEUser\\Downloads\\payload.zip",
                "C:\\Users\\IEUser\\Downloads\\payload.zip", base_time + 20,
                10, 4096, 0, 0, 0, None, base_time + 25, 0,
                base_time + 30, 0, "http://198.51.100.7/payload.zip",
                "http://198.51.100.7/", "http://198.51.100.7/",
                None, "GET", None, None, None, None,
                "application/zip", "application/zip",
            ),
        ]
        connection.executemany(
            "INSERT INTO downloads VALUES (" + ",".join("?" * 26) + ")",
            downloads,
        )
        connection.executemany(
            "INSERT INTO downloads_url_chains VALUES (?, ?, ?)",
            [
                (1, 0, "https://www.sysinternals.com/SysInternals.exe"),
                (1, 1, "https://download.sysinternals.com/files/SysInternals.zip"),
                (2, 0, "http://198.51.100.7/redirect"),
                (2, 1, "http://198.51.100.7/payload.zip"),
            ],
        )
    connection.commit()
    connection.close()
    return path


def synthetic_firefox_places(path: Path, *, base_micros: int = 1668550000000000) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.executescript(
        """
        CREATE TABLE moz_places(
          id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
          rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0,
          hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL,
          frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER,
          guid TEXT
        );
        CREATE TABLE moz_historyvisits(
          id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
          visit_date INTEGER, visit_type INTEGER, session INTEGER
        );
        """
    )
    connection.executemany(
        "INSERT INTO moz_places (id, url, title, rev_host, visit_count,"
        " hidden, typed, frecency, last_visit_date, guid)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "https://www.sysinternals.com/", "Sysinternals", "moc.slannretisys.www.", 2, 0, 0, 100, base_micros, "g1"),
            (2, "https://example.test/page", "Example", "tset.elpmaxe.", 1, 0, 0, 50, base_micros + 1000, "g2"),
        ],
    )
    connection.executemany(
        "INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date,"
        " visit_type, session) VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, 0, 1, base_micros, 1, 0),
            (2, 1, 2, base_micros + 1000, 2, 0),
        ],
    )
    connection.commit()
    connection.close()
    return path


def synthetic_ese_header(*, page_size: int = 32768, pages: int = 2) -> bytes:
    """A minimal ESE file header; not a parsable database."""
    header = bytearray(4096)
    struct.pack_into("<I", header, 0, 0xF9131DA8)
    header[4:8] = b"\xef\xcd\xab\x89"
    struct.pack_into("<I", header, 8, 0x620)
    struct.pack_into("<I", header, 12, 0x00000D13)
    struct.pack_into("<I", header, 236, page_size)
    struct.pack_into("<I", header, 240, pages)
    return bytes(header)


def stub_browser_extract(services, payloads: dict[int, bytes]):
    """Route filesystem extraction to synthetic payloads keyed by inode."""
    calls = []

    def extract(image_path, evidence_id, inode, case_id, offset_sectors=0, **kwargs):
        exports = services.policy.case_exports_dir(case_id)
        exports.mkdir(parents=True, exist_ok=True)
        path = exports / f"browser_{inode}_{len(calls)}.bin"
        path.write_bytes(payloads.get(inode, b""))
        os.chmod(path, 0o600)
        calls.append(path)
        return SimpleNamespace(output_path=str(path), inode=inode)

    services.filesystem.extract = extract
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    return calls
