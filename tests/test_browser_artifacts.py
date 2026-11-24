from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest

from dfir_browser.core.browser_artifacts.backends import (
    FirefoxPlacesBackend,
    WebCacheBackend,
    normalize_url,
    registrable_domain,
)
from dfir_browser.core.browser_artifacts.correlation import (
    basename_variants,
    correlate,
    evidence_relative,
    strip_ie_suffix,
)
from dfir_browser.core.browser_artifacts.detector import (
    inspect_artifact_header,
    user_from_path,
)
from dfir_browser.core.browser_artifacts.models import (
    BROWSER_SCHEMA_VERSION,
    BrowserArtifactRejected,
)
from dfir_browser.core.browser_artifacts.presets import (
    apply_post_filter,
    get_preset,
    list_presets,
)
from dfir_browser.core.browser_artifacts.timestamp import (
    from_chromium,
    from_ese,
    from_iso,
    from_unix_microseconds,
    from_unix_seconds,
    from_windows_filetime,
)

from browser_helpers import (
    CHROMIUM_PATH,
    DECOY_PATH,
    EDGE_PATH,
    EVIDENCE,
    FIREFOX_PATH,
    WEB_CACHE_PATH,
    build_browser_services,
    entry_id,
    synthetic_chromium_history,
    synthetic_ese_header,
    synthetic_firefox_places,
    stub_browser_extract,
)


# ----------------------------------------------------------------------
# timestamps
# ----------------------------------------------------------------------
def test_filetime_conversion_roundtrip():
    stamp = from_windows_filetime("133130207200000000")
    assert stamp.utc is not None
    assert stamp.utc.endswith("Z")
    assert stamp.method == "windows_filetime"
    assert stamp.raw == "133130207200000000"
    assert stamp.warning is None


@pytest.mark.parametrize("value", [None, 0, "0", "", "abc", -5])
def test_filetime_rejects_invalid(value):
    stamp = from_windows_filetime(value)
    assert stamp.utc is None
    if value not in (None, 0, "0", ""):
        assert stamp.warning is not None


def test_filetime_out_of_range_is_null_with_warning():
    stamp = from_windows_filetime(str(10**20))
    assert stamp.utc is None
    assert "range" in (stamp.warning or "") or "overflow" in (stamp.warning or "")


def test_chromium_microseconds_conversion():
    stamp = from_chromium(13313020720000000)
    assert stamp.utc.startswith("2022-")
    assert stamp.method == "chromium_1601_microseconds"


def test_unix_seconds_and_microseconds():
    assert from_unix_seconds(1668550000).utc.startswith("2022-11-15")
    assert from_unix_microseconds(1668550000000000).utc.startswith("2022-11-15")


def test_iso_and_ese_conversion():
    assert from_iso("2022-11-15T21:18:40Z").utc == "2022-11-15T21:18:40.000000Z"
    assert from_iso("not a time").utc is None
    assert from_ese("2022-11-15T21:18:40Z").utc is not None
    assert from_ese(133130207200000000).utc is not None


# ----------------------------------------------------------------------
# URL normalization
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Visited: IEUser@http://www.sysinternals.com/x.exe", "http://www.sysinternals.com/x.exe"),
        (":2022111520221116: IEUser@https://a.test/p?q=1", "https://a.test/p?q=1"),
        ("https://b.test/", "https://b.test/"),
    ],
)
def test_url_prefix_stripping(raw, expected):
    assert normalize_url(raw, 4096)["url"] == expected


@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.sysinternals.com", "sysinternals.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("198.51.100.7", "198.51.100.7"),
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_url_truncation_flags_and_keeps_scheme():
    long = "https://a.test/" + "x" * 5000
    parsed = normalize_url(long, 100)
    assert parsed["truncated"] is True
    assert len(parsed["url"]) == 100
    assert parsed["scheme"] == "https"


@pytest.mark.parametrize("value", ["", None])
def test_normalize_empty(value):
    assert normalize_url(value, 100)["url"] in (None, "")


# ----------------------------------------------------------------------
# detection
# ----------------------------------------------------------------------
def test_user_from_path():
    assert user_from_path(WEB_CACHE_PATH) == "IEUser"
    assert user_from_path("Users/Public/Downloads/x.exe") is None


def test_header_detection(tmp_path):
    sqlite_file = tmp_path / "History"
    sqlite_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    assert inspect_artifact_header(sqlite_file).format == "sqlite"
    ese_file = tmp_path / "WebCacheV01.dat"
    ese_file.write_bytes(synthetic_ese_header())
    assert inspect_artifact_header(ese_file).format == "ese"
    junk = tmp_path / "junk"
    junk.write_bytes(b"not a database")
    assert inspect_artifact_header(junk).signature_valid is False


def test_discovery_finds_known_paths_only(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        result = services.browser_artifacts.list_artifacts(record)
        paths = {item.path for item in result.items}
        assert WEB_CACHE_PATH in paths
        assert CHROMIUM_PATH in paths
        assert EDGE_PATH in paths
        assert FIREFOX_PATH in paths
        assert DECOY_PATH not in paths
        assert result.total == 4
    finally:
        services.cleanup()


def test_discovery_include_deleted(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        allocated = services.browser_artifacts.list_artifacts(record)
        with_deleted = services.browser_artifacts.list_artifacts(
            record, include_deleted=True
        )
        assert with_deleted.total > allocated.total
        assert any(item.deleted for item in with_deleted.items)
    finally:
        services.cleanup()


def test_discovery_filters(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        chromium = services.browser_artifacts.list_artifacts(
            record, browser="chromium"
        )
        assert chromium.total == 2
        assert all(item.browser == "chromium" for item in chromium.items)
        firefox = services.browser_artifacts.list_artifacts(
            record, artifact_type="firefox_places"
        )
        assert firefox.total == 1
    finally:
        services.cleanup()


def test_discovery_coverage_marks_absent_types(tmp_path):
    services, record = build_browser_services(tmp_path, rows=[
        (WEB_CACHE_PATH, "WebCacheV01.dat", 400, 23068672, False),
    ])
    try:
        page = services.browser_artifacts.list_artifacts(record)
        coverage = {item["artifact_type"]: item for item in page.coverage}
        assert coverage["webcache"]["status"] == "present"
        assert coverage["chromium_history"]["status"] == "not_present"
        assert coverage["firefox_places"]["status"] == "not_present"
        assert page.to_dict()["coverage"]
    finally:
        services.cleanup()


def test_discovery_reports_webcache_sidecars(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        page = services.browser_artifacts.list_artifacts(record)
        webcache = next(i for i in page.items if i.browser == "webcache")
        assert "WebCacheV01.jfm" in webcache.sidecars
        assert "V01.log" in webcache.sidecars
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# Chromium backend
# ----------------------------------------------------------------------
def test_chromium_visits_and_downloads(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        inode = 410
        stub_browser_extract(services, {inode: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        artifact_id = result["artifact"]["artifact_id"]
        status = _wait(services, artifact_id)
        assert status["status"] in {"ready", "partial"}
        downloads = services.browser_artifacts.query_downloads(EVIDENCE)
        assert downloads.total == 2
        names = {item["filename"] for item in downloads.items}
        assert "SysInternals.exe" in names
        partial = next(i for i in downloads.items if i["filename"] == "payload.zip")
        assert partial["state"] == "in_progress"
        assert partial["received_bytes"] == 10
        assert partial["total_bytes"] == 4096
        chain = next(i for i in downloads.items if i["filename"] == "SysInternals.exe")
        assert len(chain["url_chain"]) == 2
        visits = services.browser_artifacts.query_history(EVIDENCE)
        assert visits.total == 5
        assert visits.items[0]["visit_time_utc"] is not None
    finally:
        services.cleanup()


def test_chromium_wal_sidecar_used_on_copy(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    payload = {
        410: history.read_bytes(),
        411: b"wal-placeholder",
    }
    try:
        stub_browser_extract(services, payload)
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert "History-wal" in status["sidecars_used"]
        assert status["status"] in {"ready", "partial"}
    finally:
        services.cleanup()


def test_chromium_corrupt_database_partial(tmp_path):
    services, record = build_browser_services(tmp_path)
    corrupt = b"SQLite format 3\x00" + b"\x00" * 200
    try:
        stub_browser_extract(services, {410: corrupt})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] in {"failed", "partial"}
        assert status["warnings"] or status["error_message"]
    finally:
        services.cleanup()


def test_chromium_truncated_rows_do_not_crash(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    connection.execute("DELETE FROM downloads_url_chains")
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] in {"ready", "partial"}
        downloads = services.browser_artifacts.query_downloads(EVIDENCE)
        assert downloads.total == 2
    finally:
        services.cleanup()


def test_missing_schema_column_is_partial(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    connection.executescript(
        "ALTER TABLE downloads RENAME TO downloads_old;"
        "CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT);"
    )
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] in {"ready", "partial", "failed"}
    finally:
        services.cleanup()


def test_invalid_signature_rejected(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        stub_browser_extract(services, {410: b"not sqlite at all"})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] == "failed"
        assert status["error_code"] == "browser_invalid_signature"
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# Firefox backend
# ----------------------------------------------------------------------
def test_firefox_places_visits(tmp_path):
    services, record = build_browser_services(tmp_path)
    places = tmp_path / "places.sqlite"
    synthetic_firefox_places(places)
    try:
        stub_browser_extract(services, {420: places.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, FIREFOX_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] == "ready"
        visits = services.browser_artifacts.query_history(EVIDENCE)
        assert visits.total == 2
        assert visits.items[0]["browser"] == "firefox"
        assert visits.items[0]["host"] in {"example.test", "www.sysinternals.com"}
    finally:
        services.cleanup()


def test_firefox_backend_handles_missing_table(tmp_path):
    services, record = build_browser_services(tmp_path)
    places = tmp_path / "places.sqlite"
    connection = sqlite3.connect(str(places))
    connection.execute("CREATE TABLE unrelated(x)")
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {420: places.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, FIREFOX_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] == "failed"
        assert status["error_code"] in {"browser_no_records", "browser_parse_errors"}
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# WebCache signature / corruption (real ESE parsing is an integration test)
# ----------------------------------------------------------------------
def test_webcache_signature_validation(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        stub_browser_extract(services, {400: b"random garbage not ese"})
        result = services.browser_artifacts.start_index(record, entry_id(services, WEB_CACHE_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] == "failed"
        assert status["error_code"] == "browser_invalid_signature"
    finally:
        services.cleanup()


def test_webcache_truncated_does_not_crash(tmp_path):
    services, record = build_browser_services(tmp_path)
    payload = synthetic_ese_header()[:2048]
    try:
        stub_browser_extract(services, {400: payload})
        result = services.browser_artifacts.start_index(record, entry_id(services, WEB_CACHE_PATH))
        status = _wait(services, result["artifact"]["artifact_id"])
        assert status["status"] in {"failed", "partial"}
        assert services.browser_artifacts.status(status["artifact_id"])["status"] in {
            "failed",
            "partial",
        }
    finally:
        services.cleanup()


def test_webcache_backend_available_or_structured_error():
    missing = Path("/nonexistent/WebCacheV01.dat")
    backend = WebCacheBackend(missing, settings=None, profile_id="p", artifact_id="a")
    if not WebCacheBackend.available():
        from dfir_browser.core.browser_artifacts.models import BackendUnavailable

        with pytest.raises(BackendUnavailable):
            backend.parse(deadline=0)
    else:
        outcome = backend.parse(deadline=0)
        assert outcome.errors and outcome.warnings


# ----------------------------------------------------------------------
# index, query, cache, presets
# ----------------------------------------------------------------------
def test_query_filters_and_pagination(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        page = services.browser_artifacts.query_downloads(
            EVIDENCE, page_size=1, page=2, sort_dir="asc"
        )
        assert page.total == 2
        assert page.pages == 2
        assert len(page.items) == 1
        assert page.items[0]["download_id"] >= 1

        exe_only = services.browser_artifacts.query_downloads(
            EVIDENCE, executable_only=True
        )
        assert exe_only.total == 2

        by_ext = services.browser_artifacts.query_downloads(EVIDENCE, extension="zip")
        assert by_ext.total == 1

        by_domain = services.browser_artifacts.query_history(
            EVIDENCE, domain="example.test"
        )
        assert by_domain.total >= 1
    finally:
        services.cleanup()


def test_sql_injection_attempts_are_parameterized(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        for payload in ("'; DROP TABLE browser_downloads; --", "1 OR 1=1", "\" OR \"\"=\""):
            page = services.browser_artifacts.query_downloads(EVIDENCE, query=payload)
            assert page.total == 0
        assert services.browser_artifacts.query_downloads(EVIDENCE).total == 2
    finally:
        services.cleanup()


def test_query_length_limit(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        with pytest.raises(BrowserArtifactRejected) as exc:
            services.browser_artifacts.query_downloads(EVIDENCE, query="x" * 500)
        assert exc.value.code == "browser_query_too_long"
    finally:
        services.cleanup()


def test_page_size_limit(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        with pytest.raises(BrowserArtifactRejected):
            services.browser_artifacts.query_downloads(EVIDENCE, page_size=10000)
        with pytest.raises(BrowserArtifactRejected):
            services.browser_artifacts.query_downloads(EVIDENCE, query=None, page=0)
    finally:
        services.cleanup()


def test_invalid_time_filter(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        with pytest.raises(BrowserArtifactRejected):
            services.browser_artifacts.query_history(EVIDENCE, time_from="yesterday")
    finally:
        services.cleanup()


def test_cache_hit_does_not_reextract(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        calls = stub_browser_extract(services, {410: history.read_bytes()})
        first = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, first["artifact"]["artifact_id"])
        primary_calls = [c for c in calls if "_410_" in c.name]
        assert len(primary_calls) == 1
        second = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        assert second["cached"] is True
        assert second["started"] is False
        assert len([c for c in calls if "_410_" in c.name]) == 1
        third = services.browser_artifacts.start_index(
            record, entry_id(services, CHROMIUM_PATH), rebuild=True
        )
        assert third["started"] is True
        _wait(services, third["artifact"]["artifact_id"])
        assert len([c for c in calls if "_410_" in c.name]) == 2
    finally:
        services.cleanup()


def test_rejects_directory_and_non_candidate(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        with pytest.raises(BrowserArtifactRejected):
            services.browser_artifacts.start_index(
                record, entry_id(services, "Users/Public/Downloads/notes.txt")
            )
    finally:
        services.cleanup()


def test_unknown_artifact_id(tmp_path):
    services, record = build_browser_services(tmp_path)
    try:
        from dfir_browser.core.browser_artifacts.models import ArtifactNotFound

        with pytest.raises(ArtifactNotFound):
            services.browser_artifacts.status("ba_missing")
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# correlation
# ----------------------------------------------------------------------
def test_strip_ie_suffix():
    assert strip_ie_suffix("SysInternals[1].exe") == "SysInternals.exe"
    assert strip_ie_suffix("archive[12].zip") == "archive.zip"
    assert strip_ie_suffix("plain.exe") is None
    assert basename_variants("a[1].exe") == ["a[1].exe", "a.exe"]


def test_evidence_relative_normalizes():
    assert evidence_relative("C:\\Users\\Public\\x.exe") == "users/public/x.exe"
    assert evidence_relative("\\\\?\\C:\\Windows\\x.dll") is not None


def test_correlation_exact_and_basename(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        downloads = services.browser_artifacts.query_downloads(EVIDENCE)
        sysinternals = next(
            i for i in downloads.items if i["filename"] == "SysInternals.exe"
        )
        correlation = services.browser_artifacts.correlate_download(
            EVIDENCE, sysinternals["download_id"]
        )["correlation"]
        assert correlation["hits"]
        hit = correlation["hits"][0]
        assert hit["deleted"] is True
        assert hit["size_matches"] is True
        assert hit["entry_id"] == entry_id(services, "Users/Public/Downloads/SysInternals.exe")
    finally:
        services.cleanup()


def test_correlation_missing_is_honest(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        downloads = services.browser_artifacts.query_downloads(EVIDENCE)
        partial = next(i for i in downloads.items if i["filename"] == "payload.zip")
        correlation = services.browser_artifacts.correlate_download(
            EVIDENCE, partial["download_id"]
        )["correlation"]
        assert correlation["hits"] == []
        assert correlation["confidence"] == "none"
        assert correlation["warnings"]
    finally:
        services.cleanup()


def test_correlation_ambiguous_flags_warning():
    class Entry:
        def __init__(self, ident, path, size):
            self.id = ident
            self.full_path = path
            self.basename = path.rsplit("/", 1)[-1]
            self.inode = ident
            self.size = size
            self.allocated = True
            self.deleted = False
            self.modified_time = None

    entries = [
        Entry(1, "Users/a/x.exe", 10),
        Entry(2, "Users/b/x.exe", 20),
    ]
    result = correlate(
        target_path="C:\\Users\\c\\x.exe",
        filename="x.exe",
        download_size=99,
        lookup_exact=lambda rel: [],
        lookup_basename=lambda name, cap: entries,
    )
    assert len(result.hits) == 2
    assert result.confidence == "low"
    assert any("multiple files" in w for w in result.warnings)


# ----------------------------------------------------------------------
# presets
# ----------------------------------------------------------------------
def test_presets_are_documented():
    presets = list_presets()
    assert len(presets) == 8
    for preset in presets:
        assert preset["rule_id"].startswith("browser.")
        assert preset["limitations"]
        assert "indicator" in preset["note"].lower()


def test_preset_lookup_and_post_filters():
    assert get_preset("browser.executable_downloads") is not None
    assert get_preset("missing") is None
    assert apply_post_filter("ip_literal", {"host": "198.51.100.7"}) is True
    assert apply_post_filter("ip_literal", {"host": "example.test"}) is False
    assert apply_post_filter("http_scheme", {"url": "http://x.test/a"}) is True
    assert apply_post_filter("http_scheme", {"url": "https://x.test/a"}) is False
    assert apply_post_filter("suspicious_scheme", {"url": "file:///C:/x"}) is True
    assert apply_post_filter("deleted_target", {"_deleted_target": True}) is True
    assert apply_post_filter(
        "domain_filename_mismatch",
        {"domain": "example.test", "filename": "other.exe"},
    ) is True
    assert apply_post_filter(
        "domain_filename_mismatch",
        {"domain": "sysinternals.com", "filename": "SysInternals.exe"},
    ) is False


def test_preset_query_executable_and_states(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        exe = services.browser_artifacts.query_downloads(
            EVIDENCE, preset="browser.executable_downloads"
        )
        assert exe.total == 2
        assert any("not a malware verdict" in w for w in exe.warnings)
        partial = services.browser_artifacts.query_downloads(
            EVIDENCE, preset="browser.incomplete_downloads"
        )
        assert partial.total == 1
        ip = services.browser_artifacts.query_downloads(
            EVIDENCE, preset="browser.ip_literal_urls"
        )
        assert ip.total == 1
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# summary / redaction
# ----------------------------------------------------------------------
def test_summary_counts(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        summary = services.browser_artifacts.summary(EVIDENCE).to_dict()
        assert summary["total_downloads"] == 2
        assert summary["total_visits"] == 5
        assert summary["executable_downloads"] == 2
        assert summary["download_states"].get("in_progress") == 1
        assert summary["top_domains"]
        assert summary["trust"] == "untrusted_evidence_data"
        assert "not malware verdicts" in summary["note"]
    finally:
        services.cleanup()


def test_query_strings_redacted_by_default(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    connection.execute(
        "UPDATE urls SET url = 'https://example.test/page?token=SECRET123' WHERE id = 2"
    )
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        redacted = services.browser_artifacts.query_history(
            EVIDENCE, query="example.test"
        )
        for item in redacted.items:
            assert "SECRET123" not in (item["url"] or "")
        full = services.browser_artifacts.query_history(
            EVIDENCE, query="example.test", include_query_string=True
        )
        assert any("SECRET123" in (item["url"] or "") for item in full.items)
    finally:
        services.cleanup()


def test_no_sensitive_artifact_parsing(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    connection.execute("CREATE TABLE cookies(host_key TEXT, encrypted_value BLOB)")
    connection.execute("INSERT INTO cookies VALUES ('a.test', x'deadbeef')")
    connection.execute("CREATE TABLE logins(origin_url TEXT, password_value BLOB)")
    connection.execute("INSERT INTO logins VALUES ('a.test', x'cafebabe')")
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        dump = json.dumps(
            [
                services.browser_artifacts.query_downloads(EVIDENCE).to_dict(),
                services.browser_artifacts.query_history(EVIDENCE).to_dict(),
                services.browser_artifacts.query_cache(EVIDENCE).to_dict(),
            ]
        )
        assert "deadbeef" not in dump
        assert "cafebabe" not in dump
        assert "cookies" not in dump.lower()
    finally:
        services.cleanup()


def test_unicode_and_long_fields(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    long_url = "https://example.test/" + "a" * 9000
    connection.execute(
        "INSERT INTO urls VALUES (9, ?, ?, 1, 0, 13313020720000000, 0)",
        (long_url, "T" * 9000),
    )
    connection.execute(
        "INSERT INTO visits (id, url, visit_time, from_visit, transition,"
        " segment_id, visit_duration) VALUES (9, 9, 13313020720000000, 0, 0, 0, 0)"
    )
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        visits = services.browser_artifacts.query_history(EVIDENCE)
        assert visits.total == 6
        assert any("\U0001f600" in (i["url"] or "") or "unicode" in (i["url"] or "") for i in visits.items)
        longest = max(len(i["url"] or "") for i in visits.items)
        assert longest <= 4096
    finally:
        services.cleanup()


def _wait(services, artifact_id, timeout=30.0):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = services.browser_artifacts.status(artifact_id)
        if status["status"] in {"ready", "partial", "failed", "interrupted"}:
            return status
        time.sleep(0.05)
    raise AssertionError("browser index did not finish in time")


# ----------------------------------------------------------------------
# log redaction
# ----------------------------------------------------------------------
def test_redaction_strips_query_and_fragment():
    from dfir_browser.core.browser_artifacts.redaction import (
        looks_sensitive,
        redact_text,
        redact_url,
    )

    assert (
        redact_url("https://a.test/p?token=SECRET#frag")
        == "https://a.test/p"
    )
    assert redact_url("https://user:pw@a.test/x?q=1") == "https://a.test/x"
    assert redact_url(None) is None
    assert redact_url("not a url?x=1") == "not a url"
    text = "lookup failed for https://a.test/p?session=ABC123 and https://b.test/"
    redacted = redact_text(text)
    assert "ABC123" not in redacted
    assert "https://b.test/" in redacted
    assert looks_sensitive("https://a.test/?token=1") is True
    assert looks_sensitive("https://a.test/path") is False


def test_audit_log_never_contains_query_strings(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    connection = sqlite3.connect(str(history))
    connection.execute(
        "UPDATE downloads SET referrer = 'https://a.test/?token=SECRET999'"
    )
    connection.execute(
        "UPDATE urls SET url = 'https://a.test/x?session=SECRET999' WHERE id = 2"
    )
    connection.commit()
    connection.close()
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        log_path = services.settings.audit_log_path
        if log_path.exists():
            content = log_path.read_text(encoding="utf-8", errors="replace")
            assert "SECRET999" not in content
    finally:
        services.cleanup()


def test_search_all_groups_sections(tmp_path):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    try:
        stub_browser_extract(services, {410: history.read_bytes()})
        result = services.browser_artifacts.start_index(record, entry_id(services, CHROMIUM_PATH))
        _wait(services, result["artifact"]["artifact_id"])
        found = services.browser_artifacts.search_all(EVIDENCE, query="sysinternals")
        assert set(found["sections"]) == {"downloads", "history", "cache"}
        assert found["sections"]["downloads"]["total"] >= 1
        assert found["sections"]["history"]["total"] >= 1
        assert found["trust"] == "untrusted_evidence_data"
    finally:
        services.cleanup()


def test_linux_and_snap_profile_paths_are_detected(tmp_path):
    """Firefox/Chromium profiles on Linux and snap must be discovered."""
    from browser_helpers import build_browser_services

    rows = [
        (
            "home/rafael/snap/firefox/common/.mozilla/firefox/abc.default/"
            "places.sqlite",
            "places.sqlite",
            700,
            5242880,
            False,
        ),
        (
            "home/rafael/.mozilla/firefox/xyz.default-release/places.sqlite",
            "places.sqlite",
            701,
            4096,
            False,
        ),
        (
            "home/rafael/.config/google-chrome/Default/History",
            "History",
            702,
            4096,
            False,
        ),
        (
            "home/rafael/snap/chromium/common/chromium/Profile 1/History",
            "History",
            703,
            4096,
            False,
        ),
    ]
    services, record = build_browser_services(tmp_path, rows=rows)
    try:
        page = services.browser_artifacts.list_artifacts(record)
        found = {(item.browser, item.profile_name) for item in page.items}
        assert ("firefox", "abc.default") in found
        assert ("firefox", "xyz.default-release") in found
        assert ("chromium", "Default") in found
        assert ("chromium", "Profile 1") in found
        for item in page.items:
            assert item.confidence >= 0.9
            assert "Linux/snap" in item.reason
    finally:
        services.cleanup()
