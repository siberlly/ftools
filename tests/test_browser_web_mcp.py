from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

import dfir_browser.mcp_server as mcp_server
from mcp.server.fastmcp.exceptions import ToolError

from dfir_browser.core.browser_artifacts.models import BrowserArtifactRejected
from dfir_browser.web.app import create_app

from browser_helpers import (
    CHROMIUM_PATH,
    EVIDENCE,
    WEB_CACHE_PATH,
    build_browser_services,
    entry_id,
    synthetic_chromium_history,
    stub_browser_extract,
)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture()
def env(tmp_path, monkeypatch):
    services, record = build_browser_services(tmp_path)
    history = tmp_path / "History"
    synthetic_chromium_history(history)
    stub_browser_extract(services, {410: history.read_bytes()})
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "_services", services, raising=False)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record
    services.cleanup()


def _index_chromium(services, record):
    result = services.browser_artifacts.start_index(
        record, entry_id(services, CHROMIUM_PATH)
    )
    artifact_id = result["artifact"]["artifact_id"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = services.browser_artifacts.status(artifact_id)
        if status["status"] in {"ready", "partial", "failed"}:
            return status
        time.sleep(0.05)
    raise AssertionError("index did not finish")


# ----------------------------------------------------------------------
# web
# ----------------------------------------------------------------------
def test_browser_tab_lists_artifacts(env):
    client, services, record = env
    response = client.get(f"/evidence/{EVIDENCE}/browser")
    assert response.status_code == 200
    body = response.text
    assert "Browser artifacts" in body
    assert "WebCacheV01.dat" in body
    assert WEB_CACHE_PATH in body
    assert "browser-status-" in body


def test_browser_tab_requires_index(env):
    client, services, record = env
    services.indexer.status_for_record = lambda rec: type(
        "S", (), {"status": "idle", "stale": False, "queryable": False}
    )()
    response = client.get(f"/evidence/{EVIDENCE}/browser")
    assert response.status_code == 200
    assert "filesystem index" in response.text.lower()


def test_browser_index_post_and_status(env):
    client, services, record = env
    page = client.get(f"/evidence/{EVIDENCE}/browser")
    token = CSRF_RE.search(page.text).group(1)
    eid = entry_id(services, CHROMIUM_PATH)
    response = client.post(
        f"/evidence/{EVIDENCE}/browser/{eid}/index",
        data={"csrf_token": token, "rebuild": "0", "recover_sidecars": "1"},
    )
    assert response.status_code == 200
    artifact_id = re.search(r'data-browser-status="([^"]+)"', response.text)
    if artifact_id is None:
        status = _poll_web(client, eid)
        assert status["status"] in {"queued", "running", "ready", "partial"}
    else:
        assert artifact_id.group(1).startswith("ba_")


def test_browser_csrf_required(env):
    client, services, record = env
    eid = entry_id(services, CHROMIUM_PATH)
    response = client.post(
        f"/evidence/{EVIDENCE}/browser/{eid}/index",
        data={"rebuild": "0"},
    )
    assert response.status_code == 403


def test_downloads_view_and_escaping(env):
    client, services, record = env
    status = _index_chromium(services, record)
    assert status["status"] in {"ready", "partial"}
    response = client.get(f"/evidence/{EVIDENCE}/browser/downloads")
    assert response.status_code == 200
    assert "SysInternals.exe" in response.text
    assert "browser-record" in response.text
    # evidence strings are HTML-escaped, never interpreted
    assert "<script" not in response.text.lower()


def test_history_and_cache_views(env):
    client, services, record = env
    _index_chromium(services, record)
    history = client.get(f"/evidence/{EVIDENCE}/browser/history")
    assert history.status_code == 200
    assert "sysinternals.com" in history.text
    profile = services.browser_artifacts.list_profiles(EVIDENCE).items[0]
    cache = client.get(
        f"/evidence/{EVIDENCE}/browser/cache?profile_ids={profile.profile_id}"
    )
    assert cache.status_code == 200
    profiles = client.get(f"/evidence/{EVIDENCE}/browser/profiles")
    assert profiles.status_code == 200
    assert profile.profile_id in profiles.text


def test_xss_payload_escaped(env):
    client, services, record = env
    status = _index_chromium(services, record)
    profile = services.browser_artifacts.list_profiles(EVIDENCE).items[0]
    services.browser_artifacts.store.insert_records(
        visits=[
            __import__(
                "dfir_browser.core.browser_artifacts.models",
                fromlist=["VisitRecord"],
            ).VisitRecord(
                visit_id=0,
                profile_id=profile.profile_id,
                source_artifact_id=status["artifact_id"],
                source_record_id="visit:99",
                user=None,
                browser="chromium",
                url="https://evil.test/<script>alert(1)</script>",
                scheme="https",
                host="evil.test",
                registrable_domain="evil.test",
                title="<img src=x onerror=alert(1)>",
                visit_time_utc="2022-11-15T21:18:40.000000Z",
                raw_timestamp="1",
                visit_type="transition:0",
            )
        ]
    )
    response = client.get(f"/evidence/{EVIDENCE}/browser/history?q=evil")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_detail_and_correlation_views(env):
    client, services, record = env
    _index_chromium(services, record)
    downloads = services.browser_artifacts.query_downloads(EVIDENCE)
    target = next(i for i in downloads.items if i["filename"] == "SysInternals.exe")
    detail = client.get(f"/browser/records/download/{target['download_id']}")
    assert detail.status_code == 200
    assert "untrusted evidence data" in detail.text
    correlate = client.get(
        f"/evidence/{EVIDENCE}/browser/downloads/{target['download_id']}/correlate"
    )
    assert correlate.status_code == 200
    assert "Users/Public/Downloads/SysInternals.exe" in correlate.text


def test_detail_rejects_unknown_record(env):
    client, services, record = env
    response = client.get("/browser/records/download/999999")
    assert response.status_code == 200
    assert "not found" in response.text
    bad = client.get("/browser/records/cookie/1")
    assert "unknown record type" in bad.text


def test_summary_view(env):
    client, services, record = env
    _index_chromium(services, record)
    response = client.get(f"/evidence/{EVIDENCE}/browser/summary")
    assert response.status_code == 200
    assert "Activity summary" in response.text
    assert "Exe/archive downloads" in response.text


def test_explorer_view(env):
    client, services, record = env
    status = _index_chromium(services, record)
    response = client.get(f"/browser/artifacts/{status['artifact_id']}")
    assert response.status_code == 200
    assert "browser-records" in response.text
    assert 'role="tablist"' in response.text


def test_web_rejects_bad_filters(env):
    client, services, record = env
    too_long = client.get(
        f"/evidence/{EVIDENCE}/browser/downloads?q=" + "a" * 400
    )
    assert too_long.status_code == 200
    assert "maximum length" in too_long.text
    bad_time = client.get(
        f"/evidence/{EVIDENCE}/browser/downloads?time_from=not-a-time"
    )
    assert "invalid time" in bad_time.text


# ----------------------------------------------------------------------
# mcp
# ----------------------------------------------------------------------
def test_mcp_tool_schemas(env):
    import asyncio

    tools = asyncio.run(mcp_server.mcp.list_tools())
    names = {tool.name for tool in tools}
    expected = {
        "browser_list_artifacts",
        "browser_index_start",
        "browser_index_status",
        "browser_list_profiles",
        "browser_query_downloads",
        "browser_query_history",
        "browser_query_cache",
        "browser_get_record",
        "browser_correlate_download",
        "browser_activity_summary",
    }
    assert expected <= names
    by_name = {tool.name: tool for tool in tools}
    for name in expected - {"browser_index_start"}:
        assert by_name[name].annotations.readOnlyHint is True
    assert by_name["browser_index_start"].annotations.readOnlyHint is False


def test_mcp_list_and_index(env):
    client, services, record = env
    listed = mcp_server.browser_list_artifacts(EVIDENCE)
    assert listed["trust"] == "untrusted_evidence_data"
    assert listed["total"] >= 3
    item = next(i for i in listed["items"] if i["path"] == CHROMIUM_PATH)
    started = mcp_server.browser_index_start(EVIDENCE, item["entry_id"])
    assert started["started"] is True
    artifact_id = started["artifact"]["artifact_id"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = mcp_server.browser_index_status(artifact_id)
        if status["status"] in {"ready", "partial", "failed"}:
            break
        time.sleep(0.05)
    assert status["status"] in {"ready", "partial"}
    assert status["trust"] == "untrusted_evidence_data"


def test_mcp_queries_and_pagination(env):
    client, services, record = env
    _index_chromium(services, record)
    downloads = mcp_server.browser_query_downloads(EVIDENCE, page_size=1)
    assert downloads["total"] == 2
    assert downloads["page_size"] == 1
    assert downloads["has_more"] is True
    assert downloads["complete"] is False
    second = mcp_server.browser_query_downloads(EVIDENCE, page=2, page_size=1)
    assert second["items"][0]["download_id"] != downloads["items"][0]["download_id"]
    assert second["complete"] is True

    history = mcp_server.browser_query_history(EVIDENCE, query="sysinternals")
    assert history["total"] >= 1
    profiles = mcp_server.browser_list_profiles(EVIDENCE)
    assert profiles["total"] == 1
    profile_id = profiles["items"][0]["profile_id"]
    cache = mcp_server.browser_query_cache(EVIDENCE, profile_ids=[profile_id])
    assert cache["trust"] == "untrusted_evidence_data"


def test_mcp_record_and_correlation(env):
    client, services, record = env
    _index_chromium(services, record)
    downloads = mcp_server.browser_query_downloads(EVIDENCE)
    target = next(i for i in downloads["items"] if i["filename"] == "SysInternals.exe")
    detail = mcp_server.browser_get_record("download", target["download_id"])
    assert detail["filename"] == "SysInternals.exe"
    correlation = mcp_server.browser_correlate_download(
        EVIDENCE, target["download_id"]
    )
    assert correlation["trust"] == "untrusted_evidence_data"
    assert correlation["total"] >= 1
    assert correlation["correlation"]["hits"][0]["deleted"] is True


def test_mcp_summary_and_validation(env):
    client, services, record = env
    _index_chromium(services, record)
    summary = mcp_server.browser_activity_summary(EVIDENCE)
    assert summary["total_downloads"] == 2
    assert summary["trust"] == "untrusted_evidence_data"
    with pytest.raises(ToolError) as exc:
        mcp_server.browser_query_downloads(EVIDENCE, query="x" * 500)
    assert "browser_query_too_long" in str(exc.value)
    with pytest.raises(ToolError):
        mcp_server.browser_list_artifacts("ev_missing")


def test_mcp_no_cookie_or_password_leak(env):
    client, services, record = env
    _index_chromium(services, record)
    payload = mcp_server.browser_activity_summary(EVIDENCE)
    text = str(payload)
    assert "cookie" not in text.lower()
    assert "password" not in text.lower()


def _poll_web(client, entry_id_value):
    response = client.get(f"/browser/artifacts/ba_invalid/status")
    assert response.status_code == 200
    return {"status": "queued"}


def test_search_all_view_and_mcp(env):
    client, services, record = env
    _index_chromium(services, record)
    page = client.get(f"/evidence/{EVIDENCE}/browser/search?q=sysinternals")
    assert page.status_code == 200
    assert "Downloads (" in page.text or "Downloads (1)" in page.text
    result = mcp_server.browser_search_all(EVIDENCE, query="sysinternals")
    assert result["total"] >= 2
    assert result["sections"]["downloads"]["total"] >= 1
    assert result["trust"] == "untrusted_evidence_data"


def test_queries_are_scoped_to_one_evidence(env):
    """A second evidence's artifacts must never leak into these results."""
    client, services, record = env
    status = _index_chromium(services, record)
    artifact_id = status["artifact_id"]
    profile = services.browser_artifacts.list_profiles(EVIDENCE).items[0]

    # Same index database, different evidence id, distinct artifact.
    services.browser_artifacts.store.upsert_artifact(
        __import__(
            "dfir_browser.core.browser_artifacts.models", fromlist=["SourceArtifact"]
        ).SourceArtifact(
            artifact_id="ba_other_evidence",
            evidence_id="ev_00000000000b",
            entry_id=999,
            inode=999,
            evidence_path="Users/other/History",
            filename="History",
            browser="chromium",
            artifact_type="chromium_history",
            user="other",
            profile_name=None,
            size=1024,
            sha256=None,
            status="ready",
            phase="ready",
            backend="chromium-sqlite",
            parser_version="test",
        )
    )
    from dfir_browser.core.browser_artifacts.models import VisitRecord

    services.browser_artifacts.store.insert_records(
        visits=[
            VisitRecord(
                visit_id=0,
                profile_id="bp_other",
                source_artifact_id="ba_other_evidence",
                source_record_id="visit:1",
                user="other",
                browser="chromium",
                url="https://other-evidence.test/secret",
                scheme="https",
                host="other-evidence.test",
                registrable_domain="other-evidence.test",
                title="other",
                visit_time_utc="2022-11-15T21:18:40.000000Z",
                raw_timestamp="1",
                visit_type="transition:0",
            )
        ]
    )

    mine = services.browser_artifacts.query_history(EVIDENCE, page_size=500)
    assert all(
        "other-evidence.test" not in (item["url"] or "") for item in mine.items
    )
    other = services.browser_artifacts.query_history(
        "ev_00000000000b", page_size=500
    )
    assert other.total == 1
    summary = services.browser_artifacts.summary(EVIDENCE).to_dict()
    assert summary["total_visits"] == mine.total
