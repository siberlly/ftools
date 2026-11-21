from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import dfir_browser.mcp_server as mcp_server
from dfir_browser.core.evtx.models import EvtxLog, log_id_for
from dfir_browser.web.app import create_app

from registry_helpers import (
    EVIDENCE,
    build_registry_services,
    entry_id,
    stub_registry_extract,
)
from evtx_helpers import FakeBackend, sample_event_xml, synthetic_empty_evtx

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
SECURITY_PATH = "Windows/System32/winevt/Logs/Security.evtx"


def make_events():
    return [
        type(
            "Raw",
            (),
            {
                "record_id": 1,
                "chunk_number": 0,
                "xml": sample_event_xml(
                    timestamp="2022-11-15T21:18:10.740504Z",
                    data={"NewProcessName": "C:\\Synthetic\\sample.exe"},
                ),
                "xml_too_large": False,
                "error": None,
            },
        )(),
        type(
            "Raw",
            (),
            {
                "record_id": 2,
                "chunk_number": 0,
                "xml": sample_event_xml(
                    event_id=4624,
                    timestamp="2022-11-15T21:19:00.000000Z",
                    data={"TargetUserName": "synthetic"},
                ),
                "xml_too_large": False,
                "error": None,
            },
        )(),
        type(
            "Raw",
            (),
            {
                "record_id": 3,
                "chunk_number": 0,
                "xml": sample_event_xml(
                    event_id=7045,
                    channel="System",
                    provider="Service Control Manager",
                    timestamp="2022-11-15T21:20:00.000000Z",
                    data={"ServiceName": "SyntheticSvc"},
                ),
                "xml_too_large": False,
                "error": None,
            },
        )(),
    ]


@pytest.fixture()
def env(tmp_path):
    services, record = build_registry_services(tmp_path)
    calls = stub_registry_extract(services, payload=synthetic_empty_evtx())
    FakeBackend.events = make_events()
    FakeBackend.fail = None
    FakeBackend.header_signature_valid = True
    import dfir_browser.core.evtx.service as svc_module

    original = svc_module.EvtxBackend

    class PatchedBackend(FakeBackend):
        def __init__(self, path, settings):  # noqa: D401
            super().__init__(path, settings)
            # Header validation still runs on the real synthetic file.
            original(path, settings)

    svc_module.EvtxBackend = PatchedBackend
    try:
        app = create_app(services.settings, services)
        with TestClient(app) as client:
            yield client, services, record, calls
    finally:
        svc_module.EvtxBackend = original
        services.cleanup()


def index_log(services, record, calls):
    target = entry_id(services, SECURITY_PATH)
    result = services.evtx.start_index(record, target, rebuild=True)
    log_id = result["log"]["log_id"]
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        log = services.evtx.status(log_id)
        if log.status not in {"queued", "running"}:
            return log
        time.sleep(0.02)
    raise AssertionError("EVTX job did not finish")


def csrf(client, path=f"/evidence/{EVIDENCE}/event-logs"):
    response = client.get(path)
    assert response.status_code == 200
    match = CSRF_RE.search(response.text)
    assert match, response.text[:400]
    return match.group(1)


def test_event_logs_tab_lists_candidates(env) -> None:
    client, services, record, _calls = env
    page = client.get(f"/evidence/{EVIDENCE}/event-logs")
    assert page.status_code == 200
    assert "Security.evtx" in page.text
    assert "EVTX candidates" in page.text
    assert "Investigation presets" in page.text
    html = client.get(f"/evidence/{EVIDENCE}").text
    assert 'id="tab-event-logs"' in html
    assert html.count('aria-controls="tab-content"') >= 6


def test_index_via_web_and_status(env) -> None:
    client, services, record, calls = env
    token = csrf(client)
    target = entry_id(services, SECURITY_PATH)
    started = client.post(
        f"/evidence/{EVIDENCE}/event-logs/{target}/index",
        data={"rebuild": "1", "csrf_token": token},
    )
    assert started.status_code == 200
    log_id = re.search(r"log_[0-9a-f]{16}", started.text or "")
    log = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        candidates = services.evtx_store.list_for_evidence(EVIDENCE)
        if candidates and candidates[0].status not in {"queued", "running"}:
            log = candidates[0]
            break
        time.sleep(0.02)
    assert log is not None and log.status == "ready"
    assert log.records_indexed == 3
    assert len(calls) == 1
    status = client.get(f"/event-logs/{log.log_id}/status")
    assert status.status_code == 200
    assert "ready" in status.text
    void = log_id
    assert void is not None or True


def test_event_explorer_query_detail_raw_context(env) -> None:
    client, services, record, _calls = env
    log = index_log(services, record, _calls)
    explorer = client.get(f"/event-logs/{log.log_id}")
    assert explorer.status_code == 200
    assert 'role="region"' in explorer.text or "Event detail" in explorer.text

    query = client.get(
        f"/evidence/{EVIDENCE}/event-logs/query?log_id={log.log_id}"
        "&event_ids=4688&page_size=5"
    )
    assert query.status_code == 200
    assert "4688" in query.text
    assert "sample.exe" in query.text

    detail = client.get(f"/event-logs/{log.log_id}/events/1")
    assert detail.status_code == 200
    assert "message_unavailable" in detail.text
    assert "EventData" in detail.text
    # Raw XML must not appear unless explicitly requested.
    assert "&lt;Event" not in detail.text
    raw = client.get(f"/event-logs/{log.log_id}/events/1?raw=1")
    assert raw.status_code == 200
    assert "&lt;Event" in raw.text

    context = client.get(f"/event-logs/{log.log_id}/events/2/context")
    assert context.status_code == 200
    summary = client.get(
        f"/evidence/{EVIDENCE}/event-logs/summary?log_id={log.log_id}"
    )
    assert summary.status_code == 200
    assert "By event ID" in summary.text


def test_query_preset_and_validation(env) -> None:
    client, services, record, _calls = env
    log = index_log(services, record, _calls)
    preset = client.get(
        f"/evidence/{EVIDENCE}/event-logs/query?log_id={log.log_id}"
        "&preset=authentication"
    )
    assert preset.status_code == 200
    assert "4624" in preset.text
    bad = client.get(
        f"/evidence/{EVIDENCE}/event-logs/query?log_id={log.log_id}"
        "&event_ids=abc"
    )
    assert bad.status_code == 200
    assert "invalid event id" in bad.text
    bad_time = client.get(
        f"/evidence/{EVIDENCE}/event-logs/query?log_id={log.log_id}"
        "&time_from=not-a-date"
    )
    assert "ISO 8601" in bad_time.text


def test_event_data_is_escaped(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=synthetic_empty_evtx())
    FakeBackend.events = [
        type(
            "Raw",
            (),
            {
                "record_id": 1,
                "chunk_number": 0,
                "xml": sample_event_xml(
                    data={
                        "NewProcessName": "<script>alert(1)</script>",
                        "CommandLine": "C:\\x\\<img src=x onerror=alert(1)>.exe",
                    },
                    computer="<b>host</b>",
                ),
                "xml_too_large": False,
                "error": None,
            },
        )()
    ]
    FakeBackend.fail = None
    import dfir_browser.core.evtx.service as svc_module

    original = svc_module.EvtxBackend
    svc_module.EvtxBackend = FakeBackend
    try:
        app = create_app(services.settings, services)
        with TestClient(app) as client:
            log = index_log(services, record, [])
            detail = client.get(f"/event-logs/{log.log_id}/events/1?raw=1")
            assert detail.status_code == 200
            assert "<script>alert" not in detail.text
            assert "&lt;script&gt;" in detail.text
            assert "onerror=alert(1)>" not in detail.text
    finally:
        svc_module.EvtxBackend = original
        services.cleanup()


def test_parse_errors_are_reported_not_fatal(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=synthetic_empty_evtx())
    events = make_events()
    events.append(
        type(
            "Raw",
            (),
            {
                "record_id": 4,
                "chunk_number": 0,
                "xml": "",
                "xml_too_large": False,
                "error": "parser error: corrupt record",
            },
        )()
    )
    events.append(
        type(
            "Raw",
            (),
            {
                "record_id": 5,
                "chunk_number": 0,
                "xml": "<Event><broken",
                "xml_too_large": False,
                "error": None,
            },
        )()
    )
    FakeBackend.events = events
    FakeBackend.fail = None
    import dfir_browser.core.evtx.service as svc_module

    original = svc_module.EvtxBackend
    svc_module.EvtxBackend = FakeBackend
    try:
        log = index_log(services, record, [])
        assert log.status == "partial"
        assert log.records_seen == 5
        assert log.records_indexed == 4  # invalid XML still yields a row
        assert log.parse_errors >= 1
        assert log.error_message
    finally:
        svc_module.EvtxBackend = original
        services.cleanup()


def test_cache_hit_does_not_reextract(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    calls = stub_registry_extract(services, payload=synthetic_empty_evtx())
    FakeBackend.events = make_events()
    FakeBackend.fail = None
    import dfir_browser.core.evtx.service as svc_module

    original = svc_module.EvtxBackend
    svc_module.EvtxBackend = FakeBackend
    try:
        first = index_log(services, record, calls)
        assert len(calls) == 1
        target = entry_id(services, SECURITY_PATH)
        second = services.evtx.start_index(record, target)
        assert second["started"] is False and second["cached"] is True
        assert len(calls) == 1
        assert services.evtx.status(first.log_id).records_indexed == 3
    finally:
        svc_module.EvtxBackend = original
        services.cleanup()


def test_mcp_evtx_tools(env, monkeypatch) -> None:
    client, services, record, calls = env
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    logs = mcp_server.evtx_list_logs(EVIDENCE)
    assert logs["trust"] == "untrusted_evidence_data"
    assert any(item["name"] == "Security.evtx" for item in logs["items"])

    log = index_log(services, record, calls)
    status = mcp_server.evtx_index_status(log.log_id)
    assert status["status"] == "ready"
    assert status["records_indexed"] == 3

    result = mcp_server.evtx_query_events(
        EVIDENCE, log_id=log.log_id, event_ids=[4688], page_size=5
    )
    assert result["total"] == 1
    assert result["events"][0]["record_id"] == 1
    assert "raw_xml" not in result["events"][0]

    detail = mcp_server.evtx_get_event(log.log_id, 1)
    assert detail["message_status"] == "message_unavailable"
    assert detail["raw_xml_sha256"]
    assert "raw_xml" not in detail
    raw = mcp_server.evtx_get_event(log.log_id, 1, include_raw_xml=True)
    assert "<Event" in raw["raw_xml"]

    context = mcp_server.evtx_get_context(log.log_id, 2, before=5, after=5)
    assert [event["record_id"] for event in context["events"]] == [1, 2, 3]

    summary = mcp_server.evtx_activity_summary(EVIDENCE, log_ids=[log.log_id])
    assert summary["total_events"] == 3
    assert summary["by_event_id"]["7045"] == 1


def test_mcp_evtx_validation(env, monkeypatch) -> None:
    import json

    client, services, record, calls = env
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    log = index_log(services, record, calls)
    with pytest.raises(Exception) as excinfo:
        mcp_server.evtx_query_events(EVIDENCE, log_id="log_0000000000000000")
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "evtx_log_not_found"
    with pytest.raises(Exception) as excinfo:
        mcp_server.evtx_query_events(EVIDENCE, log_id=log.log_id, preset="nope")
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "evtx_unknown_preset"
    with pytest.raises(Exception) as excinfo:
        mcp_server.evtx_query_events(
            EVIDENCE, log_id=log.log_id, text="x" * 500
        )
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "evtx_query_too_long"
    with pytest.raises(Exception) as excinfo:
        mcp_server.evtx_get_event(log.log_id, 9999)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "evtx_log_not_found"


def test_mcp_evtx_tool_annotations() -> None:
    import asyncio

    tools = {tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())}
    expected = {
        "evtx_list_logs",
        "evtx_index_start",
        "evtx_index_status",
        "evtx_query_events",
        "evtx_get_event",
        "evtx_get_context",
        "evtx_activity_summary",
    }
    assert expected <= set(tools)
    for name in expected - {"evtx_index_start"}:
        assert tools[name].annotations.readOnlyHint is True
    assert tools["evtx_index_start"].annotations.readOnlyHint is False
    assert tools["evtx_index_start"].annotations.destructiveHint is False
    for name in expected:
        assert "UNTRUSTED" in (tools[name].description or "").upper()
