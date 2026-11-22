from __future__ import annotations

import json
import asyncio
from pathlib import Path

from dfir_browser.core.config import Settings
from dfir_browser.core.investigation import InvestigationService, _utc, normalize_windows_path
from dfir_browser import mcp_server
from dfir_browser.core.services import build_services
from dfir_browser.web.app import create_app
from fastapi.testclient import TestClient


def _service(tmp_path):
    settings = Settings(var_dir=tmp_path, allowed_roots=(tmp_path,), auto_index=False)
    for path in (settings.index_database(), settings.registry_database(), settings.evtx_database(), settings.browser_database()):
        path.parent.mkdir(parents=True, exist_ok=True)
    return InvestigationService(settings, object())


def test_timestamp_normalization_preserves_kind_and_uses_utc(tmp_path):
    assert _utc("2024-01-02T03:04:05+03:00") == "2024-01-02T00:04:05.000000Z"
    assert _utc("invalid") is None
    assert normalize_windows_path(r"\\?\C:/Users//Alice/App.exe") == r"c:\users\alice\app.exe"


def test_timeline_pagination_filters_source_urls_and_stale_generation(tmp_path):
    service = _service(tmp_path)
    expected = service._generations("case")
    with service._connect() as db:
        db.execute("INSERT INTO timeline_meta VALUES(?,?,?,?,?,?,?)", ("case", "ready", json.dumps(expected), 2, "{}", "now", 100))
        for i, source in enumerate(("filesystem", "evtx", "browser")):
            db.execute("INSERT INTO timeline_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                "case", f"event-{i}", source, str(i), f"2024-01-0{i+1}T00:00:00.000000Z", "modified" if source == "filesystem" else "event",
                "title", "summary", r"C:\Program Files\app.exe", "app.exe", None, None, None, None,
                f"/{source}/source/{i}", json.dumps({"generation": "x"})))
    page = service.query("case", source="evtx", page=1, page_size=1)
    assert page["total"] == 1 and page["items"][0]["source_url"] == "/evtx/source/1"
    assert page["items"][0]["provenance"]["generation"] == "x"
    assert page["skipped_timestamps"] == 2
    with service._connect() as db:
        db.execute("UPDATE timeline_meta SET generations='{}' WHERE evidence_id='case'")
    stale = service.query("case")
    assert stale["stale"] is True and stale["items"] == []


def test_timeline_and_related_mcp_tools_are_registered():
    names = {tool.name for tool in asyncio.run(mcp_server.mcp.list_tools())}
    assert {"start_timeline_index", "get_timeline_index_status", "query_timeline",
            "get_timeline_event", "find_related_artifacts"} <= names


def test_web_timeline_route_escapes_evidence_text(tmp_path):
    settings = Settings(var_dir=tmp_path, allowed_roots=(tmp_path,), auto_index=False)
    services = build_services(settings)
    try:
        eid = "ev_test"
        generations = services.investigation._generations(eid)
        with services.investigation._connect() as db:
            db.execute("INSERT INTO timeline_meta(evidence_id,state,generations,skipped,errors,updated_at,progress) VALUES(?,?,?,?,?,?,?)",
                       (eid, "ready", json.dumps(generations), 0, "{}", "now", 100))
            db.execute("INSERT INTO timeline_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (eid,"unsafe","evtx","1","2024-01-01T00:00:00Z","event","<img src=x onerror=alert(1)>","summary",None,None,None,None,None,None,"/event-logs/log/events/1","{}"))
        with TestClient(create_app(settings=settings, services=services)) as client:
            response = client.get(f"/evidence/{eid}/timeline")
        assert response.status_code == 200
        assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
        assert "<img src=x onerror=alert(1)>" not in response.text
    finally:
        services.cleanup()
