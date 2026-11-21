from __future__ import annotations

import json

import pytest

import dfir_browser.mcp_server as mcp_server

from triage_helpers import (
    EVIDENCE,
    build_services,
    sample_payload,
    stub_extraction,
    wait_job,
)


@pytest.fixture()
def services(tmp_path, monkeypatch):
    built, record, entry_id = build_services(tmp_path, sample_payload())
    stub_extraction(built, sample_payload())
    monkeypatch.setattr(mcp_server, "get_services", lambda: built)
    yield built, record, entry_id
    built.cleanup()


def test_start_file_triage_tool_schema(services) -> None:
    built, record, entry_id = services
    payload = mcp_server.start_file_triage(EVIDENCE, entry_id)
    assert payload["trust"] == "untrusted_evidence_data"
    assert payload["job_id"].startswith("tr_")
    assert payload["status"] in {"queued", "running", "complete", "partial"}
    assert payload["entry"]["entry_id"] == entry_id
    job = wait_job(built, payload["job_id"])
    assert job.status == "complete", job.errors


def test_get_file_triage_pagination(services) -> None:
    built, record, entry_id = services
    started = mcp_server.start_file_triage(EVIDENCE, entry_id)
    job = wait_job(built, started["job_id"])
    payload = mcp_server.get_file_triage(job.job_id, strings_page_size=2)
    assert payload["job"]["status"] == "complete"
    assert payload["job"]["sha256"] == job.sha256
    assert payload["strings"]["total"] > 2
    assert len(payload["strings"]["strings"]) == 2
    assert payload["strings"]["page_size"] == 2
    second = mcp_server.get_file_triage(
        job.job_id, strings_page=2, strings_page_size=2
    )
    assert {s["value"] for s in payload["strings"]["strings"]}.isdisjoint(
        {s["value"] for s in second["strings"]["strings"]}
    )
    assert payload["findings_total"] >= 1
    assert all("rule_id" in finding for finding in payload["findings"])


def test_get_file_triage_cache(services) -> None:
    built, record, entry_id = services
    first = mcp_server.start_file_triage(EVIDENCE, entry_id)
    wait_job(built, first["job_id"])
    second = mcp_server.start_file_triage(EVIDENCE, entry_id)
    job = wait_job(built, second["job_id"])
    payload = mcp_server.get_file_triage(job.job_id)
    assert payload["job"]["cached"] is True
    assert payload["job"]["cached_from_job_id"] == first["job_id"]


def test_start_triage_invalid_ids(services) -> None:
    built, record, entry_id = services
    with pytest.raises(Exception) as excinfo:
        mcp_server.start_file_triage(EVIDENCE, -3)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "invalid_entry_id"
    with pytest.raises(Exception) as excinfo:
        mcp_server.get_file_triage("../../etc/passwd")
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "triage_not_found"


def test_start_triage_directory_rejected(services) -> None:
    built, record, _entry_id = services
    directory_id = built.indexer.resolve_entry_path(record, "Files").id
    with pytest.raises(Exception) as excinfo:
        mcp_server.start_file_triage(EVIDENCE, directory_id)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "triage_directory_rejected"


def test_triage_tool_annotations() -> None:
    import asyncio

    tools = {
        tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())
    }
    assert {
        "start_file_triage",
        "get_file_triage",
    } <= set(tools)
    start = tools["start_file_triage"].annotations
    assert start.readOnlyHint is False
    assert start.destructiveHint is False
    get = tools["get_file_triage"].annotations
    assert get.readOnlyHint is True
    assert get.destructiveHint is False
    for name in ("start_file_triage", "get_file_triage"):
        description = (tools[name].description or "").upper()
        assert "UNTRUSTED" in description
        assert "INSTRUCTIONS" in description
    assert "EXECUTED" in (tools["start_file_triage"].description or "").upper()
