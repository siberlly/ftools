from __future__ import annotations

import json

import pytest

import dfir_browser.mcp_server as mcp_server

from triage_helpers import build_services, sample_payload, stub_extraction
from vt_helpers import HASH, KEY, Upstream


@pytest.fixture()
def env(tmp_path, monkeypatch):
    upstream = Upstream()
    services, record, entry_id = build_services(
        tmp_path, sample_payload(), extra_payload=b"other"
    )
    stub_extraction(services, sample_payload(), by_inode={901: b"other"})
    services.virustotal.client = __import__(
        "dfir_browser.core.virustotal", fromlist=["VirusTotalClient"]
    ).VirusTotalClient(
        transport=__import__("httpx").MockTransport(upstream), timeout=5.0
    )
    services.virustotal.save_key(KEY)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    yield services, record, entry_id, upstream
    services.cleanup()


def test_consent_is_required(env) -> None:
    _services, _record, entry_id, upstream = env
    with pytest.raises(Exception) as excinfo:
        mcp_server.lookup_file_hash_virustotal(
            "ev_0123456789ab", entry_id
        )
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "external_lookup_consent_required"
    assert "SHA-256" in payload["error"]["message"]
    assert upstream.calls == 0


def test_lookup_structured_and_cached(env) -> None:
    services, record, entry_id, upstream = env
    payload = mcp_server.lookup_file_hash_virustotal(
        "ev_0123456789ab", entry_id, allow_external_lookup=True
    )
    assert payload["trust"] == "untrusted_evidence_data"
    assert payload["status"] == "found"
    assert payload["hash"] == HASH
    assert payload["cached"] is False
    assert payload["http_status"] == 200
    assert payload["report"]["last_analysis_stats"]["undetected"] == 61
    assert payload["entry_id"] == entry_id
    assert KEY not in json.dumps(payload)
    cached = mcp_server.lookup_file_hash_virustotal(
        "ev_0123456789ab", entry_id, allow_external_lookup=True
    )
    assert cached["cached"] is True
    assert upstream.calls == 1
    forced = mcp_server.lookup_file_hash_virustotal(
        "ev_0123456789ab",
        entry_id,
        allow_external_lookup=True,
        force_refresh=True,
    )
    assert forced["cached"] is False
    assert upstream.calls == 2


def test_evidence_mismatch(env) -> None:
    _services, _record, entry_id, _upstream = env
    with pytest.raises(Exception) as excinfo:
        mcp_server.lookup_file_hash_virustotal(
            "ev_ffffffffffff", entry_id, allow_external_lookup=True
        )
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] in {
        "evidence_not_found",
        "entry_not_found",
        "index_not_found",
        "index_not_ready",
    }


def test_invalid_entry_id(env) -> None:
    _services, _record, _entry_id, _upstream = env
    for bad in (-1, 10**20):
        with pytest.raises(Exception) as excinfo:
            mcp_server.lookup_file_hash_virustotal(
                "ev_0123456789ab", bad, allow_external_lookup=True
            )
        payload = json.loads(str(excinfo.value))
        assert payload["error"]["code"] == "invalid_entry_id"


def test_directory_rejected(env) -> None:
    services, record, _entry_id, _upstream = env
    directory_id = services.indexer.resolve_entry_path(record, "Files").id
    with pytest.raises(Exception) as excinfo:
        mcp_server.lookup_file_hash_virustotal(
            "ev_0123456789ab", directory_id, allow_external_lookup=True
        )
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "virustotal_directory_rejected"


def test_missing_key(env) -> None:
    services, _record, entry_id, upstream = env
    services.virustotal.remove_key()
    with pytest.raises(Exception) as excinfo:
        mcp_server.lookup_file_hash_virustotal(
            "ev_0123456789ab", entry_id, allow_external_lookup=True
        )
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "virustotal_not_configured"
    assert upstream.calls == 0


def test_tool_schema_has_no_hash_or_url_argument() -> None:
    import asyncio

    tools = {
        tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())
    }
    tool = tools["lookup_file_hash_virustotal"]
    properties = tool.inputSchema.get("properties", {})
    assert set(properties) == {
        "evidence_id",
        "entry_id",
        "allow_external_lookup",
        "force_refresh",
    }
    annotations = tool.annotations
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is False
    assert annotations.openWorldHint is True
    description = (tool.description or "").upper()
    assert "UNTRUSTED" in description
    assert "NEVER UPLOADED" in description or "NEVER UPLOAD" in description
