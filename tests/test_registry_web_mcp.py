from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dfir_browser.web.app import create_app
import dfir_browser.mcp_server as mcp_server

from registry_helpers import (
    KeyRecord,
    SHA1,
    amcache_key_records,
    build_registry_services,
    normal_key_records,
    seed_hive,
    value,
)

EVIDENCE = "ev_0123456789ab"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture()
def env(tmp_path):
    services, record = build_registry_services(tmp_path)
    hive_id = seed_hive(
        services, normal_key_records() + amcache_key_records()
    )
    app = create_app(services.settings, services)
    with TestClient(app) as client:
        yield client, services, record, hive_id
    services.cleanup()


def csrf(client, path=f"/evidence/{EVIDENCE}/registry"):
    response = client.get(path)
    assert response.status_code == 200
    match = CSRF_RE.search(response.text)
    assert match, response.text
    return match.group(1)


def test_registry_tab_lists_hives(env) -> None:
    client, services, record, hive_id = env
    page = client.get(f"/evidence/{EVIDENCE}/registry")
    assert page.status_code == 200
    assert "Amcache.hve" in page.text
    assert "Registry hives" in page.text
    assert "sensitive" in page.text.lower()
    assert 'id="tab-registry"' in client.get(f"/evidence/{EVIDENCE}").text


def test_hive_browser_and_key_tree(env) -> None:
    client, services, record, hive_id = env
    root_id = services.registry_store.root_key(hive_id).key_id
    browser = client.get(f"/registry/hives/{hive_id}")
    assert browser.status_code == 200
    assert 'role="tree"' in browser.text
    assert f'data-root-key-id="{root_id}"' in browser.text
    keys = client.get(f"/registry/hives/{hive_id}/keys?parent_key_id={root_id}")
    assert keys.status_code == 200
    payload = keys.json()
    assert payload["ok"] is True
    assert payload["total"] == 1
    assert payload["items"][0]["name"] == "Root"
    root_children = client.get(f"/registry/hives/{hive_id}/keys").json()
    assert root_children["items"][0]["name"] == "Root"


def test_key_detail_binary_preview_limit(env) -> None:
    client, services, record, hive_id = env
    results = services.registry_browser.search(hive_id, "Binary", page_size=10)
    key_id = results.items[0]["key_id"]
    page = client.get(f"/registry/hives/{hive_id}/key/{key_id}?preview=4")
    assert page.status_code == 200
    assert "binary preview (4 bytes max)" in page.text
    assert "00010200" in page.text
    assert "000102000102" not in page.text


def test_registry_search_and_reveal(env) -> None:
    client, services, record, hive_id = env
    page = client.get(f"/registry/hives/{hive_id}/search?q=Hello")
    assert page.status_code == 200
    assert "Hello Unicode" in page.text
    key_id = services.registry_browser.search(
        hive_id, "Child", page_size=5
    ).items[0]["key_id"]
    reveal = client.get(
        f"/registry/hives/{hive_id}/reveal?key_id={key_id}"
    ).json()
    assert reveal["ok"] is True
    assert reveal["key"]["key_id"] == key_id
    assert reveal["ancestors"]


def test_amcache_search_and_compare(env, monkeypatch) -> None:
    client, services, record, hive_id = env
    page = client.get(
        f"/registry/hives/{hive_id}/amcache?q=SysInternals"
    )
    assert page.status_code == 200
    assert "SysInternals.exe" in page.text
    assert ("0000" + SHA1) in page.text
    assert "strip-4-hex-prefix-sha1" in page.text

    amcache = services.registry_browser.amcache_search(
        hive_id, "SysInternals", page_size=5
    ).items[0]
    target = services.indexer.resolve_entry_path(
        record, "Users/Public/Downloads/SysInternals.exe"
    ).id
    job = SimpleNamespace(
        job_id="tr_0123456789abcdef",
        sha1=SHA1,
        sha256="b" * 64,
        md5="c" * 32,
    )
    monkeypatch.setattr(
        services.triage.store, "latest_for_entry", lambda *args, **kwargs: job
    )
    token = csrf(client)
    response = client.post(
        f"/registry/hives/{hive_id}/amcache/{amcache['record_id']}/compare",
        data={"entry_id": str(target), "csrf_token": token},
    )
    assert response.status_code == 200
    assert "Hash comparison: match" in response.text


def test_amcache_virustotal_requires_csrf_and_key(env, monkeypatch) -> None:
    client, services, record, hive_id = env
    amcache = services.registry_browser.amcache_search(
        hive_id, "SysInternals", page_size=5
    ).items[0]
    missing = client.post(
        f"/registry/hives/{hive_id}/amcache/{amcache['record_id']}/virustotal",
        data={},
    )
    assert missing.status_code == 403
    token = csrf(client)
    response = client.post(
        f"/registry/hives/{hive_id}/amcache/{amcache['record_id']}/virustotal",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "not configured" in response.text.lower()
    assert "No evidence file was uploaded" in response.text


def test_registry_values_are_escaped(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    extra = normal_key_records() + [
        KeyRecord(
            path="{GUID}\\Root\\<script>alert(1)</script>",
            name="<script>alert(1)</script>",
            parent_path="{GUID}\\Root",
            depth=2,
            last_write_time="2020-01-01T00:00:00Z",
            subkey_count=0,
            value_count=1,
            subkeys=[],
            values=[
                value(
                    "<img src=x onerror=alert(1)>",
                    1,
                    "<script>alert('x')</script>".encode("utf-16le") + b"\x00\x00",
                )
            ],
        )
    ]
    hive_id = seed_hive(services, extra)
    app = create_app(services.settings, services)
    with TestClient(app) as client:
        results = services.registry_browser.search(
            hive_id, "script", page_size=10
        )
        key_id = results.items[0]["key_id"]
        key_page = client.get(f"/registry/hives/{hive_id}/key/{key_id}")
        search_page = client.get(f"/registry/hives/{hive_id}/search?q=script")
        for page in (key_page, search_page):
            assert page.status_code == 200
            assert "<script>alert" not in page.text
            assert "&lt;script&gt;" in page.text
    services.cleanup()


def test_unknown_hive_returns_404(env) -> None:
    client, *_rest = env
    response = client.get("/registry/hives/hive_ffffffffffffffff")
    assert response.status_code == 404
    keys = client.get("/registry/hives/hive_ffffffffffffffff/keys")
    assert keys.status_code == 400


def test_mcp_registry_tools(env, monkeypatch) -> None:
    client, services, record, hive_id = env
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    hives = mcp_server.registry_list_hives(EVIDENCE)
    assert hives["trust"] == "untrusted_evidence_data"
    assert any(item["hive_type"] == "amcache" for item in hives["items"])
    status = mcp_server.registry_index_status(hive_id)
    assert status["state"] == "ready"
    root_id = services.registry_store.root_key(hive_id).key_id
    root_children = mcp_server.registry_list_subkeys(hive_id)
    assert root_children["items"][0]["name"] == "Root"
    root_key_id = root_children["items"][0]["key_id"]
    explicit = mcp_server.registry_list_subkeys(
        hive_id, parent_key_id=root_key_id
    )
    assert explicit["items"][0]["name"] == "Child"
    key = mcp_server.registry_get_key(hive_id, explicit["items"][0]["key_id"])
    assert key["key"]["name"] == "Child"
    search = mcp_server.registry_search(hive_id, "Hello")
    assert search["total"] >= 1
    amcache = mcp_server.amcache_search(hive_id, "SysInternals")
    assert amcache["total"] == 1
    assert amcache["items"][0]["hash_normalized"] == SHA1
    record_id = amcache["items"][0]["record_id"]
    target = services.indexer.resolve_entry_path(
        record, "Users/Public/Downloads/SysInternals.exe"
    ).id
    job = SimpleNamespace(
        job_id="tr_0123456789abcdef",
        sha1=SHA1,
        sha256="b" * 64,
        md5="c" * 32,
    )
    monkeypatch.setattr(
        services.triage.store, "latest_for_entry", lambda *args, **kwargs: job
    )
    compare = mcp_server.amcache_compare_triage(hive_id, record_id, target)
    assert compare["status"] == "match"


def test_mcp_registry_no_raw_binary(env, monkeypatch) -> None:
    client, services, record, hive_id = env
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    results = services.registry_browser.search(hive_id, "Binary", page_size=5)
    key_id = results.items[0]["key_id"]
    payload = mcp_server.registry_get_key(
        hive_id, key_id, binary_preview_bytes=4
    )
    binary = next(
        item for item in payload["values"] if item["name"] == "Binary"
    )
    assert binary["value"] is None
    assert binary["preview_hex"] == "00010200"
    assert binary["raw_size"] == 60
    assert "raw" not in binary


def test_mcp_registry_errors_and_consent(env, monkeypatch) -> None:
    client, services, record, hive_id = env
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with pytest.raises(Exception) as excinfo:
        mcp_server.registry_list_subkeys("hive_ffffffffffffffff")
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "hive_not_found"
    with pytest.raises(Exception) as excinfo:
        mcp_server.amcache_lookup_virustotal(hive_id, 1)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "external_lookup_consent_required"
    with pytest.raises(Exception) as excinfo:
        mcp_server.registry_search(hive_id, "   ")
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "invalid_registry_query"


def test_mcp_tool_count_and_annotations() -> None:
    import asyncio

    tools = {tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())}
    for name in (
        "registry_list_hives",
        "registry_index_start",
        "registry_index_status",
        "registry_list_subkeys",
        "registry_get_key",
        "registry_search",
        "amcache_search",
        "amcache_compare_triage",
        "amcache_lookup_virustotal",
    ):
        assert name in tools
    assert tools["registry_list_hives"].annotations.readOnlyHint is True
    assert tools["registry_index_start"].annotations.readOnlyHint is False
    assert tools["amcache_lookup_virustotal"].annotations.openWorldHint is True
    for name in ("registry_get_key", "registry_search", "amcache_search"):
        description = (tools[name].description or "").upper()
        assert "UNTRUSTED" in description
