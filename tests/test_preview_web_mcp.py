from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError

import dfir_browser.mcp_server as mcp_server
from dfir_browser.web.app import create_app

from preview_helpers import (
    AMCACHE_PATH,
    BIG_PATH,
    BINARY_PATH,
    DIR_PATH,
    EVIDENCE,
    HOSTS_PATH,
    HOSTS_TEXT,
    SCRIPT_PATH,
    build_preview_services,
    entry_id,
    hive_payload,
    index_hive,
    stub_preview_extract,
)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _payloads():
    return {
        42564: HOSTS_TEXT.encode("utf-8"),
        50001: hive_payload(),
        50002: hive_payload(primary=7, secondary=9),
        50010: b"plain ascii\nsecond line\n",
        50011: ("line\n" * 40000).encode("utf-8"),
        50012: bytes(range(0, 256)) * 4,
        50013: b"<html><script>alert('xss')</script>ok</html>\n",
        50014: b"deep content\n",
    }


@pytest.fixture()
def env(tmp_path, monkeypatch):
    payloads = _payloads()
    services, record = build_preview_services(tmp_path, payloads)
    stub_preview_extract(services, payloads)
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record
    services.cleanup()


# ----------------------------------------------------------------------
# JSON API
# ----------------------------------------------------------------------
def test_json_preview_hosts(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview"
        "?offset=0&limit=65536&mode=auto"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["evidence_id"] == EVIDENCE
    assert data["entry_id"] == hosts
    assert data["filename"] == "hosts"
    assert data["evidence_path"] == HOSTS_PATH
    assert data["preview_mode"] == "text"
    assert data["encoding"] == "utf-8"
    assert data["offset"] == 0
    assert data["returned_bytes"] == len(HOSTS_TEXT.encode("utf-8"))
    assert data["total_size"] == data["returned_bytes"]
    assert data["truncated"] is False
    assert "www.malware430.com" in data["content"]
    assert "192.168.15.10" in data["content"]
    assert data["trust"] == "untrusted_evidence_data"


def test_json_binary_and_registry(env):
    client, services, record = env
    binary = client.get(f"/evidence/{EVIDENCE}/entries/{entry_id(services, BINARY_PATH)}/preview").json()
    assert binary["preview_mode"] == "hex"
    hive = client.get(f"/evidence/{EVIDENCE}/entries/{entry_id(services, AMCACHE_PATH)}/preview").json()
    assert hive["preview_mode"] == "registry"
    assert hive["registry"]["header"]["signature_valid"] is True
    assert hive["returned_bytes"] <= 4096


def test_json_rejections(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    assert client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview?mode=shell"
    ).status_code == 400
    assert client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview?offset=-1"
    ).status_code == 400
    assert client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview?limit=99999999"
    ).status_code == 400
    assert client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id(services, DIR_PATH)}/preview"
    ).status_code == 400
    assert client.get(
        f"/evidence/ev_000000000000/entries/{hosts}/preview"
    ).status_code == 404
    assert client.get(
        f"/evidence/{EVIDENCE}/entries/99999999/preview"
    ).status_code == 404


def test_json_never_accepts_paths(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview",
        params={"path": "/etc/passwd"},
    )
    data = response.json()
    assert data["evidence_path"] == HOSTS_PATH
    assert "/etc/passwd" not in data["content"]


# ----------------------------------------------------------------------
# HTML panel
# ----------------------------------------------------------------------
def test_panel_escapes_evidence_html(env):
    client, services, record = env
    script = entry_id(services, SCRIPT_PATH)
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{script}/preview/panel"
    )
    assert response.status_code == 200
    body = response.text
    assert "<script>alert('xss')</script>" not in body
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in body
    assert "data-preview-content" in body
    assert "Copy all" in body
    assert "Copy selected text" in body


def test_panel_hosts_shows_search_and_line_numbers(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview/panel"
    ).text
    assert "www.malware430.com" in body
    assert "192.168.15.10" in body
    assert "preview-gutter" in body
    assert "data-preview-search" in body
    assert "text/plain" in body
    assert str(len(HOSTS_TEXT.encode("utf-8"))) in body


def test_panel_truncated_state(env):
    client, services, record = env
    big = entry_id(services, BIG_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{big}/preview/panel?limit=1024"
    ).text
    assert "Preview truncated" in body
    assert "truncated" in body
    assert 'data-preview-goto="1024"' in body


def test_panel_registry_shows_open_in_explorer(env):
    client, services, record = env
    amcache = entry_id(services, AMCACHE_PATH)
    hive_id = index_hive(services, amcache)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{amcache}/preview/panel"
    ).text
    assert "Windows Registry Hive" in body
    assert "Open in Registry Explorer" in body
    assert f'data-open-registry-hive="{hive_id}"' in body
    assert "regf" in body


def test_panel_registry_not_indexed_offers_parse(env):
    client, services, record = env
    amcache = entry_id(services, AMCACHE_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{amcache}/preview/panel"
    ).text
    assert "Parse hive" in body
    assert f"/evidence/{EVIDENCE}/registry/{amcache}/index" in body
    assert "Open in Registry Explorer" in body
    assert 'data-open-registry-tab=' in body


def test_panel_error_state(env):
    client, services, record = env
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id(services, DIR_PATH)}/preview/panel"
    )
    assert response.status_code == 200
    assert "extraction failed" in response.text
    assert "preview_directory_rejected" in response.text


def test_mcp_and_web_agree(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    web = client.get(
        f"/evidence/{EVIDENCE}/entries/{hosts}/preview?mode=auto&limit=65536"
    ).json()
    tool = mcp_server.preview_file_content(EVIDENCE, hosts)
    for key in (
        "evidence_id", "entry_id", "filename", "evidence_path",
        "detected_type", "preview_mode", "encoding", "offset",
        "returned_bytes", "total_size", "truncated", "content", "warnings",
        "trust", "next_offset", "has_more",
    ):
        assert web[key] == tool[key], key


# ----------------------------------------------------------------------
# registry hand-off routing
# ----------------------------------------------------------------------
def test_registry_tab_highlight(env):
    client, services, record = env
    amcache = entry_id(services, AMCACHE_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/registry?highlight={amcache}&include_deleted=1"
    ).text
    assert "registry-row-highlight" in body
    assert 'id="registry-focus-row"' in body


# ----------------------------------------------------------------------
# MCP
# ----------------------------------------------------------------------
def test_mcp_tool_contract(env):
    import asyncio

    tools = {tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())}
    tool = tools["preview_file_content"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is False
    schema = tool.inputSchema
    props = schema["properties"]
    assert set(props) >= {"evidence_id", "entry_id", "mode", "offset", "limit"}
    assert props["mode"]["default"] == "auto"
    assert props["limit"]["default"] == 65536
    assert "UNTRUSTED" in (tool.description or "").upper()


def test_mcp_registry_mode_does_not_dump_hive(env):
    client, services, record = env
    amcache = entry_id(services, AMCACHE_PATH)
    result = mcp_server.preview_file_content(EVIDENCE, amcache)
    assert result["preview_mode"] == "registry"
    assert result["returned_bytes"] <= 4096
    assert "registry" in result
    assert result["registry"]["suggested_tool"].startswith("registry_")


def test_mcp_rejects_bad_input(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    with pytest.raises(ToolError) as exc:
        mcp_server.preview_file_content(EVIDENCE, hosts, mode="exec")
    assert "preview_invalid_mode" in str(exc.value)
    with pytest.raises(ToolError):
        mcp_server.preview_file_content(EVIDENCE, hosts, offset=-1)
    with pytest.raises(ToolError):
        mcp_server.preview_file_content(EVIDENCE, hosts, limit=5 * 1024 * 1024)
    with pytest.raises(ToolError):
        mcp_server.preview_file_content("ev_000000000000", hosts)


def test_mcp_pagination_matches_offsets(env):
    client, services, record = env
    big = entry_id(services, BIG_PATH)
    first = mcp_server.preview_file_content(EVIDENCE, big, limit=1000)
    assert first["truncated"] is True
    second = mcp_server.preview_file_content(
        EVIDENCE, big, offset=first["next_offset"], limit=1000
    )
    assert second["offset"] == first["next_offset"]
    assert second["returned_bytes"] == 1000


def test_preview_panel_offers_larger_pages_and_download(env):
    client, services, record = env
    big = entry_id(services, BIG_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{big}/preview/panel?limit=1024"
    ).text
    assert "Load 256 KiB" in body
    assert "Load 1 MiB" in body
    assert "Download full copy" in body
    assert "/download" in body


def test_download_endpoint(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    response = client.get(f"/evidence/{EVIDENCE}/entries/{hosts}/download")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "www.malware430.com" in response.content.decode("utf-8")


def test_download_rejects_unknown_evidence(env):
    client, services, record = env
    hosts = entry_id(services, HOSTS_PATH)
    response = client.get(f"/evidence/ev_000000000000/entries/{hosts}/download")
    assert response.status_code == 400
