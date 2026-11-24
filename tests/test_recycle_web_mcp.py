"""Web + MCP tests for Recycle Bin metadata analysis."""
from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError

import dfir_browser.mcp_server as mcp_server
from dfir_browser.web.app import create_app

from preview_helpers import (
    EVIDENCE,
    _row,
    build_preview_services,
    entry_id,
    stub_preview_extract,
)

SID = "S-1-5-21-3061953532-2461696977-1363062292-1001"
RECYCLE_ROOT = f"$Recycle.Bin/{SID}"
INFO_PATH = f"{RECYCLE_ROOT}/$IW9BJ2Z.txt"
CONTENT_PATH = f"{RECYCLE_ROOT}/$RW9BJ2Z.txt"
ORPHAN_PATH = f"{RECYCLE_ROOT}/$IORPHAN1.docx"
OTHER_PATH = "Users/IEUser/Documents/notes.txt"
DELETED_AT = datetime(2021, 4, 29, 18, 22, 17, 598000, tzinfo=timezone.utc)

INFO_INODE = 61001
INFO_ORPHAN_INODE = 61002


def filetime(moment: datetime) -> int:
    return int(
        (moment - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()
        * 10_000_000
    )


def info_record(original: str, *, size: int = 754, deleted=DELETED_AT) -> bytes:
    encoded = (original + "\x00").encode("utf-16-le")
    return (
        struct.pack("<QQQI", 2, size, filetime(deleted), len(encoded) // 2)
        + encoded
    )


ORIGINAL = r"C:\Users\John Doe\Downloads\10-million-password-list-top-100.txt"


def _rows():
    return [
        _row("$Recycle.Bin", "$Recycle.Bin", 61000, 0, entry_type="directory"),
        _row(RECYCLE_ROOT, SID, 61001, 0, entry_type="directory"),
        _row(INFO_PATH, "$IW9BJ2Z.txt", INFO_INODE, 158),
        _row(CONTENT_PATH, "$RW9BJ2Z.txt", 61003, 754),
        _row(ORPHAN_PATH, "$IORPHAN1.docx", INFO_ORPHAN_INODE, 120),
        _row(OTHER_PATH, "notes.txt", 61010, 24),
    ]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    services, record = build_preview_services(tmp_path, {}, rows=_rows())
    stub_preview_extract(
        services,
        {
            INFO_INODE: info_record(ORIGINAL),
            INFO_ORPHAN_INODE: info_record(r"C:\Temp\gone.docx", size=99),
            61003: b"X" * 754,
            61010: b"plain ascii\nsecond line\n",
        },
    )
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record
    services.cleanup()


# ----------------------------------------------------------------------
# core resolution through the service
# ----------------------------------------------------------------------
def test_info_entry_gets_deletion_time(env):
    client, services, record = env
    result = services.recycle_bin.metadata(
        record, entry_id(services, INFO_PATH)
    ).to_dict()
    assert result["is_recycle_entry"] is True
    assert result["kind"] == "info"
    assert result["state"] == "ready"
    assert result["sid"] == SID
    assert result["deleted_time_utc"].startswith("2021-04-29T18:22:17.598")
    assert result["deletion_source"] == "$I deletion timestamp"
    assert result["original_path"] == ORIGINAL
    assert result["original_size"] == 754
    assert result["content_entry_id"] == entry_id(services, CONTENT_PATH)
    assert result["trust"] == "untrusted_evidence_data"


def test_content_entry_resolves_its_pair(env):
    client, services, record = env
    result = services.recycle_bin.metadata(
        record, entry_id(services, CONTENT_PATH)
    ).to_dict()
    assert result["kind"] == "content"
    assert result["info_entry_id"] == entry_id(services, INFO_PATH)
    assert result["deleted_time_utc"].startswith("2021-04-29T18:22:17")


def test_missing_content_is_reported(env):
    client, services, record = env
    result = services.recycle_bin.metadata(
        record, entry_id(services, ORPHAN_PATH)
    ).to_dict()
    assert result["info_entry_id"] == entry_id(services, ORPHAN_PATH)
    assert result["content_entry_id"] is None
    assert any("no matching $R" in w for w in result["warnings"])


def test_non_recycle_entry_is_flagged(env):
    client, services, record = env
    result = services.recycle_bin.metadata(
        record, entry_id(services, OTHER_PATH)
    ).to_dict()
    assert result["is_recycle_entry"] is False
    assert result["state"] == "not_recycle_entry"


def test_sid_directory_is_not_a_recycle_record(env):
    """A SID directory holds $I/$R files but is not itself one."""
    client, services, record = env
    result = services.recycle_bin.metadata(
        record, entry_id(services, RECYCLE_ROOT)
    ).to_dict()
    assert result["is_recycle_entry"] is False
    assert result["state"] == "not_recycle_entry"


# ----------------------------------------------------------------------
# web endpoints
# ----------------------------------------------------------------------
def test_panel_shows_deletion_time_and_original_path(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    response = client.get(f"/evidence/{EVIDENCE}/recycle/{info}")
    assert response.status_code == 200
    body = response.text
    assert "Deleted at (UTC)" in body
    assert "2021-04-29T18:22:17.598000Z" in body
    assert "10-million-password-list-top-100.txt" in body
    assert "$I record" in body
    assert "Open $R content entry" in body
    assert "untrusted" in body.lower()


def test_panel_for_non_recycle_entry(env):
    client, services, record = env
    other = entry_id(services, OTHER_PATH)
    body = client.get(f"/evidence/{EVIDENCE}/recycle/{other}").text
    assert "not inside a Recycle Bin" in body


def test_json_endpoint(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    data = client.get(f"/evidence/{EVIDENCE}/recycle/{info}/json").json()
    assert data["ok"] is True
    assert data["deleted_time_utc"].startswith("2021-04-29T18:22:17")
    assert data["original_path"] == ORIGINAL
    assert data["trust"] == "untrusted_evidence_data"


def test_json_rejects_unknown_evidence(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    response = client.get(f"/evidence/ev_000000000000/recycle/{info}/json")
    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_panel_escapes_evidence_paths(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    body = client.get(f"/evidence/{EVIDENCE}/recycle/{info}").text
    assert "<script>" not in body.lower()


# ----------------------------------------------------------------------
# MCP parity
# ----------------------------------------------------------------------
def test_mcp_matches_web(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    web = client.get(f"/evidence/{EVIDENCE}/recycle/{info}/json").json()
    tool = mcp_server.recycle_bin_metadata(EVIDENCE, info)
    for key in (
        "entry_id", "kind", "state", "sid", "deleted_time_utc",
        "original_path", "original_size", "info_entry_id",
        "content_entry_id", "trust", "warnings",
    ):
        assert web[key] == tool[key], key


def test_mcp_rejects_bad_evidence(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    with pytest.raises(ToolError):
        mcp_server.recycle_bin_metadata("ev_000000000000", info)


def test_mcp_tool_is_read_only():
    import asyncio

    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    tool = tools["recycle_bin_metadata"]
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.openWorldHint is False
    assert "UNTRUSTED" in (tool.description or "").upper()


# ----------------------------------------------------------------------
# directory listing hints
# ----------------------------------------------------------------------
def test_directory_listing_shows_deleted_time(env):
    client, services, record = env
    listing = entry_id(services, RECYCLE_ROOT)
    response = client.get(
        f"/evidence/{EVIDENCE}/entry/{listing}?include_deleted=1&directories_only=0"
    )
    assert response.status_code == 200
    body = response.text
    assert "Deleted at (UTC)" in body
    assert "2021-04-29T18:22:17.598000Z" in body
    assert "10-million-password-list-top-100.txt" in body


def test_directory_hints_pair_both_names(env):
    client, services, record = env
    hints = services.recycle_bin.directory_hints(
        record,
        [
            services.indexer.tree_entry(record, entry_id(services, INFO_PATH)),
            services.indexer.tree_entry(record, entry_id(services, CONTENT_PATH)),
            services.indexer.tree_entry(record, entry_id(services, OTHER_PATH)),
        ],
    )
    info_id = entry_id(services, INFO_PATH)
    content_id = entry_id(services, CONTENT_PATH)
    assert hints[info_id]["deleted_time_utc"].startswith("2021-04-29T18:22:17")
    assert hints[content_id]["deleted_time_utc"] == hints[info_id]["deleted_time_utc"]
    assert hints[info_id]["paired"] is True
    # A non recycle entry is not present in the hints map.
    assert entry_id(services, OTHER_PATH) not in hints


def test_directory_hints_report_missing_info(env):
    client, services, record = env
    hints = services.recycle_bin.directory_hints(
        record,
        [services.indexer.tree_entry(record, entry_id(services, ORPHAN_PATH))],
    )
    orphan = hints[entry_id(services, ORPHAN_PATH)]
    # The orphan has its own $I, so it has a time but no pair.
    assert orphan["deleted_time_utc"] is not None
    assert orphan["paired"] is False


def test_directory_listing_survives_bad_recycle_data(env, monkeypatch):
    client, services, record = env

    def boom(*args, **kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(services.recycle_bin, "directory_hints", boom)
    listing = entry_id(services, RECYCLE_ROOT)
    response = client.get(
        f"/evidence/{EVIDENCE}/entry/{listing}?include_deleted=1&directories_only=0"
    )
    assert response.status_code == 200
    assert "$IW9BJ2Z.txt" in response.text


def test_recycle_card_is_above_metadata(env):
    client, services, record = env
    info = entry_id(services, INFO_PATH)
    body = client.get(f"/evidence/{EVIDENCE}/entry/{info}").text
    assert 'id="recycle-panel"' in body
    # The deletion-time card must come before the long metadata/preview blocks
    # so it is visible without deep scrolling.
    assert body.index('id="recycle-panel"') < body.index('id="preview-card-')
