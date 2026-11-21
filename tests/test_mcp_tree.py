from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import EntryNotFoundError, InvalidEntryIdError
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.services import build_services

import dfir_browser.mcp_server as mcp_server

from test_tree_store import (
    BASE_ROWS,
    DIRECTORY,
    EVIDENCE,
    FILE,
    SCAN,
    row,
)

SOURCE_SHA = "b" * 64
SCANNER = "mcp-tree-scanner"


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
            scope="volume",
            filesystem="NTFS",
            offset_sectors=0,
            method="fsstat",
        ),
        registered_at="2020-01-01T00:00:00Z",
        status="ready",
        warnings=[],
    )


@pytest.fixture()
def services(tmp_path, monkeypatch):
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
            "index_schema_version": 2,
            "scanner_version": SCANNER,
        },
        "2020-01-01T00:00:00Z",
    )
    store.insert_entries(BASE_ROWS)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(BASE_ROWS),
        entries_indexed=len(BASE_ROWS),
        parse_errors=0,
        deleted_files=sum(1 for r in BASE_ROWS if r[12] and r[10] == FILE),
        deleted_directories=sum(
            1 for r in BASE_ROWS if r[12] and r[10] == DIRECTORY
        ),
        allocated_files=sum(
            1 for r in BASE_ROWS if not r[12] and r[10] == FILE
        ),
        allocated_directories=sum(
            1 for r in BASE_ROWS if not r[12] and r[10] == DIRECTORY
        ),
        error_code=None,
        error_message=None,
    )
    settings = dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=index_path,
        auto_index=False,
        index_scanner_version=SCANNER,
    )
    built = build_services(settings)
    built.indexer._fls_version_cache = ""
    built.evidence.registry.upsert(make_record().to_dict())
    monkeypatch.setattr(mcp_server, "get_services", lambda: built)
    yield built
    built.cleanup()


def test_tree_children_tool_schema(services) -> None:
    payload = mcp_server.filesystem_list_tree_children(EVIDENCE, 0)
    assert payload["trust"] == "untrusted_evidence_data"
    assert payload["total"] == 3
    names = {child["name"] for child in payload["children"]}
    assert names == {"Users", "Windows", "$OrphanFiles"}
    assert payload["page"] == 1
    assert payload["page_size"] == 100
    assert payload["pages"] >= 1
    assert payload["has_more"] is False
    child = payload["children"][0]
    for key in (
        "entry_id",
        "parent_id",
        "name",
        "path",
        "type",
        "mft",
        "size",
        "allocated",
        "deleted",
        "status",
        "has_children",
    ):
        assert key in child


def test_tree_children_pagination(services) -> None:
    first = mcp_server.filesystem_list_tree_children(EVIDENCE, 0, page_size=2)
    assert len(first["children"]) == 2
    assert first["total"] == 3
    assert first["has_more"] is True
    second = mcp_server.filesystem_list_tree_children(EVIDENCE, 0, page=2, page_size=2)
    assert len(second["children"]) == 1
    assert second["has_more"] is False


def test_tree_children_excludes_deleted_when_requested(services) -> None:
    payload = mcp_server.filesystem_list_tree_children(
        EVIDENCE, 0, include_deleted=False
    )
    assert "$OrphanFiles" not in {c["name"] for c in payload["children"]}


def test_tree_children_directories_only(services) -> None:
    users_id = next(
        c["entry_id"]
        for c in mcp_server.filesystem_list_tree_children(EVIDENCE, 0)["children"]
        if c["name"] == "Users"
    )
    payload = mcp_server.filesystem_list_tree_children(
        EVIDENCE, users_id, directories_only=True
    )
    assert {c["name"] for c in payload["children"]} == {"Public", "IEUser"}


def test_tree_ancestors_tool(services) -> None:
    import sqlite3

    connection = sqlite3.connect(services.settings.index_database())
    try:
        target = connection.execute(
            "SELECT id FROM filesystem_entries WHERE full_path=?",
            ("Users/Public/Downloads/SysInternals.exe",),
        ).fetchone()[0]
    finally:
        connection.close()
    payload = mcp_server.filesystem_tree_ancestors(EVIDENCE, target)
    assert [a["name"] for a in payload["ancestors"]] == [
        "Users",
        "Public",
        "Downloads",
    ]
    assert payload["entry"]["deleted"] is True
    assert payload["resolvable"] is True
    assert payload["root_id"] == 0


def test_tree_children_rejects_invalid_id(services) -> None:
    with pytest.raises(Exception) as excinfo:
        mcp_server.filesystem_list_tree_children(EVIDENCE, -5)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "invalid_entry_id"


def test_tree_children_rejects_missing_entry(services) -> None:
    with pytest.raises(Exception) as excinfo:
        mcp_server.filesystem_list_tree_children(EVIDENCE, 999999)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "entry_not_found"


def test_tree_children_rejects_file_parent(services) -> None:
    import sqlite3

    connection = sqlite3.connect(services.settings.index_database())
    try:
        file_id = connection.execute(
            "SELECT id FROM filesystem_entries WHERE entry_type='file' LIMIT 1"
        ).fetchone()[0]
    finally:
        connection.close()
    with pytest.raises(Exception) as excinfo:
        mcp_server.filesystem_list_tree_children(EVIDENCE, file_id)
    payload = json.loads(str(excinfo.value))
    assert payload["error"]["code"] == "not_a_directory"


def test_tree_tools_are_read_only_annotations() -> None:
    import asyncio

    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    for name in (
        "filesystem_list_tree_children",
        "filesystem_tree_ancestors",
    ):
        annotations = tools[name].annotations
        assert annotations.readOnlyHint is True
        assert annotations.destructiveHint is False
        description = (tools[name].description or "").upper()
        assert "UNTRUSTED" in description
