from __future__ import annotations

import dataclasses
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dfir_browser.core.config import Settings
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.services import build_services
from dfir_browser.web.app import create_app

from test_tree_store import (
    BASE_ROWS,
    DIRECTORY,
    EVIDENCE,
    FILE,
    SCAN,
    build_store,
    row,
)

SOURCE_SHA = "a" * 64
SCANNER = "test-scanner"


def make_settings(tmp_path: Path) -> Settings:
    return dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=tmp_path / "index" / "filesystem.db",
        auto_index=False,
        index_scanner_version=SCANNER,
    )


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


def install_index(tmp_path: Path, rows) -> Path:
    store = IndexStore(tmp_path / "index" / "filesystem.db")
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
            "index_schema_version": 3,
            "scanner_version": SCANNER,
        },
        "2020-01-01T00:00:00Z",
    )
    store.insert_entries(rows)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(rows),
        entries_indexed=len(rows),
        parse_errors=0,
        deleted_files=sum(1 for r in rows if r[12] and r[10] == FILE),
        deleted_directories=sum(
            1 for r in rows if r[12] and r[10] == DIRECTORY
        ),
        allocated_files=sum(1 for r in rows if not r[12] and r[10] == FILE),
        allocated_directories=sum(
            1 for r in rows if not r[12] and r[10] == DIRECTORY
        ),
        error_code=None,
        error_message=None,
    )
    return store.path


@pytest.fixture()
def client(tmp_path):
    settings = make_settings(tmp_path)
    install_index(tmp_path, BASE_ROWS)
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    app = create_app(settings, services)
    with TestClient(app) as test_client:
        yield test_client
    services.cleanup()


def tree_html(client) -> str:
    response = client.get(f"/evidence/{EVIDENCE}/tree")
    assert response.status_code == 200
    return response.text


def root_children(client) -> dict:
    response = client.get(f"/evidence/{EVIDENCE}/tree/children?parent_id=0")
    assert response.status_code == 200
    return response.json()


def child_id(client, name: str) -> int:
    response = client.get(f"/evidence/{EVIDENCE}/tree/children?parent_id=0")
    payload = response.json()
    return next(c["entry_id"] for c in payload["children"] if c["name"] == name)


def test_tree_page_has_aria_tree_structure(client) -> None:
    html = tree_html(client)
    assert 'role="tree"' in html
    assert 'role="treeitem"' in html
    assert 'role="group"' in html
    assert 'role="toolbar"' in html
    assert 'aria-expanded="true"' in html
    assert "Filter tree" in html
    assert "Collapse all" in html
    assert "Go to root" in html
    assert "Show deleted entries" in html
    assert "Directories only" in html
    assert 'aria-label="Evidence filesystem tree"' in html


def test_children_json_only_direct_children(client) -> None:
    root = root_children(client)
    names = {child["name"] for child in root["children"]}
    assert names == {"Users", "Windows", "$OrphanFiles"}
    assert "Public" not in names
    assert root["ok"] is True
    assert root["total"] == 3

    users = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={child_id(client, 'Users')}"
    ).json()
    assert {c["name"] for c in users["children"]} == {"Public", "IEUser"}


def test_include_deleted_toggle_changes_query(client) -> None:
    users_id = child_id(client, "Users")
    users = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={users_id}"
    ).json()
    public_id = next(c["entry_id"] for c in users["children"] if c["name"] == "Public")
    public = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={public_id}"
    ).json()
    downloads_id = next(
        c["entry_id"] for c in public["children"] if c["name"] == "Downloads"
    )
    with_deleted = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={downloads_id}"
    ).json()
    without = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={downloads_id}"
        "&include_deleted=0"
    ).json()
    assert with_deleted["total"] == 2
    assert without["total"] == 1
    assert {c["name"] for c in without["children"]} == {"desktop.ini"}


def test_directories_only_toggle_changes_query(client) -> None:
    users_id = child_id(client, "Users")
    dirs = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={users_id}"
        "&directories_only=1"
    ).json()
    assert {c["name"] for c in dirs["children"]} == {"Public", "IEUser"}


def test_tree_node_payload_schema(client) -> None:
    child = root_children(client)["children"][0]
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
    assert child["status"] in {"allocated", "deleted", "unallocated"}
    assert root_children(client)["trust"] == "untrusted_evidence_data"


def test_file_panel_shows_metadata_and_extract(client) -> None:
    users_id = child_id(client, "Users")
    users = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={users_id}"
    ).json()
    public_id = next(c["entry_id"] for c in users["children"] if c["name"] == "Public")
    public = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={public_id}"
    ).json()
    downloads_id = next(
        c["entry_id"] for c in public["children"] if c["name"] == "Downloads"
    )
    downloads = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={downloads_id}"
    ).json()
    sysinternals = next(
        c for c in downloads["children"] if c["name"] == "SysInternals.exe"
    )
    assert sysinternals["deleted"] is True
    panel = client.get(f"/evidence/{EVIDENCE}/entry/{sysinternals['entry_id']}")
    assert panel.status_code == 200
    assert "Untrusted evidence file" in panel.text
    assert "Users/Public/Downloads/SysInternals.exe" in panel.text
    assert "csrf_token" in panel.text


def test_directory_panel_lists_children_and_sort_controls(client) -> None:
    users_id = child_id(client, "Users")
    panel = client.get(f"/evidence/{EVIDENCE}/entry/{users_id}")
    assert panel.status_code == 200
    assert "Public" in panel.text
    assert "IEUser" in panel.text
    assert "data-tree-sort" in panel.text
    sorted_panel = client.get(
        f"/evidence/{EVIDENCE}/entry/{users_id}?sort=size&sort_dir=desc"
    )
    assert sorted_panel.status_code == 200


def test_reveal_returns_ancestor_chain(client) -> None:
    connection = sqlite3.connect(client.app.state.services.settings.index_database())
    try:
        target = connection.execute(
            "SELECT id FROM filesystem_entries WHERE full_path=?",
            ("Users/Public/Downloads/SysInternals.exe",),
        ).fetchone()[0]
    finally:
        connection.close()
    payload = client.get(
        f"/evidence/{EVIDENCE}/tree/reveal?entry_id={target}"
    ).json()
    assert payload["ok"] is True
    assert [a["name"] for a in payload["ancestors"]] == [
        "Users",
        "Public",
        "Downloads",
    ]
    assert payload["entry"]["deleted"] is True
    assert len(payload["steps"]) == 3
    assert payload["steps"][0]["page"] == 1


def test_invalid_and_foreign_entry_ids_rejected(client) -> None:
    for value in ("-1", "notanint", "1e3"):
        response = client.get(
            f"/evidence/{EVIDENCE}/tree/children?parent_id={value}"
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_entry_id"
    missing = client.get(f"/evidence/{EVIDENCE}/tree/children?parent_id=999999")
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "entry_not_found"
    panel = client.get(f"/evidence/{EVIDENCE}/entry/999999")
    assert panel.status_code == 404
    assert "Could not load" in panel.text


def test_non_directory_parent_is_rejected(client) -> None:
    connection = sqlite3.connect(client.app.state.services.settings.index_database())
    try:
        file_id = connection.execute(
            "SELECT id FROM filesystem_entries WHERE entry_type='file' LIMIT 1"
        ).fetchone()[0]
    finally:
        connection.close()
    response = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={file_id}"
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "not_a_directory"


def test_evidence_names_are_escaped_not_rendered_as_html(tmp_path) -> None:
    rows = [
        row("Studies", DIRECTORY),
        row("Studies/<script>alert(1)<script>.txt", FILE, inode=900),
        row('Studies/quote"name.txt', FILE, inode=901),
        row("Studies/日本語.txt", FILE, inode=902),
    ]
    settings = make_settings(tmp_path)
    install_index(tmp_path, rows)
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    with TestClient(create_app(settings, services)) as test_client:
        studies_id = next(
            c["entry_id"]
            for c in test_client.get(
                f"/evidence/{EVIDENCE}/tree/children?parent_id=0"
            ).json()["children"]
            if c["name"] == "Studies"
        )
        panel = test_client.get(f"/evidence/{EVIDENCE}/entry/{studies_id}")
        html = panel.text
        assert "<script>alert(1)<script>.txt" not in html
        assert "&lt;script&gt;" in html
        assert "|safe" not in html
        assert "日本語.txt" in html
    services.cleanup()


def test_tablist_has_aria_tab_roles(client) -> None:
    page = client.get(f"/evidence/{EVIDENCE}")
    assert page.status_code == 200
    html = page.text
    assert 'role="tablist"' in html
    assert html.count('role="tab"') >= 4
    assert 'aria-selected="true"' in html
    assert 'aria-controls="tab-content"' in html
    assert 'tabindex="-1"' in html


def test_tree_unavailable_when_index_not_ready(tmp_path) -> None:
    settings = make_settings(tmp_path)
    IndexStore(tmp_path / "index" / "filesystem.db").ensure_schema()
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    with TestClient(create_app(settings, services)) as test_client:
        children_response = test_client.get(
            f"/evidence/{EVIDENCE}/tree/children?parent_id=0"
        )
        assert children_response.status_code == 409
        assert children_response.json()["error"]["code"] in {
            "index_not_ready",
            "index_stale",
        }
        panel = test_client.get(f"/evidence/{EVIDENCE}/tree")
        assert panel.status_code == 200
        assert "Filesystem index required" in panel.text
    services.cleanup()


def test_static_tree_assets_are_local(client) -> None:
    js = client.get("/static/tree.js")
    assert js.status_code == 200
    assert "textContent" in js.text
    assert "https://" not in js.text
    assert "aria-expanded" in js.text
    assert "ArrowDown" in js.text
    assert "sessionStorage" in js.text
    css = client.get("/static/style.css")
    assert css.status_code == 200
    assert ".tree-node" in css.text
    assert re.search(r"max-width:\s*640px", css.text)
    assert "@media" in css.text


def test_tree_markup_never_uses_inner_html_for_names(client) -> None:
    js = client.get("/static/tree.js").text
    assert "textContent" in js
    # Evidence values are only ever assigned through textContent.
    for pattern in (
        "name.innerHTML",
        ".insertAdjacentHTML",
        "document.write",
        "eval(",
    ):
        assert pattern not in js


def test_root_panel_is_synthetic_volume_node(client) -> None:
    panel = client.get(f"/evidence/{EVIDENCE}/entry/0")
    assert panel.status_code == 200
    assert "sample.E01" in panel.text
    assert "Users" in panel.text
    assert "data-tree-open-id" in panel.text


def test_search_and_deleted_results_offer_reveal(client) -> None:
    search = client.get(f"/evidence/{EVIDENCE}/search?q=Users&exact=1")
    assert search.status_code == 200
    assert "data-reveal-entry" in search.text
    deleted = client.get(f"/evidence/{EVIDENCE}/deleted")
    assert deleted.status_code == 200
    assert "data-reveal-entry" in deleted.text


def test_filter_and_pagination_params_are_validated(client) -> None:
    bad_filter = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id=0&filter=" + "x" * 200
    )
    assert bad_filter.status_code == 400
    assert bad_filter.json()["error"]["code"] == "invalid_search_query"
    bad_page = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id=0&page=0"
    )
    assert bad_page.status_code == 400
    assert bad_page.json()["error"]["code"] == "invalid_page"


def test_tabpanel_labels_follow_active_tab_contract(client) -> None:
    page = client.get(f"/evidence/{EVIDENCE}")
    html = page.text
    for tab_id in (
        "tab-tree",
        "tab-entries",
        "tab-deleted",
        "tab-search",
        "tab-registry",
    ):
        assert f'id="{tab_id}"' in html
    assert html.count('aria-controls="tab-content"') >= 5
    assert 'role="tabpanel"' in html
    js = client.get("/static/tree.js").text
    assert "labelPanel" in js
    assert 'setAttribute("aria-labelledby"' in js
    assert "data-active-tab" in js


def test_search_form_enter_contract(client) -> None:
    page = client.get(f"/evidence/{EVIDENCE}/search")
    assert page.status_code == 200
    assert "data-search-form" in page.text
    assert "data-search-submit" in page.text
    forms = client.get("/static/forms.js")
    assert forms.status_code == 200
    assert '"Enter"' in forms.text
    assert "requestSubmit" in forms.text


def test_right_pane_click_reveals_unloaded_entry(client) -> None:
    """A directory listing link must work even when the node is not in the tree.

    The right pane lists direct children; the left tree only holds expanded
    nodes. Clicking a child that was never expanded used to do nothing because
    nodeById() returned null. The handler must fall back to revealEntry().
    """
    tree_js = client.get("/static/tree.js")
    assert tree_js.status_code == 200
    script = tree_js.text
    assert "bindPanel" in script
    marker = "data-tree-open-id"
    assert marker in script
    # The unloaded-node branch must call revealEntry before bailing out.
    unloaded = script.split("var node = self.nodeById(id);", 1)[1].split(
        "});", 1
    )[0]
    assert "if (!node)" in unloaded
    assert "revealEntry(id)" in unloaded
    # And it must return instead of falling through to selectNode.
    assert "return;" in unloaded


def test_tree_children_cache_key_includes_page_size(client) -> None:
    """A 100-item page and a 500-item page must not share a cache entry.

    Reveal asks for a large page; without the page size in the key it reused a
    cached 100-item page and could not find deeper children (for example
    etc/os-release among 236 entries).
    """
    script = client.get("/static/tree.js").text
    assert 'var key = id + ":" + page + ":" + pageSize;' in script
