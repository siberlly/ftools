from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from dfir_browser.core.index_models import (
    INDEX_SCHEMA_VERSION,
    EntryNotFoundError,
    IndexNotReadyError,
    InvalidEntryIdError,
    TreeNode,
    validate_entry_id,
)
from dfir_browser.core.index_store import IndexStore, escape_like

EVIDENCE = "ev_0123456789ab"
SCAN = "scan_tree"
DIRECTORY = "directory"
FILE = "file"


def row(
    full_path: str,
    entry_type: str,
    *,
    parent_path: str | None = None,
    inode: int = 100,
    deleted: bool = False,
    allocated: bool = True,
    size: int | None = 10,
    modified: str | None = "2020-01-01 00:00:00",
):
    parent = (
        parent_path
        if parent_path is not None
        else (full_path.rsplit("/", 1)[0] if "/" in full_path else "")
    )
    basename = full_path.rsplit("/", 1)[-1]
    return (
        EVIDENCE,
        SCAN,
        full_path,
        parent,
        basename,
        basename.rsplit(".", 1)[-1].lower() if "." in basename else "",
        inode,
        1,
        128,
        "-/r" if deleted else "-/-",
        entry_type,
        1 if allocated else 0,
        1 if deleted else 0,
        size,
        modified,
        modified,
        modified,
        modified,
        "hash",
        None,
    )


def build_store(tmp_path: Path, rows) -> IndexStore:
    store = IndexStore(tmp_path / "index.db")
    store.ensure_schema()
    store.begin_scan(
        EVIDENCE,
        SCAN,
        {
            "source_sha256": "a" * 64,
            "raw_exposure_path": "/raw/exposure",
            "filesystem": "NTFS",
            "offset_sectors": 0,
            "fls_version": "4.12",
            "index_schema_version": INDEX_SCHEMA_VERSION,
            "scanner_version": "test-scanner",
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
        deleted_directories=sum(1 for r in rows if r[12] and r[10] == DIRECTORY),
        allocated_files=sum(1 for r in rows if not r[12] and r[10] == FILE),
        allocated_directories=sum(
            1 for r in rows if not r[12] and r[10] == DIRECTORY
        ),
        error_code=None,
        error_message=None,
    )
    return store


BASE_ROWS = [
    row("Users", DIRECTORY, inode=1746),
    row("Users/Public", DIRECTORY, inode=500),
    row("Users/Public/Downloads", DIRECTORY, inode=501),
    row("Users/Public/Downloads/desktop.ini", FILE, inode=502, size=174),
    row(
        "Users/Public/Downloads/SysInternals.exe",
        FILE,
        inode=503,
        deleted=True,
        allocated=False,
        size=57344,
    ),
    row("Users/IEUser", DIRECTORY, inode=83437),
    row("Windows", DIRECTORY, inode=1000),
    row("$OrphanFiles", DIRECTORY, inode=2000, deleted=True, allocated=False),
    row(
        "$OrphanFiles/lost.txt",
        FILE,
        inode=2001,
        deleted=True,
        allocated=False,
    ),
]


def children(store, parent_id, **kwargs):
    defaults = dict(
        include_deleted=True,
        directories_only=False,
        filter_text=None,
        sort="path",
        sort_dir="asc",
        page=1,
        page_size=100,
    )
    defaults.update(kwargs)
    return store.children_of(EVIDENCE, SCAN, parent_id, **defaults)


def test_schema_upgrade_to_tree_version(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    connection = sqlite3.connect(store.path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            INDEX_SCHEMA_VERSION
        )
        columns = {
            r[1] for r in connection.execute("PRAGMA table_info(filesystem_entries)")
        }
        assert {"parent_id", "has_children"} <= columns
    finally:
        connection.close()


def test_schema_v1_is_upgraded_and_preserves_rows(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE evidence_indexes (
          evidence_id TEXT PRIMARY KEY,
          source_sha256 TEXT,
          raw_exposure_path TEXT,
          filesystem TEXT,
          offset_sectors INTEGER,
          fls_version TEXT,
          index_schema_version INTEGER NOT NULL,
          scanner_version TEXT NOT NULL,
          status TEXT NOT NULL,
          stale INTEGER NOT NULL DEFAULT 0,
          scan_id TEXT,
          started_at TEXT,
          completed_at TEXT,
          entries_seen INTEGER NOT NULL DEFAULT 0,
          entries_indexed INTEGER NOT NULL DEFAULT 0,
          parse_errors INTEGER NOT NULL DEFAULT 0,
          deleted_files INTEGER NOT NULL DEFAULT 0,
          deleted_directories INTEGER NOT NULL DEFAULT 0,
          allocated_files INTEGER NOT NULL DEFAULT 0,
          allocated_directories INTEGER NOT NULL DEFAULT 0,
          current_path TEXT,
          error_code TEXT,
          error_message TEXT,
          updated_at TEXT
        );
        CREATE TABLE filesystem_entries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          evidence_id TEXT NOT NULL,
          scan_id TEXT NOT NULL,
          full_path TEXT NOT NULL,
          parent_path TEXT NOT NULL,
          basename TEXT NOT NULL,
          extension TEXT NOT NULL DEFAULT '',
          inode INTEGER,
          sequence INTEGER,
          attribute_id INTEGER,
          fls_type TEXT,
          entry_type TEXT NOT NULL,
          allocated INTEGER NOT NULL,
          deleted INTEGER NOT NULL,
          size INTEGER,
          created_time TEXT,
          modified_time TEXT,
          accessed_time TEXT,
          mft_modified_time TEXT,
          raw_line_hash TEXT
        );
        CREATE TABLE filesystem_parse_errors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          evidence_id TEXT NOT NULL,
          scan_id TEXT NOT NULL,
          line_no INTEGER,
          raw_line TEXT,
          error TEXT,
          created_at TEXT
        );
        PRAGMA user_version = 1;
        """
    )
    connection.execute(
        "INSERT INTO evidence_indexes (evidence_id, index_schema_version, "
        "scanner_version, status, scan_id) VALUES (?, 1, 'old', 'ready', ?)",
        (EVIDENCE, SCAN),
    )
    legacy = [
        (EVIDENCE, SCAN, "Users", "", "Users", "", 1746, 1, 128, "-/-",
         DIRECTORY, 1, 0, None, None, None, None, None, "h"),
        (EVIDENCE, SCAN, "Users/Public", "Users", "Public", "", 500, 1, 128,
         "-/-", DIRECTORY, 1, 0, None, None, None, None, None, "h"),
    ]
    connection.executemany(
        "INSERT INTO filesystem_entries (evidence_id, scan_id, full_path, "
        "parent_path, basename, extension, inode, sequence, attribute_id, "
        "fls_type, entry_type, allocated, deleted, size, created_time, "
        "modified_time, accessed_time, mft_modified_time, raw_line_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        legacy,
    )
    connection.commit()
    connection.close()

    store = IndexStore(path)
    store.ensure_schema()
    upgrade = sqlite3.connect(path)
    try:
        assert upgrade.execute("PRAGMA user_version").fetchone()[0] == 2
        nulls = upgrade.execute(
            "SELECT COUNT(*) FROM filesystem_entries WHERE parent_id IS NULL"
        ).fetchone()[0]
        assert nulls == 1
        public_parent = upgrade.execute(
            "SELECT parent_id FROM filesystem_entries WHERE full_path='Users/Public'"
        ).fetchone()[0]
        assert public_parent is not None
    finally:
        upgrade.close()


def test_root_children_only_direct_entries(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    rows, total = children(store, None)
    names = {item.basename for item in rows}
    assert total == 3
    assert names == {"Users", "Windows", "$OrphanFiles"}
    assert "Users/Public" not in {item.full_path for item in rows}


def test_lazy_direct_children_nested(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    users = store.get_entry_by_path(EVIDENCE, SCAN, "Users")
    rows, total = children(store, users.id)
    assert total == 2
    assert {item.basename for item in rows} == {"Public", "IEUser"}
    public = store.get_entry_by_path(EVIDENCE, SCAN, "Users/Public")
    rows, total = children(store, public.id)
    assert [item.basename for item in rows] == ["Downloads"]
    downloads = store.get_entry_by_path(EVIDENCE, SCAN, "Users/Public/Downloads")
    rows, total = children(store, downloads.id)
    assert {item.basename for item in rows} == {
        "desktop.ini",
        "SysInternals.exe",
    }


def test_pagination_is_stable_and_bounded(tmp_path: Path) -> None:
    rows = [row("Big", DIRECTORY)]
    for index in range(25):
        rows.append(row(f"Big/file{index:02d}.txt", FILE, inode=300 + index))
    store = build_store(tmp_path, rows)
    big = store.get_entry_by_path(EVIDENCE, SCAN, "Big")
    page1, total = children(store, big.id, page=1, page_size=10)
    page3, _ = children(store, big.id, page=3, page_size=10)
    assert total == 25
    assert len(page1) == 10
    assert len(page3) == 5
    assert {item.id for item in page1}.isdisjoint({item.id for item in page3})


def test_deleted_file_and_directory(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    downloads = store.get_entry_by_path(EVIDENCE, SCAN, "Users/Public/Downloads")
    rows, _ = children(store, downloads.id)
    deleted = [item for item in rows if item.deleted]
    assert len(deleted) == 1
    assert deleted[0].basename == "SysInternals.exe"
    assert deleted[0].allocated is False
    assert deleted[0].inode == 503

    orphan = store.get_entry_by_path(EVIDENCE, SCAN, "$OrphanFiles")
    assert orphan.deleted is True
    orphan_rows, _ = children(store, orphan.id)
    assert [item.basename for item in orphan_rows] == ["lost.txt"]


def test_include_deleted_filter_changes_query(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    downloads = store.get_entry_by_path(EVIDENCE, SCAN, "Users/Public/Downloads")
    with_deleted, total_all = children(store, downloads.id, include_deleted=True)
    without, total_live = children(store, downloads.id, include_deleted=False)
    assert total_all == 2
    assert total_live == 1
    assert [item.basename for item in without] == ["desktop.ini"]
    assert len(with_deleted) == 2


def test_directories_only_filter(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    users = store.get_entry_by_path(EVIDENCE, SCAN, "Users")
    rows, total = children(store, users.id, directories_only=True)
    assert total == 2
    assert {item.basename for item in rows} == {"Public", "IEUser"}


def test_filter_text_escapes_like_wildcards(tmp_path: Path) -> None:
    rows = [
        row("Data", DIRECTORY),
        row("Data/100%done.txt", FILE),
        row("Data/ordinary.txt", FILE, inode=101),
    ]
    store = build_store(tmp_path, rows)
    data = store.get_entry_by_path(EVIDENCE, SCAN, "Data")
    found, total = children(store, data.id, filter_text="100%")
    assert total == 1
    assert found[0].basename == "100%done.txt"
    assert escape_like("100%") == "100\\%"
    underscore, total = children(store, data.id, filter_text="_")
    assert total == 0


def test_duplicate_filenames_in_different_directories(tmp_path: Path) -> None:
    rows = [
        row("A", DIRECTORY, inode=10),
        row("B", DIRECTORY, inode=11),
        row("A/same.txt", FILE, inode=12),
        row("B/same.txt", FILE, inode=13),
    ]
    store = build_store(tmp_path, rows)
    a = store.get_entry_by_path(EVIDENCE, SCAN, "A")
    b = store.get_entry_by_path(EVIDENCE, SCAN, "B")
    a_rows, _ = children(store, a.id)
    b_rows, _ = children(store, b.id)
    assert a_rows[0].basename == b_rows[0].basename == "same.txt"
    assert a_rows[0].id != b_rows[0].id
    assert a_rows[0].inode != b_rows[0].inode


def test_hardlink_same_inode_multiple_paths(tmp_path: Path) -> None:
    rows = [
        row("Dir1", DIRECTORY, inode=20),
        row("Dir2", DIRECTORY, inode=21),
        row("Dir1/linked.bin", FILE, inode=99),
        row("Dir2/linked.bin", FILE, inode=99),
    ]
    store = build_store(tmp_path, rows)
    dir1 = store.get_entry_by_path(EVIDENCE, SCAN, "Dir1")
    dir2 = store.get_entry_by_path(EVIDENCE, SCAN, "Dir2")
    left, _ = children(store, dir1.id)
    right, _ = children(store, dir2.id)
    assert left[0].inode == right[0].inode == 99
    assert left[0].id != right[0].id


def test_duplicate_directory_path_prefers_allocated(tmp_path: Path) -> None:
    rows = [
        row("Dup", DIRECTORY, inode=30, deleted=True, allocated=False),
        row("Dup", DIRECTORY, inode=31),
        row("Dup/child.txt", FILE, inode=32),
    ]
    store = build_store(tmp_path, rows)
    allocated = [
        item
        for item in store.children_of(
            EVIDENCE,
            SCAN,
            None,
            include_deleted=True,
            directories_only=False,
            filter_text=None,
            sort="path",
            sort_dir="asc",
            page=1,
            page_size=100,
        )[0]
        if item.basename == "Dup"
    ]
    live = [item for item in allocated if not item.deleted]
    assert len(live) == 1
    child_rows, _ = children(store, live[0].id)
    assert [item.basename for item in child_rows] == ["child.txt"]


def test_unicode_long_names_and_escaped_html(tmp_path: Path) -> None:
    long_name = "n" * 240 + ".txt"
    rows = [
        row("Studies", DIRECTORY),
        row("Studies/日本語ファイル.txt", FILE, inode=40),
        row(f"Studies/{long_name}", FILE, inode=41),
        row("Studies/<script>alert(1)<script>.txt", FILE, inode=42),
    ]
    store = build_store(tmp_path, rows)
    studies = store.get_entry_by_path(EVIDENCE, SCAN, "Studies")
    found, total = children(store, studies.id)
    names = {item.basename for item in found}
    assert total == 3
    assert "日本語ファイル.txt" in names
    assert long_name in names
    assert "<script>alert(1)<script>.txt" in names
    node = found[0].to_tree_node()
    assert node.to_dict()["name"] in names


def test_entry_without_timestamps(tmp_path: Path) -> None:
    rows = [
        row("EmptyDir", DIRECTORY, inode=50),
        row("EmptyDir/no-times.bin", FILE, inode=51, modified=None),
    ]
    store = build_store(tmp_path, rows)
    empty = store.get_entry_by_path(EVIDENCE, SCAN, "EmptyDir")
    found, _ = children(store, empty.id)
    assert found[0].modified_time is None
    assert found[0].to_tree_node().to_dict()["modified_time"] is None


def test_empty_directory(tmp_path: Path) -> None:
    store = build_store(
        tmp_path, [row("Empty", DIRECTORY, inode=60)]
    )
    empty = store.get_entry_by_path(EVIDENCE, SCAN, "Empty")
    found, total = children(store, empty.id)
    assert found == []
    assert total == 0
    assert empty.entry_type == DIRECTORY


def test_invalid_path_is_not_resolved(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    with pytest.raises(EntryNotFoundError):
        store.get_entry_by_path(EVIDENCE, SCAN, "does/not/exist")
    with pytest.raises(EntryNotFoundError):
        store.get_entry_by_path(EVIDENCE, SCAN, "../../etc/passwd")


def test_ancestors_chain_root_first(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    downloads = store.get_entry_by_path(EVIDENCE, SCAN, "Users/Public/Downloads")
    entry = store.get_entry_by_path(
        EVIDENCE, SCAN, "Users/Public/Downloads/SysInternals.exe"
    )
    resolved, ancestors = store.entry_ancestors(EVIDENCE, SCAN, entry.id)
    assert resolved.id == entry.id
    assert [item.basename for item in ancestors] == [
        "Users",
        "Public",
        "Downloads",
    ]
    assert ancestors[-1].id == downloads.id


def test_orphan_entries_attach_to_root_with_explanation(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    orphan_file = store.get_entry_by_path(
        EVIDENCE, SCAN, "$OrphanFiles/lost.txt"
    )
    assert orphan_file.parent_id is not None
    missing_parent_rows = [row("NoParent/orphan.bin", FILE, inode=70)]
    store2 = build_store(tmp_path / "second", missing_parent_rows)
    orphan = store2.get_entry_by_path(EVIDENCE, SCAN, "NoParent/orphan.bin")
    assert orphan.parent_id is None
    root_rows, _ = store2.children_of(
        EVIDENCE,
        SCAN,
        None,
        include_deleted=True,
        directories_only=False,
        filter_text=None,
        sort="path",
        sort_dir="asc",
        page=1,
        page_size=100,
    )
    assert orphan.id in {item.id for item in root_rows}


def test_validate_entry_id_rejects_bad_values() -> None:
    assert validate_entry_id("0") == 0
    assert validate_entry_id(42) == 42
    for bad in (-1, "-3", "abc", 1.5, True, None, "1e3", ""):
        with pytest.raises(InvalidEntryIdError):
            validate_entry_id(bad)
    with pytest.raises(InvalidEntryIdError):
        validate_entry_id(0, allow_root=False)


def test_cross_evidence_entry_is_not_found(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    users = store.get_entry_by_path(EVIDENCE, SCAN, "Users")
    with pytest.raises(EntryNotFoundError):
        store.get_entry("ev_other", SCAN, users.id)


def test_linked_rows_have_expected_root_count(tmp_path: Path) -> None:
    store = build_store(tmp_path, BASE_ROWS)
    connection = sqlite3.connect(store.path)
    try:
        assert connection.execute(
            "SELECT COUNT(*) FROM filesystem_entries WHERE parent_id IS NULL"
        ).fetchone()[0] == 3
        assert connection.execute(
            "SELECT COUNT(*) FROM filesystem_entries WHERE has_children = 1"
        ).fetchone()[0] >= 3
    finally:
        connection.close()
    node = TreeNode(1, None, "x", "x", FILE, 1, 1, True, False, False)
    assert node.to_dict()["status"] == "allocated"


def test_child_page_of_finds_reveal_page(tmp_path: Path) -> None:
    rows = [row("Big", DIRECTORY)]
    for index in range(30):
        rows.append(row(f"Big/f{index:02d}.txt", FILE, inode=500 + index))
    store = build_store(tmp_path, rows)
    big = store.get_entry_by_path(EVIDENCE, SCAN, "Big")
    target = store.get_entry_by_path(EVIDENCE, SCAN, "Big/f25.txt")
    page = store.child_page_of(EVIDENCE, SCAN, big.id, target.id, 10)
    assert page == 3
    found, _ = children(store, big.id, page=3, page_size=10)
    assert target.id in {item.id for item in found}


def test_index_not_queryable_raises() -> None:
    with pytest.raises(IndexNotReadyError):
        raise IndexNotReadyError("index not ready")
