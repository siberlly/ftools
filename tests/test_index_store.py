from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from dfir_browser.core.index_models import IndexStoreError, utc_now_iso
from dfir_browser.core.index_store import IndexStore, escape_like

EV = "ev_0123456789ab"
SCAN = "scan1"
IDENTITY = {
    "source_sha256": "a" * 64,
    "raw_exposure_path": "/home/ubuntu/mnt/ewf/ewf1",
    "filesystem": "NTFS",
    "offset_sectors": 0,
    "fls_version": "The Sleuth Kit ver 4.12.1",
    "index_schema_version": 1,
    "scanner_version": "fls-r-p-l-v1",
}


def make_store(tmp_path: Path) -> IndexStore:
    store = IndexStore(tmp_path / "var" / "index" / "filesystem.db")
    store.ensure_schema()
    return store


def begin(store: IndexStore, scan: str = SCAN) -> None:
    store.begin_scan(EV, scan, IDENTITY, utc_now_iso())


def finish(store: IndexStore, scan: str = SCAN, status: str = "ready") -> None:
    store.finish_scan(
        EV,
        scan,
        status=status,
        entries_seen=0,
        entries_indexed=0,
        parse_errors=0,
        deleted_files=0,
        deleted_directories=0,
        allocated_files=0,
        allocated_directories=0,
        error_code=None,
        error_message=None,
    )


def row(
    full_path: str,
    *,
    inode: int = 1,
    deleted: bool = False,
    entry_type: str = "file",
    size: int = 1,
    extension: str | None = None,
    modified: str = "2020-01-02T03:04:05Z",
    scan: str = SCAN,
) -> tuple:
    parent, _, base = full_path.rpartition("/")
    if extension is None:
        base_for_extension = base.split(":", 1)[0]
        extension = (
            base_for_extension.rsplit(".", 1)[1].lower()
            if "." in base_for_extension
            else ""
        )
    return (
        EV,
        scan,
        full_path,
        parent,
        base,
        extension,
        inode,
        1,
        128,
        "-/r" if deleted else "r/r",
        entry_type,
        0 if deleted else 1,
        1 if deleted else 0,
        size,
        None,
        modified,
        None,
        None,
        "a" * 64,
        None,
    )


def search(store: IndexStore, query: str, *, exact: bool = False, **kwargs):
    return store.search(
        EV,
        SCAN,
        query=query,
        exact=exact,
        extension=kwargs.get("extension"),
        deleted_only=kwargs.get("deleted_only", False),
        allocated_only=kwargs.get("allocated_only", False),
        entry_type=kwargs.get("entry_type"),
        sort=kwargs.get("sort", "path"),
        sort_dir=kwargs.get("sort_dir", "asc"),
        page=kwargs.get("page", 1),
        page_size=kwargs.get("page_size", 100),
    )


def test_insert_and_query_directory(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    store.insert_entries(
        [
            row("Users", inode=1746, entry_type="directory"),
            row("Users/IEUser", inode=83437, entry_type="directory"),
        ]
    )
    finish(store)

    root, total = store.query_directory(EV, SCAN, "", 100, 0)
    assert total == 1
    assert root[0].basename == "Users"
    assert root[0].inode == 1746

    users, total = store.query_directory(EV, SCAN, "Users", 100, 0)
    assert total == 1
    assert users[0].basename == "IEUser"
    assert users[0].full_path == "Users/IEUser"


def test_pagination(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    store.insert_entries(
        [row(f"dir/file{index}.txt", inode=index + 1) for index in range(250)]
    )
    finish(store)
    first, total = store.query_directory(EV, SCAN, "dir", 100, 0)
    second, _ = store.query_directory(EV, SCAN, "dir", 100, 100)
    third, _ = store.query_directory(EV, SCAN, "dir", 100, 200)
    assert total == 250
    assert len(first) == 100
    assert len(second) == 100
    assert len(third) == 50


def test_deleted_files_and_directories(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    store.insert_entries(
        [
            row("Users/Public/Downloads/SysInternals.exe", deleted=True),
            row("Config.Msi", inode=2, deleted=True, entry_type="directory"),
            row("Users/keep.txt", inode=3),
        ]
    )
    finish(store)

    files, total = store.query_deleted(
        EV,
        SCAN,
        include_directories=False,
        extension=None,
        search=None,
        sort="path",
        sort_dir="asc",
        page=1,
        page_size=100,
    )
    assert total == 1
    assert files[0].basename == "SysInternals.exe"
    assert files[0].deleted is True
    assert files[0].entry_type == "file"

    all_deleted, total = store.query_deleted(
        EV,
        SCAN,
        include_directories=True,
        extension=None,
        search=None,
        sort="path",
        sort_dir="asc",
        page=1,
        page_size=100,
    )
    assert total == 2
    assert {entry.basename for entry in all_deleted} == {
        "SysInternals.exe",
        "Config.Msi",
    }


def test_search_is_parameterized_and_escapes_wildcards(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    store.insert_entries(
        [
            row("Users/percent%file.txt"),
            row("Users/percentXfile.txt"),
            row("Users/under_score.txt"),
            row("Users/underXscore.txt"),
            row("Users/normal.txt"),
        ]
    )
    finish(store)

    percent_rows, total = search(store, "%")
    assert total == 1
    assert percent_rows[0].basename == "percent%file.txt"

    underscore_rows, total = search(store, "_")
    assert total == 1
    assert underscore_rows[0].basename == "under_score.txt"

    injection_rows, total = search(store, "' OR 1=1 --")
    assert total == 0
    assert injection_rows == []

    exact_rows, total = search(store, "normal.txt", exact=True)
    assert total == 1
    assert exact_rows[0].basename == "normal.txt"


def test_duplicate_inode_at_multiple_paths(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    store.insert_entries(
        [
            row("Users/Alice/link.txt", inode=777),
            row("Users/Bob/link.txt", inode=777),
        ]
    )
    finish(store)
    rows, total = search(store, "link.txt", exact=True)
    assert total == 2
    assert {entry.full_path for entry in rows} == {
        "Users/Alice/link.txt",
        "Users/Bob/link.txt",
    }
    assert {entry.inode for entry in rows} == {777}


def test_transaction_rollback(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    good = row("good.txt")
    bad = list(row("bad.txt"))
    bad[2] = None
    with pytest.raises(IndexStoreError):
        store.insert_entries([good, tuple(bad)])
    rows, total = store.query_directory(EV, SCAN, "", 100, 0)
    assert total == 0
    assert rows == []


def test_mark_stale_and_interrupted(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store)
    finish(store)
    store.mark_stale(EV)
    index_row = store.get_index_row(EV)
    assert index_row["stale"] == 1

    begin(store, "scan2")
    store.mark_interrupted(EV, "scan2", "test interruption")
    index_row = store.get_index_row(EV)
    assert index_row["status"] == "interrupted"
    assert index_row["error_code"] == "interrupted"


def test_finish_replaces_old_generation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    begin(store, "scan1")
    store.insert_entries([row("old.txt", scan="scan1")])
    finish(store, "scan1")

    begin(store, "scan2")
    store.insert_entries([row("new.txt", scan="scan2")])
    finish(store, "scan2")

    old_rows, old_total = store.query_all_under(
        EV, "scan1", "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    new_rows, new_total = store.query_all_under(
        EV, "scan2", "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    assert old_total == 0
    assert old_rows == []
    assert new_total == 1
    assert new_rows[0].basename == "new.txt"


def test_database_permissions(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_newer_schema_rejected(tmp_path: Path) -> None:
    path = tmp_path / "var" / "index" / "filesystem.db"
    store = IndexStore(path)
    store.ensure_schema()
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA user_version = 99")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(IndexStoreError) as excinfo:
        store.ensure_schema()
    assert excinfo.value.code == "index_schema_newer"


def test_escape_like() -> None:
    assert escape_like("a%b_c\\d") == "a\\%b\\_c\\\\d"
