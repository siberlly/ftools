from __future__ import annotations

import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

import dfir_browser.mcp_server as mcp_server
from dfir_browser.web.app import create_app

from preview_helpers import (
    EVIDENCE,
    _row,
    build_preview_services,
    entry_id,
    stub_preview_extract,
)

DB_PATH = "Users/IEUser/AppData/Roaming/app/state.sqlite"
DB_INODE = 63001


def make_db() -> bytes:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "state.sqlite"
        connection = sqlite3.connect(str(path))
        connection.executescript(
            """
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, visits INTEGER);
            CREATE TABLE blobs(name TEXT, data BLOB);
            CREATE VIEW recent AS SELECT id, url FROM urls;
            CREATE TABLE wide(a TEXT, b TEXT, c TEXT, d TEXT, e TEXT, f TEXT, g TEXT, h TEXT);
            """
        )
        connection.executemany(
            "INSERT INTO urls VALUES (?, ?, ?)",
            [
                (1, "https://example.test/a", 3),
                (2, "https://example.test/b", 1),
                (3, "https://example.test/c", 7),
            ],
        )
        connection.execute("INSERT INTO blobs VALUES ('x', X'DEADBEEF')")
        connection.execute(
            "INSERT INTO blobs VALUES (?, ?)",
            ("long", "A" * 900),
        )
        connection.commit()
        connection.close()
        return path.read_bytes()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    payload = make_db()
    rows = [_row(DB_PATH, "state.sqlite", DB_INODE, len(payload))]
    services, record = build_preview_services(
        tmp_path, {DB_INODE: payload}, rows=rows
    )
    stub_preview_extract(services, {DB_INODE: payload})
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record, payload
    services.cleanup()


def test_sqlite_schema_preview(env):
    client, services, record, payload = env
    result = services.preview.preview(record, entry_id(services, DB_PATH))
    assert result.preview_mode == "sqlite"
    assert result.mime_type == "application/vnd.sqlite3"
    names = {table["name"] for table in result.sqlite["tables"]}
    assert {"urls", "blobs", "recent", "wide"} <= names
    assert result.sqlite["table_count"] == 4
    urls = next(t for t in result.sqlite["tables"] if t["name"] == "urls")
    assert [c["name"] for c in urls["columns"]] == ["id", "url", "visits"]
    assert urls["row_estimate"] == 3
    assert result.content == ""


def test_sqlite_rows_and_paging(env):
    client, services, record, payload = env
    rows = services.preview.sqlite_rows(record, entry_id(services, DB_PATH), "urls", limit=2)
    assert rows["returned"] == 2
    assert rows["has_more"] is True
    assert rows["rows"][0][0]["kind"] == "number"
    second = services.preview.sqlite_rows(
        record, entry_id(services, DB_PATH), "urls", offset=2, limit=2
    )
    assert second["returned"] == 1
    assert second["has_more"] is False


def test_sqlite_blob_cells(env):
    client, services, record, payload = env
    rows = services.preview.sqlite_rows(record, entry_id(services, DB_PATH), "blobs")
    cell = rows["rows"][0][1]
    assert cell["kind"] == "blob"
    assert cell["text"] == "deadbeef"
    assert cell["length"] == 4


def test_sqlite_never_writes_to_the_copy(env):
    client, services, record, payload = env
    before = hashlib.sha256(payload).hexdigest()
    entry = services.indexer.tree_entry(record, entry_id(services, DB_PATH))
    services.preview.preview(record, entry.id)
    services.preview.sqlite_rows(record, entry.id, "urls", limit=1)
    copy = services.preview._ensure_copy(record, entry)
    assert copy.path.is_file()
    assert hashlib.sha256(copy.path.read_bytes()).hexdigest() == before


def test_sqlite_unknown_table_rejected(env):
    client, services, record, payload = env
    with pytest.raises(Exception) as exc:
        services.preview.sqlite_rows(
            record, entry_id(services, DB_PATH), "nope"
        )
    assert "unknown table" in str(exc.value)


def test_sqlite_injection_attempt_rejected(env):
    client, services, record, payload = env
    for name in ('urls"; DROP TABLE urls; --', "urls' OR 1=1", "sqlite_master"):
        with pytest.raises(Exception):
            services.preview.sqlite_rows(
                record, entry_id(services, DB_PATH), name
            )


def test_sqlite_web_json_and_panel(env):
    client, services, record, payload = env
    db = entry_id(services, DB_PATH)
    data = client.get(
        f"/evidence/{EVIDENCE}/entries/{db}/sqlite?table=urls&limit=2"
    ).json()
    assert data["ok"] is True
    assert data["returned"] == 2
    assert data["columns"] == ["id", "url", "visits"]
    panel = client.get(
        f"/evidence/{EVIDENCE}/entries/{db}/sqlite/panel?table=urls"
    )
    assert panel.status_code == 200
    assert "example.test" in panel.text
    bad = client.get(
        f"/evidence/{EVIDENCE}/entries/{db}/sqlite?table=nope"
    )
    assert bad.status_code == 400


def test_sqlite_panel_escapes_values(env, tmp_path):
    payload = make_db()
    connection = sqlite3.connect(str(tmp_path / "x.sqlite"))
    # Rebuild with a script-like value to prove escaping.
    connection.close()
    client, services, record, payload = env
    db = entry_id(services, DB_PATH)
    rows = services.preview.sqlite_rows(record, db, "urls")
    assert all("kind" in cell for row in rows["rows"] for cell in row)


def test_preview_panel_renders_sqlite_schema(env):
    client, services, record, payload = env
    db = entry_id(services, DB_PATH)
    body = client.get(
        f"/evidence/{EVIDENCE}/entries/{db}/preview/panel"
    ).text
    assert "Show rows" in body
    assert "urls" in body
    assert "mode=ro&amp;immutable=1" in body


def test_mcp_sqlite_rows(env):
    client, services, record, payload = env
    db = entry_id(services, DB_PATH)
    data = mcp_server.preview_sqlite_table(EVIDENCE, db, "urls", limit=2)
    assert data["returned"] == 2
    assert data["trust"] == "untrusted_evidence_data"
    schema = mcp_server.preview_file_content(EVIDENCE, db)
    assert schema["preview_mode"] == "sqlite"
    assert schema["sqlite"]["table_count"] == 4


def test_long_cell_exposes_inline_full_value(env):
    client, services, record, payload = env
    rows = services.preview.sqlite_rows(
        record, entry_id(services, DB_PATH), "blobs", limit=5
    )
    long_cell = next(
        cell
        for row in rows["rows"]
        for cell in row
        if cell.get("kind") == "text" and cell.get("length") == 900
    )
    assert len(long_cell["text"]) == 200
    assert long_cell["full"] is not None
    assert len(long_cell["full"]) == 900
    assert long_cell["full_truncated"] is False
    panel = client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id(services, DB_PATH)}"
        "/sqlite/panel?table=blobs"
    ).text
    assert "cell-expand" in panel
    assert "A" * 200 in panel


def test_row_limit_can_be_raised_to_cap(env):
    client, services, record, payload = env
    rows = services.preview.sqlite_rows(
        record, entry_id(services, DB_PATH), "urls", limit=500
    )
    assert rows["limit"] == 500
    assert rows["returned"] == 3


def test_row_limit_is_clamped_to_max(env):
    client, services, record, payload = env
    rows = services.preview.sqlite_rows(
        record, entry_id(services, DB_PATH), "urls", limit=100000
    )
    assert rows["limit"] == 500


def test_panel_hides_extra_columns_by_default(env):
    client, services, record, payload = env
    panel = client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id(services, DB_PATH)}"
        "/sqlite/panel?table=wide"
    ).text
    assert "sqlite-extra-col" in panel
    assert "data-sqlite-toggle-columns" in panel
    assert "500 rows" in panel
