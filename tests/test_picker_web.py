from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from dfir_browser.core.config import Settings
from dfir_browser.core.services import build_services
from dfir_browser.web.app import create_app


@pytest.fixture()
def env(tmp_path):
    allowed = tmp_path / "evidence"
    allowed.mkdir()
    (allowed / "case").mkdir()
    (allowed / "case" / "disk.E01").write_bytes(b"x")
    (allowed / "top.E01").write_bytes(b"y")
    (allowed / "notes.txt").write_text("hi")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.E01").write_bytes(b"z")
    (allowed / "escape").symlink_to(outside)

    settings = dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=tmp_path / "index" / "filesystem.db",
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        allowed_roots=(allowed,),
        auto_index=False,
    )
    services = build_services(settings)
    app = create_app(settings, services)
    with TestClient(app) as client:
        yield client, allowed, outside
    services.cleanup()


def test_index_has_browse_button_and_dialog(env):
    client, allowed, _ = env
    page = client.get("/")
    assert page.status_code == 200
    assert "Browse…" in page.text
    assert 'id="evidence-picker"' in page.text
    assert 'aria-haspopup="dialog"' in page.text


def test_picker_lists_roots(env):
    client, allowed, _ = env
    response = client.get("/picker")
    assert response.status_code == 200
    assert "Allowed roots" in response.text
    assert "evidence" in response.text


def test_picker_lists_folder(env):
    client, allowed, _ = env
    response = client.get("/picker", params={"path": str(allowed)})
    assert response.status_code == 200
    assert "case" in response.text
    assert "top.E01" in response.text
    assert "notes.txt" not in response.text
    assert 'data-picker-file="' in response.text


def test_picker_navigates_into_subfolder(env):
    client, allowed, _ = env
    response = client.get("/picker", params={"path": str(allowed / "case")})
    assert response.status_code == 200
    assert "disk.E01" in response.text
    assert "Parent folder" in response.text


def test_picker_rejects_outside_root(env):
    client, allowed, outside = env
    response = client.get("/picker", params={"path": str(outside)})
    assert response.status_code == 200
    assert "outside the allowed roots" in response.text
    assert "secret.E01" not in response.text


def test_picker_skips_symlink_escape(env):
    client, allowed, outside = env
    response = client.get("/picker", params={"path": str(allowed)})
    # The symlink may be mentioned in a warning, but it is never navigable.
    assert f'data-picker-go="{allowed / "escape"}"' not in response.text
    assert "secret.E01" not in response.text


def test_picker_json(env):
    client, allowed, outside = env
    data = client.get("/picker/api", params={"path": str(allowed)}).json()
    assert data["ok"] is True
    names = {entry["name"] for entry in data["entries"]}
    assert {"case", "top.E01"} <= names
    assert "notes.txt" not in names
    bad = client.get("/picker/api", params={"path": str(outside)})
    assert bad.status_code == 400
    assert bad.json()["ok"] is False


def test_picker_escapes_names(env, tmp_path):
    client, allowed, _ = env
    nasty = allowed / "<script>alert(1)<script>.E01"
    nasty.write_bytes(b"x")
    body = client.get("/picker", params={"path": str(allowed)}).text
    assert "<script>alert(1)" not in body
    assert "&lt;script&gt;" in body
