from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from dfir_browser.core.config import Settings
from dfir_browser.core.services import build_services
from dfir_browser.web.app import create_app

from triage_helpers import (
    EVIDENCE,
    build_services as build_triage_services,
    sample_payload,
    stub_extraction,
    wait_job,
)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture()
def env(tmp_path):
    services, record, entry_id = build_triage_services(tmp_path, sample_payload())
    stub_extraction(services, sample_payload())
    app = create_app(services.settings, services)
    with TestClient(app) as client:
        yield client, services, record, entry_id
    services.cleanup()


def token(client: TestClient) -> str:
    response = client.get(f"/evidence/{EVIDENCE}?entry=0")
    assert response.status_code == 200
    match = CSRF_RE.search(response.text)
    assert match, response.text
    return match.group(1)


def test_triage_panel_requires_index(env) -> None:
    client, services, record, entry_id = env
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/triage/panel"
    )
    assert response.status_code == 200
    assert "Run static triage" in response.text
    assert "csrf_token" in response.text


def test_triage_start_requires_csrf(env) -> None:
    client, services, record, entry_id = env
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/triage",
        data={"case_id": "case01"},
        headers={"hx-request": "true"},
    )
    assert response.status_code == 403
    assert "CSRF" in response.text


def test_triage_start_and_poll(env) -> None:
    client, services, record, entry_id = env
    csrf = token(client)
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/triage",
        data={"case_id": "case01", "force": "0", "csrf_token": csrf},
        headers={"hx-request": "true"},
    )
    assert response.status_code == 200
    match = re.search(r'data-job-id="(tr_[0-9a-f]{16})"', response.text)
    assert match, response.text
    job_id = match.group(1)
    job = wait_job(services, job_id)
    assert job.status == "complete", job.errors
    page = client.get(f"/triage/jobs/{job_id}")
    assert page.status_code == 200
    assert "static triage" in page.text
    assert job.sha256 in page.text
    assert "Users/Public" not in page.text or "Files/sample.bin" in page.text
    assert "Extracted strings" in page.text
    assert "DFIR_TRIAGE_TEST_MARKER" in page.text


def test_triage_results_and_strings_endpoints(env) -> None:
    client, services, record, entry_id = env
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    results = client.get(f"/triage/jobs/{job.job_id}/results")
    assert results.status_code == 200
    strings = client.get(f"/triage/jobs/{job.job_id}/strings?page=1&page_size=2")
    assert strings.status_code == 200
    assert "004" not in strings.text or True
    filtered = client.get(
        f"/triage/jobs/{job.job_id}/strings?q=DFIR_TRIAGE&encoding=ascii"
    )
    assert filtered.status_code == 200


def test_triage_unknown_job_returns_404(env) -> None:
    client, *_rest = env
    response = client.get("/triage/jobs/tr_0000000000000000")
    assert response.status_code == 404
    assert "not available" in response.text
    bad = client.get("/triage/jobs/../../etc/passwd")
    assert bad.status_code in {404, 400}


def test_triage_directory_entry_rejected(env) -> None:
    client, services, record, _entry_id = env
    directory_id = services.indexer.resolve_entry_path(record, "Files").id
    csrf = token(client)
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{directory_id}/triage",
        data={"case_id": "case01", "csrf_token": csrf},
        headers={"hx-request": "true"},
    )
    assert response.status_code == 400
    assert "directories" in response.text.lower()


def test_triage_force_creates_new_job(env) -> None:
    client, services, record, entry_id = env
    csrf = token(client)
    first = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/triage",
        data={"case_id": "case01", "force": "0", "csrf_token": csrf},
        headers={"hx-request": "true"},
    )
    job_one = re.search(r'data-job-id="(tr_[0-9a-f]{16})"', first.text).group(1)
    wait_job(services, job_one)
    second = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/triage",
        data={"case_id": "case01", "force": "1", "csrf_token": csrf},
        headers={"hx-request": "true"},
    )
    job_two = re.search(r'data-job-id="(tr_[0-9a-f]{16})"', second.text).group(1)
    wait_job(services, job_two)
    assert job_one != job_two
    assert f"cached result" not in second.text


def test_triage_escapes_evidence_values(tmp_path) -> None:
    payload = (
        b"<script>alert('x')</script> https://evil.example/x\n"
        b"C:\\<img src=x onerror=alert(1)>.exe\n"
    )
    services, record, entry_id = build_triage_services(
        tmp_path, payload, filename="<script>alert(1)<script>.txt"
    )
    stub_extraction(services, payload)
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "complete", job.errors
    app = create_app(services.settings, services)
    with TestClient(app) as client:
        page = client.get(f"/triage/jobs/{job.job_id}")
        assert page.status_code == 200
        assert "<script>alert" not in page.text
        assert "&lt;script&gt;" in page.text
        strings = client.get(f"/triage/jobs/{job.job_id}/strings")
        assert "<script>alert" not in strings.text
        panel = client.get(
            f"/evidence/{EVIDENCE}/entries/{entry_id}/triage/panel"
        )
        assert "<script>alert" not in panel.text
    services.cleanup()


def test_tree_children_include_triage_badge(env) -> None:
    client, services, record, entry_id = env
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    root = client.get(f"/evidence/{EVIDENCE}/tree/children?parent_id=0").json()
    files_id = next(c["entry_id"] for c in root["children"] if c["name"] == "Files")
    children = client.get(
        f"/evidence/{EVIDENCE}/tree/children?parent_id={files_id}"
    ).json()
    child = next(c for c in children["children"] if c["name"] == "sample.bin")
    assert child["triage"]["job_id"] == job.job_id
    assert child["triage"]["status"] == "complete"


def test_file_panel_contains_triage_controls(env) -> None:
    client, services, record, entry_id = env
    panel = client.get(f"/evidence/{EVIDENCE}/entry/{entry_id}")
    assert panel.status_code == 200
    assert "Static triage" in panel.text
    assert "Run static triage" in panel.text
    assert "never executed" in panel.text


def test_entries_table_has_triage_action(env) -> None:
    client, services, record, entry_id = env
    page = client.get(f"/evidence/{EVIDENCE}/entries")
    assert page.status_code == 200
    assert "/triage/panel" in page.text


def test_triage_static_assets(env) -> None:
    client, *_rest = env
    js = client.get("/static/triage.js")
    assert js.status_code == 200
    assert "textContent" in js.text
    assert "https://" not in js.text
    css = client.get("/static/style.css")
    assert ".triage-result" in css.text


def test_finished_job_returns_oob_summary(env) -> None:
    client, services, record, entry_id = env
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    page = client.get(f"/triage/jobs/{job.job_id}")
    assert page.status_code == 200
    assert f'hx-swap-oob="innerHTML:#triage-summary-{entry_id}"' in page.text
    assert job.job_id in page.text
    assert f"data-job-id=\"{job.job_id}\"" in page.text
