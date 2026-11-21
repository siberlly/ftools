from __future__ import annotations

import re
import stat

import pytest
from fastapi.testclient import TestClient

from dfir_browser.web.app import create_app

from triage_helpers import build_services, sample_payload, stub_extraction
from vt_helpers import KEY, Upstream, report_body

EVIDENCE = "ev_0123456789ab"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture()
def env(tmp_path):
    upstream = Upstream()
    services, record, entry_id = build_services(
        tmp_path, sample_payload(), extra_payload=b"other payload"
    )
    stub_extraction(
        services,
        sample_payload(),
        by_inode={901: b"other payload"},
    )
    services.virustotal.client = __import__(
        "dfir_browser.core.virustotal", fromlist=["VirusTotalClient"]
    ).VirusTotalClient(
        transport=__import__("httpx").MockTransport(upstream), timeout=5.0
    )
    services.virustotal.save_key(KEY)
    other_id = services.indexer.resolve_entry_path(record, "Files/other.bin").id
    app = create_app(services.settings, services)
    with TestClient(app) as client:
        yield client, services, record, entry_id, other_id, upstream
    services.cleanup()


def csrf(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = CSRF_RE.search(response.text)
    assert match, response.text
    return match.group(1)


def test_settings_page_no_secret(env) -> None:
    client, services, *_rest = env
    services.virustotal.remove_key()
    page = client.get("/settings/integrations")
    assert page.status_code == 200
    assert "Not configured" in page.text
    assert "VT_API_KEY" in page.text
    assert KEY not in page.text
    assert 'type="password"' in page.text
    assert 'autocomplete="new-password"' in page.text


def test_save_and_mask_key(env) -> None:
    client, services, *_rest = env
    services.virustotal.remove_key()
    token = csrf(client, "/settings/integrations")
    response = client.post(
        "/settings/integrations/virustotal",
        data={"api_key": KEY, "csrf_token": token},
    )
    assert response.status_code == 200
    assert "Configured" in response.text
    assert "****" + KEY[-4:] in response.text
    assert KEY not in response.text
    assert services.virustotal.status()["source"] == "ui"
    secret = services.settings.virustotal_secret_directory() / "virustotal.key"
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert stat.S_IMODE(secret.parent.stat().st_mode) == 0o700
    page = client.get("/settings/integrations")
    assert KEY not in page.text


def test_remove_key(env) -> None:
    client, services, *_rest = env
    token = csrf(client, "/settings/integrations")
    response = client.post(
        "/settings/integrations/virustotal/remove",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "Not configured" in response.text
    assert services.virustotal.status()["configured"] is False


def test_environment_precedence_in_ui(env, monkeypatch) -> None:
    client, services, *_rest = env
    monkeypatch.setenv("VT_API_KEY", "e" * 64)
    page = client.get("/settings/integrations")
    assert "Managed by environment" in page.text
    assert KEY not in page.text
    assert "****" + ("e" * 4) in page.text
    # Removing the UI fallback cannot remove the environment key.
    token = csrf(client, "/settings/integrations")
    client.post(
        "/settings/integrations/virustotal/remove",
        data={"csrf_token": token},
    )
    assert services.virustotal.status()["source"] == "environment"


def test_settings_csrf_required(env) -> None:
    client, *_rest = env
    response = client.post(
        "/settings/integrations/virustotal", data={"api_key": KEY}
    )
    assert response.status_code == 403
    assert "CSRF" in response.text


def test_test_lookup_route(env) -> None:
    client, services, *_rest = env
    from vt_helpers import HASH

    token = csrf(client, "/settings/integrations")
    response = client.post(
        "/settings/integrations/virustotal/test",
        data={"hash_value": HASH, "csrf_token": token},
    )
    assert response.status_code == 200
    assert "Report found" in response.text
    assert HASH in response.text
    assert "No engines reported malicious" in response.text


def test_panel_disabled_without_key(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    services.virustotal.remove_key()
    page = client.get(f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal")
    assert page.status_code == 200
    assert "VirusTotal is not configured" in page.text
    assert "disabled" in page.text
    assert upstream.calls == 0


def test_get_panel_does_not_lookup(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    page = client.get(f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal")
    assert page.status_code == 200
    assert upstream.calls == 0
    assert "Only the hash is sent" in page.text
    assert "Look up SHA-256 on VirusTotal" in page.text


def test_lookup_then_cache(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    token = csrf(client, "/settings/integrations")
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "Report found" in response.text
    assert "live" in response.text
    assert upstream.calls == 1
    cached = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    assert cached.status_code == 200
    assert "cached" in cached.text
    assert upstream.calls == 1
    # Force refresh sends exactly one new request.
    refreshed = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal/refresh",
        data={"csrf_token": token},
    )
    assert refreshed.status_code == 200
    assert upstream.calls == 2


def test_lookup_requires_csrf(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal", data={}
    )
    assert response.status_code == 403
    assert upstream.calls == 0


def test_remote_data_is_escaped(env) -> None:
    from vt_helpers import HASH

    client, services, record, entry_id, _other, upstream = env
    upstream.body = report_body(
        meaningful_name='<script>alert("x")</script>',
        type_description="<img src=x onerror=alert(1)>",
        tags=['<script>tag</script>'],
    )
    token = csrf(client, "/settings/integrations")
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "<script>alert" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "<img src=x" not in response.text
    assert HASH in response.text


def test_report_not_carried_to_other_entry(env) -> None:
    client, services, record, entry_id, other_id, upstream = env
    token = csrf(client, "/settings/integrations")
    client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    other = client.get(
        f"/evidence/{EVIDENCE}/entries/{other_id}/virustotal"
    )
    assert other.status_code == 200
    assert "Report found" not in other.text
    assert "cached" not in other.text


def test_invalid_key_error_ui(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    upstream.status = 401
    upstream.body = {}
    token = csrf(client, "/settings/integrations")
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "rejected the API key" in response.text
    assert KEY not in response.text


def test_directory_panel_rejected(env) -> None:
    client, services, record, *_rest = env
    directory_id = services.indexer.resolve_entry_path(record, "Files").id
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{directory_id}/virustotal"
    )
    assert response.status_code == 400
    assert "only applies to files" in response.text


def test_rate_limit_message(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    # Force the local limiter by pre-filling its window.
    now = services.virustotal._clock()
    services.virustotal._calls.extend([now] * 4)
    token = csrf(client, "/settings/integrations")
    response = client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal/refresh",
        data={"csrf_token": token},
    )
    assert response.status_code == 200
    assert "rate limit" in response.text.lower()
    assert upstream.calls == 0


def test_cached_report_survives_reload(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    token = csrf(client, "/settings/integrations")
    client.post(
        f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal",
        data={"csrf_token": token},
    )
    assert upstream.calls == 1
    page = client.get(f"/evidence/{EVIDENCE}/entries/{entry_id}/virustotal")
    assert page.status_code == 200
    assert "Report found" in page.text
    assert "cached" in page.text
    assert upstream.calls == 1


def test_file_panel_has_single_virustotal_card(env) -> None:
    client, services, record, entry_id, _other, upstream = env
    panel = client.get(f"/evidence/{EVIDENCE}/entry/{entry_id}")
    assert panel.status_code == 200
    assert panel.text.count('class="card vt-card"') == 1
    assert upstream.calls == 0
