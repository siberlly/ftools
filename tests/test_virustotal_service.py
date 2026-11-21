from __future__ import annotations

import json
import threading
import time

import httpx
import pytest

from dfir_browser.core.audit import AuditLogger
from dfir_browser.core.virustotal import (
    VirusTotalClient,
    VirusTotalNotConfigured,
    VirusTotalRateLimited,
    VirusTotalService,
    VirusTotalStore,
)

from vt_helpers import HASH, KEY, Upstream, build, report_body
from triage_helpers import EVIDENCE


def test_missing_key_is_rejected(tmp_path) -> None:
    services, record, entry_id = build(tmp_path, Upstream())
    services.virustotal.remove_key()
    with pytest.raises(VirusTotalNotConfigured):
        services.virustotal.lookup_entry(record, entry_id)
    services.cleanup()


def test_found_and_cache_hit(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    first = services.virustotal.lookup_entry(record, entry_id)
    assert first["status"] == "found"
    assert first["cached"] is False
    assert upstream.calls == 1
    assert upstream.urls[0].endswith("/api/v3/files/" + HASH)
    second = services.virustotal.lookup_entry(record, entry_id)
    assert second["cached"] is True
    assert second["fetched_at"] == first["fetched_at"]
    assert upstream.calls == 1
    assert second["report"]["last_analysis_stats"]["undetected"] == 61
    services.cleanup()


def test_force_refresh_makes_one_new_request(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    services.virustotal.lookup_entry(record, entry_id)
    refreshed = services.virustotal.lookup_entry(
        record, entry_id, force_refresh=True
    )
    assert refreshed["cached"] is False
    assert upstream.calls == 2
    services.cleanup()


def test_not_found_uses_short_ttl(tmp_path) -> None:
    upstream = Upstream(status=404, body={})
    services, record, entry_id = build(
        tmp_path, upstream, virustotal_notfound_ttl=120
    )
    result = services.virustotal.lookup_entry(record, entry_id)
    assert result["status"] == "not_found"
    assert result["report"] is None
    cached = services.virustotal_store.get(HASH)
    assert cached is not None
    assert cached["expires_at"] - int(time.time()) <= 122
    again = services.virustotal.lookup_entry(record, entry_id)
    assert again["cached"] is True
    assert upstream.calls == 1
    services.cleanup()


def test_auth_failure_is_not_cached(tmp_path) -> None:
    upstream = Upstream(status=401, body={})
    services, record, entry_id = build(tmp_path, upstream)
    for _ in range(2):
        with pytest.raises(Exception) as excinfo:
            services.virustotal.lookup_entry(record, entry_id)
        assert getattr(excinfo.value, "code", "") == "virustotal_invalid_key"
    assert upstream.calls == 2
    assert services.virustotal_store.get(HASH) is None
    services.cleanup()


def test_local_rate_limit_four_per_minute(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    for _ in range(4):
        services.virustotal.lookup_entry(record, entry_id, force_refresh=True)
    with pytest.raises(VirusTotalRateLimited) as excinfo:
        services.virustotal.lookup_entry(record, entry_id, force_refresh=True)
    assert excinfo.value.retry_after >= 1
    assert upstream.calls == 4
    services.cleanup()


def test_concurrent_same_hash_is_coalesced(tmp_path) -> None:
    gate = threading.Event()
    upstream = Upstream(delay=lambda: gate.wait(5))
    services, record, entry_id = build(tmp_path, upstream)
    results = []
    errors = []

    def run():
        try:
            results.append(services.virustotal.lookup_entry(record, entry_id))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    first = threading.Thread(target=run)
    first.start()
    time.sleep(0.2)
    second = threading.Thread(target=run)
    second.start()
    time.sleep(0.3)
    gate.set()
    first.join(10)
    second.join(10)
    assert not errors
    assert upstream.calls == 1
    assert len(results) == 2
    assert {item["status"] for item in results} == {"found"}
    services.cleanup()


def test_cache_survives_service_restart(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    services.virustotal.lookup_entry(record, entry_id)
    failing = Upstream(status=503)
    restarted = VirusTotalService(
        settings=services.settings,
        secret_store=services.virustotal.secrets,
        store=VirusTotalStore(services.settings.virustotal_database()),
        evidence=services.evidence,
        indexer=services.indexer,
        triage=services.triage,
        audit=services.audit,
        client=VirusTotalClient(
            transport=httpx.MockTransport(failing), timeout=5.0
        ),
    )
    result = restarted.lookup_hash(HASH)
    assert result["cached"] is True
    assert failing.calls == 0
    services.cleanup()


def test_key_never_written_to_cache_or_audit(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    services.virustotal.lookup_entry(record, entry_id)
    db_bytes = services.settings.virustotal_database().read_bytes()
    assert KEY.encode() not in db_bytes
    audit_bytes = services.settings.audit_file().read_bytes()
    assert KEY.encode() not in audit_bytes
    assert HASH.encode() in audit_bytes
    services.cleanup()


def test_directory_entry_rejected(tmp_path) -> None:
    services, record, _entry_id = build(tmp_path, Upstream())
    directory_id = services.indexer.resolve_entry_path(record, "Files").id
    with pytest.raises(Exception) as excinfo:
        services.virustotal.lookup_entry(record, directory_id)
    assert getattr(excinfo.value, "code", "") == "virustotal_directory_rejected"
    services.cleanup()


def test_missing_hash_is_computed_server_side(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    # No triage job exists yet: the service extracts once and hashes.
    result = services.virustotal.lookup_entry(record, entry_id)
    assert result["status"] == "found"
    assert result["hash"] == HASH
    job = services.triage_store.latest_for_entry(EVIDENCE, entry_id)
    assert job is None or job.sha256 in (None, HASH)
    services.cleanup()


def test_audit_records_lookup_metadata(tmp_path) -> None:
    upstream = Upstream()
    services, record, entry_id = build(tmp_path, upstream)
    services.virustotal.lookup_entry(record, entry_id)
    services.virustotal.lookup_entry(record, entry_id)
    lines = [
        json_line
        for json_line in services.settings.audit_file().read_text().splitlines()
        if '"virustotal_lookup"' in json_line
    ]
    assert lines
    events = [json.loads(line) for line in lines]
    cached_flags = {event["details"]["cache"] for event in events}
    assert cached_flags == {False, True}
    for event in events:
        assert event["details"]["hash"] == HASH
        assert event["details"]["hash_type"] == "sha256"
        assert event["details"]["http_status"] in (200, 404)
        assert KEY not in json.dumps(event)
    services.cleanup()


def test_upstream_429_sets_cooldown_without_retry(tmp_path) -> None:
    upstream = Upstream(status=429, body={}, headers={"Retry-After": "60"})
    services, record, entry_id = build(tmp_path, upstream)
    with pytest.raises(VirusTotalRateLimited):
        services.virustotal.lookup_entry(record, entry_id)
    assert upstream.calls == 1
    with pytest.raises(VirusTotalRateLimited) as excinfo:
        services.virustotal.lookup_entry(record, entry_id, force_refresh=True)
    assert excinfo.value.retry_after >= 1
    assert upstream.calls == 1
    assert services.virustotal_store.get(HASH) is None
    services.cleanup()
