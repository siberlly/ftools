from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from dfir_browser.core.config import EwfMapping, Settings
from dfir_browser.core.services import build_services

EVIDENCE = Path(
    os.environ.get(
        "DFIR_TEST_EVIDENCE",
        "/home/ubuntu/test/temp_extract_dir/SysInternals.E01",
    )
)
EWF1 = Path(os.environ.get("DFIR_TEST_EWF1", "/home/ubuntu/mnt/ewf/ewf1"))

pytestmark = pytest.mark.integration

SKIP_REASON = None
if os.environ.get("DFIR_SKIP_EVIDENCE_TESTS") == "1":
    SKIP_REASON = "DFIR_SKIP_EVIDENCE_TESTS=1"
elif not EVIDENCE.is_file():
    SKIP_REASON = f"evidence not found: {EVIDENCE}"
elif not EWF1.is_file():
    SKIP_REASON = f"EWF exposure not found: {EWF1}"

PRIORITY_LOGS = (
    "Security.evtx",
    "System.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_until(predicate, timeout=300.0, interval=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value is not None:
            return value
        time.sleep(interval)
    raise AssertionError("timed out waiting for condition")


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_evtx_explorer(tmp_path: Path) -> None:
    before_stat = EVIDENCE.stat()
    before_hash = sha256_file(EVIDENCE)

    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(Path("/home/ubuntu/test"), Path("/home/ubuntu/evidence")),
        ewf_mappings={
            str(EVIDENCE.resolve()): EwfMapping(
                exposure=str(EWF1.resolve()),
                source_sha256=before_hash,
                media_size=14720958464,
            )
        },
        ewf_automount=False,
        auto_index=False,
        command_timeout=60.0,
        index_timeout=180.0,
        evtx_index_timeout=300.0,
    )
    services = build_services(settings)
    record = services.evidence.register(str(EVIDENCE))
    services.indexer.start_scan(record.evidence_id)
    status = wait_until(
        lambda: (
            services.indexer.status_for_record(record)
            if services.indexer.status_for_record(record).status
            not in {"running", "pending"}
            else None
        )
    )
    assert status.status == "ready", status.warning

    try:
        candidates = services.evtx.list_logs(record, page_size=500)
        assert candidates.total > 10
        by_name = {item.name: item for item in candidates.items}
        present = [name for name in PRIORITY_LOGS if name in by_name]
        assert "Security.evtx" in present
        assert "System.evtx" in present
        assert "Microsoft-Windows-PowerShell%4Operational.evtx" in present

        security = by_name["Security.evtx"]
        assert security.channel == "Security"
        assert security.inode == 80826
        started = services.evtx.start_index(
            record, security.entry_id, rebuild=True
        )
        log_id = started["log"]["log_id"]
        log = wait_until(
            lambda: (
                services.evtx.status(log_id)
                if services.evtx.status(log_id).status
                not in {"queued", "running"}
                else None
            )
        )
        assert log.status == "ready", log.error_message
        assert log.records_indexed > 1000
        assert log.parse_errors == 0
        assert log.first_event_time and log.last_event_time

        events = services.evtx.query(
            record, log_ids=[log_id], event_ids=[4688], page_size=5
        )
        assert events.total > 0
        assert events.events[0].event_data.get("NewProcessName")
        event = events.events[0]
        detail = services.evtx.get_event(
            log_id, event.record_id, include_raw_xml=True
        )
        assert detail["raw_xml"] and "<Event" in detail["raw_xml"]
        assert detail["message_status"] == "message_unavailable"

        context = services.evtx.context(log_id, event.record_id, 2, 2)
        assert len(context["events"]) == 5

        summary = services.evtx.summary(record, log_ids=[log_id], top_n=5)
        assert summary["total_events"] == log.records_indexed
        assert summary["by_channel"].get("Security")
        assert summary["time_from"] and summary["time_to"]

        # Priority preset must be a structured filter, not a verdict.
        preset = services.evtx.query(
            record, log_ids=[log_id], preset="authentication", page_size=3
        )
        assert preset.total >= 0

        # Cached run must not extract again.
        exports = services.policy.case_exports_dir("case01")
        before_copies = len(
            [
                path
                for path in exports.iterdir()
                if path.is_file() and not path.name.endswith(".provenance.json")
            ]
        )
        cached = services.evtx.start_index(record, security.entry_id)
        assert cached["started"] is False and cached["cached"] is True
        after_copies = len(
            [
                path
                for path in exports.iterdir()
                if path.is_file() and not path.name.endswith(".provenance.json")
            ]
        )
        assert after_copies == before_copies
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
