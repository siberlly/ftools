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
def test_real_amcache_registry(tmp_path: Path) -> None:
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
        triage_job_timeout=60.0,
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
        hives = services.registry_browser.list_hives(record, page_size=100)
        amcache = [h for h in hives.items if h.hive_type == "amcache"]
        assert amcache, [h.name for h in hives.items]
        hive_candidate = amcache[0]
        assert hive_candidate.inode == 83201
        assert hive_candidate.name == "Amcache.hve"

        started = services.registry_browser.start_index(
            record, hive_candidate.entry_id, rebuild=True
        )
        hive_id = started["hive"]["hive_id"]
        hive = wait_until(
            lambda: (
                services.registry_browser.status(hive_id)
                if services.registry_browser.status(hive_id).state
                not in {"queued", "running"}
                else None
            )
        )
        assert hive.state == "ready", hive.error_message
        assert hive.key_count > 100
        assert hive.value_count > 1000
        assert hive.amcache_count > 0
        assert "Amcache.hve.LOG1" in hive.transaction_logs
        assert any("not replayed" in warning for warning in hive.warnings)

        subkeys = services.registry_browser.list_subkeys(hive_id, page_size=50)
        assert subkeys.total == 1
        assert subkeys.items[0].name == "Root"
        search = services.registry_browser.search(
            hive_id, "SysInternals", page_size=20
        )
        assert search.total > 0

        records = services.registry_browser.amcache_search(
            hive_id, "SysInternals.exe", exact=True, page_size=10
        )
        assert records.total == 1
        entry_record = records.items[0]
        assert entry_record["executable_name"] == "SysInternals.exe"
        assert entry_record["executable_path"].endswith("sysinternals.exe")
        assert entry_record["file_id_raw"] == "0000fa1002b02fc5551e075ec44bb4ff9cc13d563dcf"
        assert entry_record["hash_algorithm"] == "sha1"
        assert entry_record["hash_normalized"] == "fa1002b02fc5551e075ec44bb4ff9cc13d563dcf"
        assert entry_record["normalization_method"] == "strip-4-hex-prefix-sha1"
        assert entry_record["hash_valid"] is True
        assert entry_record["size"] == 57344
        assert entry_record["publisher"].startswith("sysinternals")
        assert entry_record["source_key_path"].endswith(
            "sysinternals.exe|1a80e611058c98e5"
        )
        assert entry_record["source_value_names"]["file_id"] == "FileId"

        taskmgr = services.registry_browser.amcache_search(
            hive_id, "taskmgr.exe", exact=True, page_size=10
        )
        assert taskmgr.total == 1
        assert (
            taskmgr.items[0]["hash_normalized"]
            == "7a1df2950ac856b9c7eddbfdc2728b217665c31e"
        )

        target = services.indexer.resolve_entry_path(
            record, "Users/Public/Downloads/SysInternals.exe"
        )
        comparison = services.registry_browser.compare_triage(
            record, hive_id, entry_record["record_id"], target.id
        )
        assert comparison.status in {"mismatch", "match", "unavailable"}
        assert comparison.algorithm == "sha1"
        assert comparison.amcache_hash == entry_record["hash_normalized"]

        # A valid cached working copy must not be re-extracted.
        exports = services.policy.case_exports_dir("case01")
        before = len(
            [
                path
                for path in exports.iterdir()
                if path.is_file() and not path.name.endswith(".provenance.json")
            ]
        )
        cached = services.registry_browser.start_index(
            record, hive_candidate.entry_id
        )
        assert cached["started"] is False and cached["cached"] is True
        after = len(
            [
                path
                for path in exports.iterdir()
                if path.is_file() and not path.name.endswith(".provenance.json")
            ]
        )
        assert after == before
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
