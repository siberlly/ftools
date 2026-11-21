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

HOSTS = "Windows/System32/drivers/etc/hosts"
AMCACHE = "Windows/appcompat/Programs/Amcache.hve"


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
def test_real_preview_hosts_and_hive(tmp_path: Path) -> None:
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
        hosts = services.indexer.resolve_entry_path(record, HOSTS)
        assert hosts.inode == 42564
        preview = services.preview.preview(record, hosts.id)
        assert preview.preview_mode == "text"
        assert preview.detected_type == "text"
        assert preview.total_size == 896
        assert preview.truncated is False
        assert "www.malware430.com" in preview.content
        assert "192.168.15.10" in preview.content
        assert preview.encoding in {"utf-8", "utf-16-le", "latin-1"}

        amcache = services.indexer.resolve_entry_path(record, AMCACHE)
        hive = services.preview.preview(record, amcache.id)
        assert hive.preview_mode == "registry"
        assert hive.detected_type == "windows_registry_hive"
        assert hive.registry["header"]["signature_valid"] is True
        assert hive.registry["header"]["signature"] == "regf"
        assert hive.returned_bytes <= 4096
        assert hive.registry["hive_type"] == "amcache"

        # Selecting a hive must never start registry parsing on its own.
        assert services.registry_store.find_hive_by_entry(
            record.evidence_id, amcache.id
        ) is None

        exports = services.policy.case_exports_dir("case01")
        copies = [p for p in exports.glob("inode_42564_*") if not p.name.endswith(".json")]
        assert len(copies) == 1
        # A second preview reuses the same copy.
        services.preview.preview(record, hosts.id, limit=128)
        copies_after = [
            p for p in exports.glob("inode_42564_*") if not p.name.endswith(".json")
        ]
        assert len(copies_after) == 1

        audit = settings.audit_log_path.read_text(encoding="utf-8")
        assert "file_preview" in audit
        assert "malware430" not in audit
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
