from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from dfir_browser.core.config import Settings
from dfir_browser.core.services import build_services

# Recycle Bin $I/$R records live in this logical AD1 image, not the E01.
EVIDENCE = Path(
    os.environ.get(
        "DFIR_TEST_AD1",
        "/home/ubuntu/test/testad1/temp_extract_dir/DiskDigger/DiskDrigger.ad1",
    )
)

pytestmark = pytest.mark.integration

SKIP_REASON = None
if os.environ.get("DFIR_SKIP_EVIDENCE_TESTS") == "1":
    SKIP_REASON = "DFIR_SKIP_EVIDENCE_TESTS=1"
elif not EVIDENCE.is_file():
    SKIP_REASON = f"evidence not found: {EVIDENCE}"


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
def test_real_recycle_bin_metadata(tmp_path: Path) -> None:
    before = EVIDENCE.stat()
    before_hash = sha256_file(EVIDENCE)
    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(Path("/home/ubuntu/test"), Path("/home/ubuntu/evidence")),
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
        scan_id = services.index_store.get_index_row(record.evidence_id)["scan_id"]
        rows = services.index_store._connect().execute(
            "SELECT id FROM filesystem_entries WHERE evidence_id = ? "
            "AND scan_id = ? AND basename LIKE '$I%' "
            "ORDER BY full_path COLLATE NOCASE LIMIT 50",
            (record.evidence_id, scan_id),
        ).fetchall()
        assert rows, "expected $I records in the AD1 logical image"
        info_entry_id = int(rows[0]["id"])
        result = services.recycle_bin.metadata(record, info_entry_id)
        assert result.is_recycle_entry
        assert result.kind == "info"
        assert result.version in {1, 2}
        assert result.original_path
        assert result.deleted_time_utc
        assert result.deletion_source == "$I deletion timestamp"
        assert result.sid and result.sid.startswith("S-")
        # The pair must agree on the deletion time when $R exists.
        if result.content_entry_id:
            paired = services.recycle_bin.metadata(
                record, result.content_entry_id
            )
            assert paired.deleted_time_utc == result.deleted_time_utc
    finally:
        services.cleanup()
    after = EVIDENCE.stat()
    assert sha256_file(EVIDENCE) == before_hash
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
