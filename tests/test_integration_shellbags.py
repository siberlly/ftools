from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from dfir_browser.core.config import Settings
from dfir_browser.core.services import build_services

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
def test_real_shellbags_recover_mtp_tree(tmp_path: Path) -> None:
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
        candidates = services.shellbags.candidates(record)
        usrclass = next(
            c for c in candidates if c["name"] == "UsrClass.dat"
        )
        # Index the hive first so ShellBags can deep-link to registry keys.
        services.registry_browser.start_index(record, usrclass["entry_id"])
        wait_until(
            lambda: (
                services.registry_browser.status(
                    services.registry_store.find_hive_by_entry(
                        record.evidence_id, usrclass["entry_id"]
                    ).hive_id
                )
                if services.registry_store.find_hive_by_entry(
                    record.evidence_id, usrclass["entry_id"]
                ) is not None
                and services.registry_store.find_hive_by_entry(
                    record.evidence_id, usrclass["entry_id"]
                ).state
                in {"ready", "partial", "failed"}
                else None
            ),
            timeout=300.0,
        )
        started = services.shellbags.start(record, rebuild=True)
        assert started["started"] is True
        state = wait_until(
            lambda: (
                services.shellbags.state(record.evidence_id)
                if services.shellbags.state(record.evidence_id)["state"]
                not in {"queued", "running"}
                else None
            ),
            timeout=300.0,
        )
        assert state["state"] in {"ready", "partial"}, state
        assert state["nodes"] > 20

        devices = services.shellbags.devices(record.evidence_id)
        mtp = [d for d in devices["items"] if d["kind"] == "mtp"]
        assert mtp, devices["items"]
        assert mtp[0]["name"] == "LG Q7"

        chain = services.shellbags.search(
            record.evidence_id, query="Camera", kind="folder"
        )
        paths = [item["path"] for item in chain["items"]]
        assert any(
            path.endswith(r"LG Q7\Internal storage\DCIM\Camera") for path in paths
        ), paths

        found = services.shellbags.search(
            record.evidence_id, query="Internal storage"
        )
        assert found["total"] >= 1
        node = services.shellbags.node(found["items"][0]["node_id"])
        assert node["registry_key_path"].lower().endswith(
            ("bagmru", "bagmru\\0", "bagmru\\1")
        ) or "bagmru" in node["registry_key_path"].lower()
        assert node["key_last_write_utc"]
        # The registry index is ready, so the deep link must resolve.
        assert node["registry"] is not None
        assert node["registry"]["key_path"] == node["registry_key_path"]
        assert node["registry"]["key_id"] is not None

        # The MTP names must not be the regipy "<UNKNOWN: 0x00>" placeholder.
        text = " ".join(
            (item["name"] or "") for item in found["items"]
        )
        assert "UNKNOWN" not in text.upper()

        media, _name, body = services.shellbags.export(
            record.evidence_id, fmt="json"
        )
        assert media == "application/json"
        assert b"LG Q7" in body
    finally:
        services.cleanup()
    after = EVIDENCE.stat()
    assert sha256_file(EVIDENCE) == before_hash
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
