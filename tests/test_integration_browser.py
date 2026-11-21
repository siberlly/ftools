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

WEB_CACHE_SUFFIX = (
    "Users/IEUser/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat"
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
def test_real_browser_artifacts(tmp_path: Path) -> None:
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
        browser_parser_timeout=600.0,
        browser_max_records=500_000,
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
        candidates = services.browser_artifacts.list_artifacts(
            record, include_deleted=True, page_size=500
        )
        paths = {item.path for item in candidates.items}
        webcache = next(
            (item for item in candidates.items if item.path.endswith(WEB_CACHE_SUFFIX)),
            None,
        )
        assert webcache is not None
        assert webcache.browser == "webcache"
        assert webcache.user == "IEUser"
        assert "WebCacheV01.jfm" in webcache.sidecars
        # Chromium and Firefox are absent from this image; they must be reported
        # as not present instead of faked.
        assert not any(item.browser == "chromium" for item in candidates.items)
        assert not any(item.browser == "firefox" for item in candidates.items)
        coverage = {item["artifact_type"]: item for item in candidates.coverage}
        assert coverage["webcache"]["status"] == "present"
        assert coverage["webcache"]["users"] == ["IEUser"]
        assert coverage["chromium_history"]["status"] == "not_present"
        assert coverage["firefox_places"]["status"] == "not_present"

        started = services.browser_artifacts.start_index(
            record, webcache.entry_id, rebuild=True
        )
        artifact_id = started["artifact"]["artifact_id"]
        artifact = wait_until(
            lambda: (
                services.browser_artifacts.status(artifact_id)
                if services.browser_artifacts.status(artifact_id)["status"]
                not in {"queued", "running"}
                else None
            ),
            timeout=600.0,
        )
        assert artifact["status"] in {"ready", "partial"}
        assert artifact["records_indexed"] > 0
        after_index = services.browser_artifacts.list_artifacts(
            record, include_deleted=True
        )
        coverage = {item["artifact_type"]: item for item in after_index.coverage}
        assert coverage["webcache"]["status"] == "indexed"
        assert coverage["chromium_history"]["status"] == "not_present"
        assert coverage["firefox_places"]["status"] == "not_present"
        assert artifact["parse_errors"] == 0
        assert artifact["first_record_time"] and artifact["last_record_time"]

        downloads = services.browser_artifacts.query_downloads(
            record.evidence_id, page_size=500
        )
        assert downloads.total > 0
        sysinternals = next(
            (
                item
                for item in downloads.items
                if (item["filename"] or "").lower().startswith("sysinternals")
            ),
            None,
        )
        assert sysinternals is not None
        assert sysinternals["domain"] == "sysinternals.com"
        assert sysinternals["received_bytes"] == 57344
        assert sysinternals["state"] == "complete"

        search = services.browser_artifacts.query_downloads(
            record.evidence_id, query="download.sysinternals.com"
        )
        assert search.total == 0

        history = services.browser_artifacts.query_history(
            record.evidence_id, query="SysInternals", page_size=200
        )
        assert history.total >= 1

        window = services.browser_artifacts.query_downloads(
            record.evidence_id,
            time_from="2022-11-15T00:00:00Z",
            time_to="2022-11-16T00:00:00Z",
            page_size=500,
        )
        assert window.total >= 1
        assert any(
            (item["filename"] or "").lower().startswith("sysinternals")
            for item in window.items
        )

        correlation = services.browser_artifacts.correlate_download(
            record.evidence_id, sysinternals["download_id"]
        )
        hits = correlation["correlation"]["hits"]
        assert hits
        assert any(
            hit["path"].lower() == "users/public/downloads/sysinternals.exe"
            for hit in hits
        )
        deleted_hit = next(
            hit
            for hit in hits
            if hit["path"].lower() == "users/public/downloads/sysinternals.exe"
        )
        assert deleted_hit["deleted"] is True
        assert deleted_hit["size_matches"] is True

        summary = services.browser_artifacts.summary(
            record.evidence_id
        ).to_dict()
        assert summary["total_downloads"] == downloads.total
        assert summary["top_domains"]
        assert summary["trust"] == "untrusted_evidence_data"

        for preset in (
            "browser.executable_downloads",
            "browser.incomplete_downloads",
            "browser.ip_literal_urls",
            "browser.http_downloads",
            "browser.suspicious_schemes",
            "browser.deleted_targets",
            "browser.domain_filename_mismatch",
            "browser.recent_window",
        ):
            result = services.browser_artifacts.query_downloads(
                record.evidence_id, preset=preset, page_size=50
            )
            assert result.kind == "downloads"
            assert any("not a malware verdict" in w for w in result.warnings)

        exports = services.policy.case_exports_dir("case01")
        before = len([p for p in exports.rglob("*") if p.is_file()])
        cached = services.browser_artifacts.start_index(
            record, webcache.entry_id
        )
        assert cached["started"] is False and cached["cached"] is True
        after = len([p for p in exports.rglob("*") if p.is_file()])
        assert after == before
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
