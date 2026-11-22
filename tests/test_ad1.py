from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dfir_browser.core.backends import AD1EvidenceBackend, ad1_segments, segment_manifest
from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import FileSearchQuery
from dfir_browser.core.services import build_services
from dfir_browser.web.app import create_app

FIXTURE_DIR = Path(os.environ.get("DFIR_TEST_AD1_DIR", "~/test/testad1/temp_extract_dir")).expanduser()


def _snapshot(paths: list[Path]):
    result = {}
    for path in paths:
        stat = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[str(path)] = (stat.st_size, stat.st_mtime_ns, digest.hexdigest())
    return result


@pytest.mark.integration
@pytest.mark.skipif(not FIXTURE_DIR.is_dir(), reason=f"AD1 fixture not found: {FIXTURE_DIR}")
def test_ad1_fixture_end_to_end(tmp_path: Path) -> None:
    primary = next(FIXTURE_DIR.rglob("*.ad1"), None)
    if primary is None:
        pytest.skip(f"no primary .ad1 fixture in {FIXTURE_DIR}")
    segments = ad1_segments(primary, (Path.home() / "test",))
    before = _snapshot(segments)
    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(Path.home() / "test",),
        auto_index=False,
        extract_timeout=120,
    )
    services = build_services(settings)
    try:
        record = services.evidence.register(str(primary))
        assert record.format == "AD1"
        assert record.layout.scope == "logical"
        assert record.exposure_details["segment_count"] == len(segments)
        assert record.exposure_details["segments"] == segment_manifest(segments)

        start = services.indexer.start_scan(record.evidence_id)
        assert start.started
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = services.indexer.status(record.evidence_id)
            if status.status not in {"pending", "running"}:
                break
            time.sleep(0.25)
        assert status.status == "ready", status.to_dict()
        assert status.complete
        tree = services.indexer.tree_page(record, 0, page_size=500)
        dirs = [services.indexer.tree_entry(record, node.entry_id) for node in tree.children if node.entry_type == "directory"]
        assert dirs
        files = [row for row in services.indexer.search(record, FileSearchQuery(query=".", entry_type="file", page_size=500)).results if row.size is not None and row.size <= 2 * 1024 * 1024]
        assert files
        entry = next((row for row in files if row.stored_md5 or row.stored_sha1), files[0])
        with TestClient(create_app(settings, services)) as client:
            landing = client.get("/")
            csrf = re.search(r'name="csrf_token" value="([^\"]+)"', landing.text).group(1)
            registration = client.post("/evidence", data={"path": str(primary), "csrf_token": csrf})
            assert registration.status_code == 200
            assert record.evidence_id in registration.text
            page = client.get(f"/evidence/{record.evidence_id}?entry=0")
            assert page.status_code == 200
            csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
            assert 'role="tree"' in client.get(f"/evidence/{record.evidence_id}/tree").text
            assert client.get(f"/evidence/{record.evidence_id}/tree/children?parent_id=0").status_code == 200
            assert client.get(f"/evidence/{record.evidence_id}/search?query=.").status_code == 200
            preview_response = client.get(f"/evidence/{record.evidence_id}/entries/{entry.id}/preview?limit=4096")
            assert preview_response.status_code == 200
            assert preview_response.json()["ok"] is True
            extract_response = client.post(f"/evidence/{record.evidence_id}/entry/{entry.id}/extract",
                data={"case_id": "ad1test", "csrf_token": csrf})
            assert extract_response.status_code == 200, extract_response.text
            exports = services.policy.case_exports_dir("ad1test")
            extracted_path = next(path for path in exports.iterdir() if not path.name.endswith(".provenance.json"))
            assert extracted_path.stat().st_size == entry.size
            triage_panel = client.get(f"/evidence/{record.evidence_id}/entries/{entry.id}/triage/panel")
            assert triage_panel.status_code == 200
            triage_response = client.post(f"/evidence/{record.evidence_id}/entries/{entry.id}/triage",
                data={"case_id": "ad1test", "force": "1", "csrf_token": csrf}, headers={"hx-request": "true"})
            assert triage_response.status_code == 200, triage_response.text
            job_id = re.search(r'data-job-id="(tr_[0-9a-f]{16})"', triage_response.text).group(1)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                job = services.triage.get_job(job_id)
                if job.status not in {"queued", "running"}:
                    break
                time.sleep(0.25)
            assert job.status in {"complete", "partial"}, job.to_dict()
        actual = extracted_path.read_bytes()
        if entry.stored_md5:
            assert hashlib.md5(actual).hexdigest() == entry.stored_md5.lower()
        if entry.stored_sha1:
            assert hashlib.sha1(actual).hexdigest() == entry.stored_sha1.lower()
        assert Path(str(extracted_path) + ".provenance.json").is_file()
        provenance = json.loads(Path(str(extracted_path) + ".provenance.json").read_text())
        if entry.stored_md5 or entry.stored_sha1:
            assert provenance["integrity_verified"] is True
        assert provenance["source_ref"] == entry.source_ref
        assert provenance["untrusted"] is True
    finally:
        services.cleanup()
    assert _snapshot(segments) == before


def test_ad1_backend_rejects_path_traversal() -> None:
    with pytest.raises(Exception, match="unsafe path"):
        AD1EvidenceBackend._safe_name("../outside")
