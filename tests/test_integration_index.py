from __future__ import annotations

import hashlib
import os
import stat as stat_module
import time
from pathlib import Path

import pytest

from dfir_browser.core.config import EwfMapping, Settings
from dfir_browser.core.index_models import DeletedFilesQuery, FileSearchQuery
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


def wait_for_scan(services, record, timeout: float = 180.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = services.indexer.status_for_record(record)
        if status.status != "running":
            return status
        time.sleep(0.25)
    raise AssertionError("filesystem index scan did not finish within timeout")


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_full_filesystem_index(tmp_path: Path) -> None:
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
        index_batch_size=1000,
        index_page_size_default=100,
        index_page_size_max=500,
    )
    services = build_services(settings)
    record = services.evidence.register(str(EVIDENCE))

    assert record.layout.scope == "volume"
    assert record.layout.filesystem == "NTFS"
    assert record.layout.offset_sectors == 0
    assert record.layout.method == "fsstat"
    assert record.raw_exposure_path == str(EWF1.resolve())
    assert record.source_sha256 == before_hash

    started = services.indexer.start_scan(record.evidence_id)
    assert started.started is True
    status = wait_for_scan(services, record)
    assert status.status == "ready"
    assert status.complete is True
    assert status.stale is False
    assert status.parse_errors == 0
    assert status.entries_seen > 100_000
    assert status.entries_indexed == status.entries_seen
    assert status.deleted_files > 0
    assert status.deleted_directories > 0

    root = services.indexer.list_directory(
        record, "", page=1, page_size=100
    )
    assert root.source == "index"
    assert root.complete is True
    users = [entry for entry in root.entries if entry.name == "Users"]
    assert users, "index root must contain Users"
    assert users[0].inode == 1746
    assert users[0].entry_type == "directory"

    users_dir = services.indexer.list_directory(
        record, "Users", page=1, page_size=100
    )
    ieuser = [entry for entry in users_dir.entries if entry.name == "IEUser"]
    assert ieuser, "index Users must contain IEUser"
    assert ieuser[0].inode == 83437
    assert ieuser[0].entry_type == "directory"

    downloads = services.indexer.list_directory(
        record, "Users/Public/Downloads", page=1, page_size=100
    )
    sysinternals = [
        entry
        for entry in downloads.entries
        if entry.basename.lower() == "sysinternals.exe"
    ]
    assert sysinternals, "Users/Public/Downloads must contain SysInternals.exe"
    entry = sysinternals[0]
    assert entry.full_path == "Users/Public/Downloads/SysInternals.exe"
    assert entry.inode == 124567
    assert entry.deleted is True
    assert entry.allocated is False
    assert entry.entry_type == "file"
    assert entry.size == 57344
    assert entry.fls_type == "-/r"

    deleted_query = DeletedFilesQuery.create(
        search="Sysinternals.exe",
        page=1,
        page_size=100,
        default_page_size=100,
        max_page_size=500,
    )
    deleted = services.indexer.list_deleted(record, deleted_query)
    assert deleted.complete is True
    assert deleted.index_status.status == "ready"
    deleted_paths = {item.full_path: item for item in deleted.results}
    assert "Users/Public/Downloads/SysInternals.exe" in deleted_paths
    deleted_entry = deleted_paths["Users/Public/Downloads/SysInternals.exe"]
    assert deleted_entry.deleted is True
    assert deleted_entry.allocated is False
    assert deleted_entry.inode == 124567

    search_query = FileSearchQuery.create(
        query="Sysinternals.exe",
        exact=True,
        deleted_only=True,
        page=1,
        page_size=100,
        default_page_size=100,
        max_page_size=500,
    )
    search = services.indexer.search(record, search_query)
    assert search.complete is True
    assert search.total >= 1
    search_paths = {item.full_path for item in search.results}
    assert "Users/Public/Downloads/SysInternals.exe" in search_paths
    assert deleted_paths.keys() >= search_paths

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert before_hash == after_hash, "evidence content changed"
    assert before_stat.st_size == after_stat.st_size
    assert before_stat.st_mtime_ns == after_stat.st_mtime_ns
    assert stat_module.S_IMODE(before_stat.st_mode) == stat_module.S_IMODE(
        after_stat.st_mode
    )

    services.cleanup()


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_tree_navigation(tmp_path: Path) -> None:
    """Real-evidence tree: root -> Users -> Public -> Downloads, lazy pages."""
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
        index_batch_size=1000,
        index_page_size_default=100,
        index_page_size_max=500,
    )
    services = build_services(settings)
    record = services.evidence.register(str(EVIDENCE))
    services.indexer.start_scan(record.evidence_id)
    status = wait_for_scan(services, record, timeout=300.0)
    assert status.status == "ready", status.warning
    assert status.complete is True

    try:
        root = services.indexer.tree_page(record, 0, page_size=100)
        assert root.parent is None
        root_names = {child.name for child in root.children}
        assert {"Users", "Windows", "$Extend"} <= root_names
        assert root.total == 33

        users = next(child for child in root.children if child.name == "Users")
        assert users.path == "Users"
        users_page = services.indexer.tree_page(
            record, users.entry_id, page_size=100
        )
        assert {"IEUser", "Public"} <= {c.name for c in users_page.children}
        ieuser = next(c for c in users_page.children if c.name == "IEUser")
        assert ieuser.inode == 83437

        public = next(c for c in users_page.children if c.name == "Public")
        public_page = services.indexer.tree_page(
            record, public.entry_id, page_size=100
        )
        downloads = next(
            c for c in public_page.children if c.name == "Downloads"
        )
        downloads_page = services.indexer.tree_page(
            record, downloads.entry_id, page_size=100
        )
        names = {c.name for c in downloads_page.children}
        assert {"desktop.ini", "SysInternals.exe"} <= names
        exe = next(
            c for c in downloads_page.children if c.name == "SysInternals.exe"
        )
        assert exe.deleted is True
        assert exe.allocated is False
        assert exe.inode == 124567
        assert exe.status_label == "deleted"

        ancestors = services.indexer.tree_ancestors(record, exe.entry_id)
        assert [a.name for a in ancestors.ancestors] == [
            "Users",
            "Public",
            "Downloads",
        ]

        reveal = services.indexer.tree_reveal(record, exe.entry_id)
        assert len(reveal["steps"]) == 3
        assert reveal["entry"]["deleted"] is True

        hidden = services.indexer.tree_page(
            record, downloads.entry_id, include_deleted=False
        )
        assert "SysInternals.exe" not in {c.name for c in hidden.children}

        orphan_root = next(
            (c for c in root.children if c.name == "$OrphanFiles"), None
        )
        if orphan_root is not None:
            orphan_page = services.indexer.tree_page(
                record, orphan_root.entry_id, page_size=5
            )
            assert orphan_page.total > 0
            assert orphan_page.children

        direct = services.indexer.resolve_entry_path(
            record, "Users/Public/Downloads/SysInternals.exe"
        )
        assert direct.id == exe.entry_id
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_vmtoolsio_timeline_correlation(tmp_path: Path) -> None:
    """Use a SysInternals executable as anchor and cite FS metadata as source."""
    before_stat = EVIDENCE.stat()
    before_hash = sha256_file(EVIDENCE)
    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(Path("/home/ubuntu/test"), Path("/home/ubuntu/evidence")),
        ewf_mappings={str(EVIDENCE.resolve()): EwfMapping(
            exposure=str(EWF1.resolve()), source_sha256=before_hash,
            media_size=14720958464)},
        ewf_automount=False, auto_index=False, command_timeout=60.0,
        index_timeout=240.0, index_batch_size=2000,
    )
    services = build_services(settings)
    try:
        record = services.evidence.register(str(EVIDENCE))
        services.indexer.start_scan(record.evidence_id)
        status = wait_for_scan(services, record, timeout=300)
        assert status.status == "ready" and status.complete
        query = FileSearchQuery.create(query="vmtoolsIO.exe", exact=True, page_size=20)
        matches = services.indexer.search(record, query).results
        assert matches, "vmtoolsIO.exe was not present in the filesystem index"
        source_entry = matches[0]
        assert source_entry.entry_type == "file"
        services.investigation.start(record.evidence_id, rebuild=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = services.investigation.status(record.evidence_id)
            if result["state"] not in {"queued", "running"}: break
            time.sleep(.2)
        assert result["state"] in {"ready", "partial"}, result
        assert "filesystem" not in result["errors"], result["errors"]
        timeline = services.investigation.query(record.evidence_id, keyword="vmtoolsIO.exe", page_size=20)
        assert any(item["source_type"] == "filesystem" and item["source_record_id"] == str(source_entry.id)
                   for item in timeline["items"]), "timeline omitted vmtoolsIO filesystem metadata"
        related = services.investigation.related(record.evidence_id, source_entry.id, limit=20)
        assert related["entry_id"] == source_entry.id
    finally:
        services.cleanup()
    after_stat = EVIDENCE.stat()
    assert (after_stat.st_size, after_stat.st_mtime_ns) == (before_stat.st_size, before_stat.st_mtime_ns)
    assert sha256_file(EVIDENCE) == before_hash


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_static_triage(tmp_path: Path) -> None:
    """Real SysInternals.exe entry: static triage only, evidence unchanged."""
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
        index_batch_size=1000,
        index_page_size_default=100,
        index_page_size_max=500,
        triage_yara_rules_dir=(
            Path(__file__).resolve().parents[1] / "rules" / "yara"
        ),
    )
    services = build_services(settings)
    record = services.evidence.register(str(EVIDENCE))
    services.indexer.start_scan(record.evidence_id)
    status = wait_for_scan(services, record, timeout=300.0)
    assert status.status == "ready", status.warning

    try:
        entry = services.indexer.resolve_entry_path(
            record, "Users/Public/Downloads/SysInternals.exe"
        )
        assert entry.inode == 124567
        started = services.triage.start(record, entry.id, case_id="case01")
        deadline = time.monotonic() + 180
        job = None
        while time.monotonic() < deadline:
            job = services.triage.get_job(started.job_id)
            if job.status not in {"queued", "running"}:
                break
            time.sleep(0.25)
        assert job is not None
        assert job.status in {"complete", "partial"}, job.errors
        assert job.sha256 and len(job.sha256) == 64
        assert job.md5 and job.sha1
        assert job.size and job.size > 0
        assert job.file_type
        assert job.entropy is not None
        assert job.pe_status in {"ok", "skipped", "failed", "unavailable"}
        assert job.yara_status in {
            "ok",
            "no_rules",
            "failed",
            "timeout",
            "unavailable",
        }
        extracted = settings.var_dir / job.extract_relpath
        assert extracted.is_file()
        assert (extracted.stat().st_mode & 0o777) == 0o600

        second = services.triage.start(record, entry.id, case_id="case01")
        cached = None
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            cached = services.triage.get_job(second.job_id)
            if cached.status not in {"queued", "running"}:
                break
            time.sleep(0.25)
        assert cached is not None
        assert cached.cached is True
        assert cached.cached_from_job_id in {
            job.job_id,
            job.cached_from_job_id,
        }
        assert cached.sha256 == job.sha256
    finally:
        services.cleanup()

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert after_hash == before_hash
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
