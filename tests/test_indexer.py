from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from dfir_browser.core.audit import AuditLogger
from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import (
    DeletedFilesQuery,
    IndexStaleError,
    utc_now_iso,
)
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.indexer import FilesystemIndexer
from dfir_browser.core.models import Layout

EV = "ev_0123456789ab"
TS = "2020-01-01 00:00:00 (UTC)"

FAKE_FLS = r'''
import sys
import time

image = sys.argv[-1]
try:
    data = open(image, "r", encoding="utf-8").read()
except OSError as exc:
    print("cannot read image: " + str(exc), file=sys.stderr)
    sys.exit(2)

if data.startswith("__SLEEP__"):
    print("r/r 1-128-1:\tfake.txt\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t1\t0\t0", flush=True)
    time.sleep(30)
elif data.startswith("__FAIL__"):
    print("fake fls failure", file=sys.stderr)
    sys.exit(2)
elif data.startswith("__PARTIAL__"):
    sys.stdout.write("r/r 2-128-1:\tpartial.txt\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t1\t0\t0")
    sys.stdout.flush()
    sys.exit(2)
elif data.startswith("__MANY__"):
    for index in range(2500):
        print(f"r/r {index + 3}-128-1:\tMany/file{index}.txt\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t2020-01-01 00:00:00 (UTC)\t1\t0\t0")
else:
    sys.stdout.write(data)
'''


class FakeRunner:
    def version(self, binary: str) -> str:
        return "fake-tsk 1.0"


class FakeEvidence:
    def __init__(self, record, image: Path) -> None:
        self.record = record
        self.image = image

    def get(self, evidence_id: str):
        assert evidence_id == self.record.evidence_id
        return self.record

    def ensure_image(self, record):
        return self.image


class RecordingStore(IndexStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.batches: list[int] = []

    def insert_entries(self, rows):
        materialized = list(rows)
        self.batches.append(len(materialized))
        super().insert_entries(materialized)


def make_env(
    tmp_path: Path,
    image_content: str,
    *,
    store_factory=IndexStore,
    **settings_overrides,
):
    script = tmp_path / "fake_fls.py"
    script.write_text(FAKE_FLS, encoding="utf-8")
    image = tmp_path / "exposure.bin"
    image.write_text(image_content, encoding="utf-8")

    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(tmp_path,),
        ewf_mappings={},
        auto_index=False,
        index_fls_command=(sys.executable, str(script)),
        index_db_path=tmp_path / "var" / "index" / "filesystem.db",
        index_timeout=settings_overrides.pop("index_timeout", 5.0),
        index_batch_size=settings_overrides.pop("index_batch_size", 1000),
        index_max_entries=settings_overrides.pop("index_max_entries", 100000),
        index_page_size_default=100,
        index_page_size_max=500,
        **settings_overrides,
    )
    store = store_factory(settings.index_database())
    store.ensure_schema()
    audit = AuditLogger(settings.audit_file())
    record = SimpleNamespace(
        evidence_id=EV,
        source_sha256="a" * 64,
        raw_exposure_path=str(image),
        layout=Layout(
            scope="volume",
            filesystem="NTFS",
            offset_sectors=0,
            method="fsstat",
        ),
    )
    evidence = FakeEvidence(record, image)
    indexer = FilesystemIndexer(
        settings=settings,
        store=store,
        evidence=evidence,
        runner=FakeRunner(),
        audit=audit,
    )
    return settings, store, indexer, record, image, audit


def wait_for(indexer: FilesystemIndexer, record, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = indexer.status_for_record(record)
        if status.status != "running":
            return status
        time.sleep(0.05)
    raise AssertionError("index scan did not finish")


def valid_line(name: str, inode: int = 1) -> str:
    return (
        f"r/r {inode}-128-1:\t{name}\t{TS}\t{TS}\t{TS}\t{TS}\t1\t0\t0\n"
    )


def test_streaming_batches_and_ready_status(tmp_path: Path) -> None:
    _settings, store, indexer, record, _image, _audit = make_env(
        tmp_path, "__MANY__", store_factory=RecordingStore, index_batch_size=10
    )
    result = indexer.start_scan(EV)
    assert result.started is True
    status = wait_for(indexer, record)
    assert status.status == "ready"
    assert status.complete is True
    assert status.entries_seen == 2500
    assert status.entries_indexed == 2500
    assert status.parse_errors == 0
    assert len(store.batches) > 1
    assert max(store.batches) <= 10
    assert sum(store.batches) == 2500
    indexer.cancel_all()


def test_nonzero_exit_marks_failed(tmp_path: Path) -> None:
    _settings, _store, indexer, record, _image, _audit = make_env(
        tmp_path, "__FAIL__"
    )
    indexer.start_scan(EV)
    status = wait_for(indexer, record)
    assert status.status == "failed"
    assert status.error_code == "fls_failed"
    indexer.cancel_all()


def test_timeout_marks_failed(tmp_path: Path) -> None:
    _settings, _store, indexer, record, _image, _audit = make_env(
        tmp_path, "__SLEEP__", index_timeout=0.5
    )
    indexer.start_scan(EV)
    status = wait_for(indexer, record, timeout=15.0)
    assert status.status == "failed"
    assert status.error_code == "index_timeout"
    indexer.cancel_all()


def test_entry_limit_marks_incomplete(tmp_path: Path) -> None:
    _settings, _store, indexer, record, _image, _audit = make_env(
        tmp_path, "__MANY__", index_max_entries=20, index_batch_size=5
    )
    indexer.start_scan(EV)
    status = wait_for(indexer, record)
    assert status.status == "incomplete"
    assert status.error_code == "index_entry_limit"
    assert status.entries_seen == 20
    indexer.cancel_all()


def test_parse_errors_are_stored(tmp_path: Path) -> None:
    content = "this is not a valid fls line\n" + valid_line("Users/good.txt")
    _settings, store, indexer, record, _image, _audit = make_env(
        tmp_path, content
    )
    indexer.start_scan(EV)
    status = wait_for(indexer, record)
    assert status.status == "incomplete"
    assert status.error_code == "parse_errors"
    assert status.parse_errors == 1
    assert store.count_parse_errors(EV, status.scan_id) == 1
    errors = store.list_parse_errors(EV, status.scan_id)
    assert "not a valid fls line" in errors[0]["raw_line"]
    # The warning must state the exact count, not a vague "may be missing".
    assert status.warning is not None
    assert "1 of" in status.warning
    assert "entries could not be parsed" in status.warning
    assert "%" in status.warning
    indexer.cancel_all()


def test_partial_final_line_is_dropped(tmp_path: Path) -> None:
    _settings, store, indexer, record, _image, _audit = make_env(
        tmp_path, "__PARTIAL__"
    )
    indexer.start_scan(EV)
    status = wait_for(indexer, record)
    assert status.status == "failed"
    assert status.parse_errors >= 1
    rows, total = store.query_all_under(
        EV, status.scan_id, "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    assert total == 0
    assert all(entry.basename != "partial.txt" for entry in rows)
    indexer.cancel_all()


def test_one_active_scan_per_evidence(tmp_path: Path) -> None:
    _settings, _store, indexer, record, _image, _audit = make_env(
        tmp_path, "__SLEEP__", index_timeout=10.0
    )
    first = indexer.start_scan(EV)
    assert first.started is True
    second = indexer.start_scan(EV)
    assert second.started is False
    assert second.status.status == "running"
    assert second.note == "index scan already running"
    indexer.cancel_all()
    status = wait_for(indexer, record, timeout=15.0)
    assert status.status == "interrupted"


def test_rebuild_replaces_generation(tmp_path: Path) -> None:
    _settings, store, indexer, record, image, _audit = make_env(
        tmp_path, valid_line("Users/old.txt", inode=10)
    )
    indexer.start_scan(EV)
    first = wait_for(indexer, record)
    assert first.status == "ready"
    first_scan = first.scan_id
    rows, total = store.query_all_under(
        EV, first_scan, "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    assert total == 1
    assert rows[0].basename == "old.txt"

    image.write_text(valid_line("Users/new.txt", inode=11), encoding="utf-8")
    result = indexer.start_scan(EV, rebuild=True)
    assert result.started is True
    second = wait_for(indexer, record)
    assert second.status == "ready"
    assert second.scan_id != first_scan
    new_rows, new_total = store.query_all_under(
        EV, second.scan_id, "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    old_rows, old_total = store.query_all_under(
        EV, first_scan, "", sort="path", sort_dir="asc", page=1, page_size=100
    )
    assert new_total == 1
    assert new_rows[0].basename == "new.txt"
    assert old_total == 0
    assert old_rows == []
    indexer.cancel_all()


def test_identity_mismatch_is_stale_and_rejected(tmp_path: Path) -> None:
    _settings, _store, indexer, record, _image, _audit = make_env(
        tmp_path, valid_line("Users/file.txt")
    )
    indexer.start_scan(EV)
    wait_for(indexer, record)

    changed = SimpleNamespace(
        evidence_id=EV,
        source_sha256="b" * 64,
        raw_exposure_path=record.raw_exposure_path,
        layout=record.layout,
    )
    status = indexer.status_for_record(changed)
    assert status.stale is True
    assert status.queryable is False
    query = DeletedFilesQuery.create(
        default_page_size=100, max_page_size=500
    )
    with pytest.raises(IndexStaleError):
        indexer.list_deleted(changed, query)
    indexer.cancel_all()


def test_interrupted_scan_recovered_on_startup(tmp_path: Path) -> None:
    _settings, store, _indexer, record, image, audit = make_env(
        tmp_path, valid_line("Users/file.txt")
    )
    store.begin_scan(
        EV,
        "interrupted-scan",
        {
            "source_sha256": "a" * 64,
            "raw_exposure_path": str(image),
            "filesystem": "NTFS",
            "offset_sectors": 0,
            "fls_version": "fake-tsk 1.0",
            "index_schema_version": 1,
            "scanner_version": "fls-r-p-l-v1",
        },
        utc_now_iso(),
    )
    # A new indexer has no in-process handle and the lock is free, so it must
    # mark the old running row interrupted.
    FilesystemIndexer(
        settings=_settings,
        store=store,
        evidence=FakeEvidence(record, image),
        runner=FakeRunner(),
        audit=audit,
    )
    row = store.get_index_row(EV)
    assert row["status"] == "interrupted"
    assert row["error_code"] == "interrupted"


def test_audit_records_scan_metadata_without_filenames(tmp_path: Path) -> None:
    settings, _store, indexer, record, _image, audit = make_env(
        tmp_path, valid_line("Users/secret-name.txt")
    )
    indexer.start_scan(EV)
    wait_for(indexer, record)
    audit_path = settings.audit_file()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if (
            audit_path.exists()
            and '"tool": "fls-index"' in audit_path.read_text(encoding="utf-8")
        ):
            break
        time.sleep(0.05)
    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    scan_records = [record for record in records if record.get("tool") == "fls-index"]
    assert len(scan_records) == 1
    scan_record = scan_records[0]
    assert scan_record["evidence_id"] == EV
    assert scan_record["extra"]["entries_seen"] == 1
    assert scan_record["extra"]["entries_indexed"] == 1
    assert scan_record["extra"]["status"] == "ready"
    events = [record["event"] for record in records if "event" in record]
    assert "index_start" in events
    assert "index_finish" in events
    serialized = audit_path.read_text(encoding="utf-8")
    assert "secret-name.txt" not in serialized
    indexer.cancel_all()
