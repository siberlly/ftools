from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from dfir_browser.core.registry.amcache import normalize_file_id
from dfir_browser.core.registry.detector import inspect_hive_header
from dfir_browser.core.registry.models import (
    HiveNotFoundError,
    RegistryRejectedError,
)
from dfir_browser.core.registry.reader import RegistryLimitError, decode_value

from registry_helpers import (
    SHA1,
    amcache_key_records,
    build_registry_services,
    entry_id,
    normal_key_records,
    seed_hive,
    stub_registry_extract,
)


def header_bytes(seq1=1, seq2=1):
    return (
        b"regf"
        + seq1.to_bytes(4, "little")
        + seq2.to_bytes(4, "little")
        + b"\x00" * 8
        + b"\x00" * (4096 - 20)
    )


class FakeReader:
    records: list = []
    fail: Exception | None = None

    def __init__(self, path, settings):
        self.path = path

    def walk(self, deadline):
        for record in self.records:
            yield record
        if self.fail is not None:
            raise self.fail

    def close(self):
        pass


def wait_hive(services, hive_id, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hive = services.registry_browser.status(hive_id)
        if hive.state not in {"queued", "running"}:
            return hive
        time.sleep(0.02)
    raise AssertionError("registry job did not finish")


def test_discovery_classifies_known_hives(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    page = services.registry_browser.list_hives(record, page_size=50)
    types = {item.hive_type for item in page.items}
    assert {
        "amcache",
        "system",
        "software",
        "sam",
        "security",
        "ntuser",
        "usrclass",
    } <= types
    amcache = next(item for item in page.items if item.hive_type == "amcache")
    assert amcache.name == "Amcache.hve"
    assert amcache.inode == 200
    assert amcache.confidence >= 0.95
    sam = next(item for item in page.items if item.hive_type == "sam")
    assert sam.sensitive is True
    ntuser = next(item for item in page.items if item.name == "NTUSER.DAT")
    assert ntuser.owner == "IEUser"
    assert all(item.name != "old.hve" for item in page.items)
    with_deleted = services.registry_browser.list_hives(
        record, include_deleted=True, page_size=50
    )
    old = next(item for item in with_deleted.items if item.name == "old.hve")
    assert old.deleted is True and old.hive_type == "other"
    services.cleanup()


def test_hive_header_validation(tmp_path) -> None:
    good = tmp_path / "good.hve"
    good.write_bytes(header_bytes())
    header = inspect_hive_header(good)
    assert header.signature_valid is True
    assert header.dirty is False

    dirty = tmp_path / "dirty.hve"
    dirty.write_bytes(header_bytes(10, 11))
    header = inspect_hive_header(dirty)
    assert header.signature_valid is True
    assert header.dirty is True

    bad = tmp_path / "bad.hve"
    bad.write_bytes(b"XXXX" + b"\x00" * 4092)
    assert inspect_hive_header(bad).signature_valid is False

    short = tmp_path / "short.hve"
    short.write_bytes(b"regf")
    assert inspect_hive_header(short).signature_valid is False


def test_file_id_normalization() -> None:
    assert normalize_file_id(SHA1) == {
        "raw": SHA1,
        "algorithm": "sha1",
        "hash": SHA1,
        "valid": True,
        "method": "40-hex-sha1",
    }
    prefixed = "0000" + SHA1
    result = normalize_file_id(prefixed)
    assert result["algorithm"] == "sha1"
    assert result["hash"] == SHA1
    assert result["method"] == "strip-4-hex-prefix-sha1"
    assert normalize_file_id("0001" + SHA1)["algorithm"] == "unknown"
    assert normalize_file_id("A" * 64)["algorithm"] == "unknown"
    assert normalize_file_id("xyz")["valid"] is False
    assert normalize_file_id(None)["method"] == "none"


def test_decode_registry_value_types() -> None:
    assert (
        decode_value(
            "s", 1, "abc".encode("utf-16le"),
            max_value_bytes=100, max_text_length=10, preview_bytes=4,
        ).text_value
        == "abc"
    )
    assert (
        decode_value(
            "d", 4, (42).to_bytes(4, "little"),
            max_value_bytes=100, max_text_length=10, preview_bytes=4,
        ).text_value
        == "42"
    )
    assert (
        decode_value(
            "be", 5, (42).to_bytes(4, "big"),
            max_value_bytes=100, max_text_length=10, preview_bytes=4,
        ).text_value
        == "42"
    )
    assert (
        decode_value(
            "q", 11, (2**33).to_bytes(8, "little"),
            max_value_bytes=100, max_text_length=10, preview_bytes=4,
        ).text_value
        == str(2**33)
    )
    multi = decode_value(
        "m", 7, "a\x00b\x00\x00".encode("utf-16le"),
        max_value_bytes=100, max_text_length=20, preview_bytes=4,
    )
    assert multi.text_value == "a\nb"
    binary = decode_value(
        "b", 3, b"\x00\x01\x02" * 10,
        max_value_bytes=100, max_text_length=10, preview_bytes=4,
    )
    assert binary.text_value is None
    assert binary.preview_hex == "00010200"
    assert binary.raw_size == 30
    assert "binary preview truncated" in binary.warnings
    invalid = decode_value(
        "i", 1, b"\xff\xfe\x00",
        max_value_bytes=100, max_text_length=10, preview_bytes=4,
    )
    assert any("UTF-16" in warning for warning in invalid.warnings)
    truncated = decode_value(
        "t", 1, "abcdefgh".encode("utf-16le"),
        max_value_bytes=4, max_text_length=100, preview_bytes=4,
    )
    assert truncated.truncated is True
    assert "value truncated" in truncated.warnings[0]


def test_store_parent_child_search_and_pagination(tmp_path) -> None:
    services, _record = build_registry_services(tmp_path)
    hive_id = seed_hive(services, normal_key_records())
    children = services.registry_browser.list_subkeys(hive_id, page_size=10)
    assert children.total == 1
    assert children.items[0].name == "Root"
    child_page = services.registry_browser.list_subkeys(
        hive_id, parent_key_id=children.items[0].key_id, page_size=1
    )
    assert child_page.total == 1
    detail = services.registry_browser.get_key(
        hive_id, child_page.items[0].key_id
    )
    values = {item["name"]: item for item in detail["values"]}
    assert values["Dword"]["value"] == "42"
    assert values["Qword"]["value"] == "123456789"
    assert values["Binary"]["value"] is None
    assert values["Binary"]["preview_hex"] is not None

    search = services.registry_browser.search(hive_id, "Child", page_size=10)
    assert search.total >= 1
    assert any(item["kind"] == "key" for item in search.items)
    value_search = services.registry_browser.search(
        hive_id, "Hello Unicode", search_key_names=False, page_size=10
    )
    assert value_search.total == 1
    assert "日本語" in value_search.items[0]["value"]
    binary_search = services.registry_browser.search(
        hive_id, "000102", search_string_values=True, page_size=10
    )
    assert binary_search.total == 0

    page1 = services.registry_browser.search(hive_id, "Root", page_size=1)
    assert page1.total >= 2
    assert len(page1.items) == 1
    services.cleanup()


def test_seed_amcache_records(tmp_path) -> None:
    services, _record = build_registry_services(tmp_path)
    hive_id = seed_hive(services, amcache_key_records())
    result = services.registry_browser.amcache_search(
        hive_id, "SysInternals", page_size=10
    )
    assert result.total == 1
    record = result.items[0]
    assert record["executable_name"] == "SysInternals.exe"
    assert record["executable_path"].endswith("sysinternals.exe")
    assert record["file_id_raw"] == "0000" + SHA1
    assert record["hash_algorithm"] == "sha1"
    assert record["hash_normalized"] == SHA1
    assert record["normalization_method"] == "strip-4-hex-prefix-sha1"
    assert record["size"] == 57344
    assert record["publisher"].startswith("sysinternals")
    assert record["source_key_id"]
    assert record["source_value_names"]["file_id"] == "FileId"

    legacy = services.registry_browser.amcache_search(
        hive_id, "legacy", page_size=10
    )
    assert legacy.total == 1
    legacy_record = legacy.items[0]
    assert legacy_record["schema"] == "legacy_file"
    assert legacy_record["hash_algorithm"] == "sha1"
    assert legacy_record["file_id_raw"] == "A" * 40
    assert legacy_record["hash_normalized"] == "a" * 40
    services.cleanup()


def test_reader_build_reuses_cache_and_handles_warnings(
    tmp_path, monkeypatch
) -> None:
    services, record = build_registry_services(tmp_path)
    calls = stub_registry_extract(services, payload=header_bytes())
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records() + amcache_key_records()
    FakeReader.fail = None
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    first = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, first["hive"]["hive_id"])
    assert hive.state == "ready", hive.error_message
    assert hive.key_count == len(FakeReader.records)
    assert hive.amcache_count == 2
    assert hive.transaction_logs == ["Amcache.hve.LOG1"]
    assert any("not replayed" in warning for warning in hive.warnings)
    extracted = services.settings.var_dir / hive.extract_relpath
    assert oct(extracted.stat().st_mode & 0o777) == "0o600"

    exports_before = len(calls)
    second = services.registry_browser.start_index(record, target)
    assert second["started"] is False and second["cached"] is True
    assert len(calls) == exports_before
    services.cleanup()


def test_dirty_hive_and_limit_partial(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=header_bytes(5, 6))
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records()
    FakeReader.fail = None
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    result = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert hive.state == "ready"
    assert hive.dirty is True
    assert any("dirty" in warning for warning in hive.warnings)

    FakeReader.fail = RegistryLimitError("registry key limit reached")
    result = services.registry_browser.start_index(record, target, rebuild=True)
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert hive.state == "partial"
    assert hive.error_code == "registry_limit"
    services.cleanup()


def test_invalid_signature_fails(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=b"XXXX" + b"\x00" * 4092)
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    result = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert hive.state == "failed"
    assert hive.error_code == "registry_invalid_signature"
    services.cleanup()


def test_sensitive_hive_warning(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=header_bytes())
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records()
    FakeReader.fail = None
    target = entry_id(services, "Windows/System32/config/SAM")
    result = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert hive.sensitive is True
    assert any(
        "credential material is never" in warning for warning in hive.warnings
    )
    services.cleanup()


def test_cache_invalidated_when_schema_differs(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=header_bytes())
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records()
    FakeReader.fail = None
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    first = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, first["hive"]["hive_id"])
    row = services.registry_store.get_hive(hive.hive_id)
    row.schema_version = 0
    services.registry_store.finish_hive(row)
    again = services.registry_browser.start_index(record, target)
    assert again["started"] is True
    services.cleanup()


def test_missing_hive_and_invalid_entry(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    with pytest.raises(HiveNotFoundError):
        services.registry_browser.status("hive_ffffffffffffffff")
    with pytest.raises(Exception) as excinfo:
        services.registry_browser.start_index(record, -5)
    assert getattr(excinfo.value, "code", "") == "invalid_entry_id"
    services.cleanup()


def test_path_escape_and_symlink_rejected(tmp_path) -> None:
    services, _record = build_registry_services(tmp_path)
    outside = tmp_path / "outside.hve"
    outside.write_bytes(header_bytes())
    with pytest.raises(RegistryRejectedError) as excinfo:
        services.registry_browser._validate_extracted(str(outside))
    assert excinfo.value.code == "registry_path_escape"
    exports = services.policy.case_exports_dir("case01")
    link = exports / "link.hve"
    link.symlink_to(outside)
    with pytest.raises(RegistryRejectedError) as excinfo:
        services.registry_browser._validate_extracted(str(link))
    assert excinfo.value.code == "registry_symlink_rejected"
    services.cleanup()


def test_compare_match_mismatch_and_legacy(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    hive_id = seed_hive(services, amcache_key_records())
    record_row = services.registry_browser.amcache_search(
        hive_id, "SysInternals", page_size=5
    ).items[0]
    target = entry_id(services, "Users/Public/Downloads/SysInternals.exe")
    job = SimpleNamespace(
        job_id="tr_0123456789abcdef",
        sha1=SHA1,
        sha256="b" * 64,
        md5="c" * 32,
    )
    monkeypatch.setattr(
        services.triage.store, "latest_for_entry", lambda *args, **kwargs: job
    )
    result = services.registry_browser.compare_triage(
        record, hive_id, record_row["record_id"], target
    )
    assert result.status == "match"
    assert result.algorithm == "sha1"

    job.sha1 = "d" * 40
    result = services.registry_browser.compare_triage(
        record, hive_id, record_row["record_id"], target
    )
    assert result.status == "mismatch"

    legacy = services.registry_browser.amcache_search(
        hive_id, "legacy", page_size=5
    ).items[0]
    job.sha1 = "a" * 40
    result = services.registry_browser.compare_triage(
        record, hive_id, legacy["record_id"], target
    )
    assert result.status == "match"
    services.cleanup()


def test_compare_unknown_hash_and_ownership(tmp_path) -> None:
    services, record = build_registry_services(tmp_path)
    hive_id = seed_hive(services, amcache_key_records())
    amcache = services.registry_store.amcache_search(
        hive_id, "SysInternals", False, 1, 5
    ).items[0]
    with services.registry_store._connect() as connection:
        connection.execute(
            "UPDATE registry_amcache SET hash_algorithm='unknown', "
            "hash_normalized=NULL, hash_valid=0 WHERE id=?",
            (amcache["record_id"],),
        )
    target = entry_id(services, "Users/Public/Downloads/SysInternals.exe")
    result = services.registry_browser.compare_triage(
        record, hive_id, amcache["record_id"], target
    )
    assert result.status == "unknown"

    from dfir_browser.core.models import EvidenceRecord

    other = EvidenceRecord.from_dict(
        {**record.to_dict(), "evidence_id": "ev_ffffffffffff"}
    )
    with pytest.raises(RegistryRejectedError) as excinfo:
        services.registry_browser.compare_triage(
            other, hive_id, amcache["record_id"], target
        )
    assert excinfo.value.code == "hive_evidence_mismatch"
    services.cleanup()


def test_amcache_virustotal_uses_hash_only(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    hive_id = seed_hive(services, amcache_key_records())
    amcache = services.registry_browser.amcache_search(
        hive_id, "SysInternals", page_size=5
    ).items[0]
    captured = {}

    def fake_lookup(value, *, force_refresh=False, context=None):
        captured["value"] = value
        captured["context"] = context
        return {"status": "found", "hash": value, "cached": False}

    monkeypatch.setattr(services.virustotal, "lookup_hash", fake_lookup)
    result = services.registry_browser.amcache_lookup_virustotal(
        record, hive_id, amcache["record_id"]
    )
    assert captured["value"] == SHA1
    assert captured["context"]["hive_id"] == hive_id
    assert "path" not in captured["context"]
    assert result["amcache_record_id"] == amcache["record_id"]
    services.cleanup()


def test_recover_with_logs_is_reported_unavailable(tmp_path, monkeypatch) -> None:
    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=header_bytes())
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records()
    FakeReader.fail = None
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    result = services.registry_browser.start_index(
        record, target, recover_with_logs=True
    )
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert any(
        "transaction_log_recovery_unavailable" in warning
        for warning in hive.warnings
    )
    assert hive.recovered is False
    services.cleanup()


def test_parser_timeout_marks_partial(tmp_path, monkeypatch) -> None:
    from dfir_browser.core.registry.reader import RegistryTimeoutError

    services, record = build_registry_services(tmp_path)
    stub_registry_extract(services, payload=header_bytes())
    monkeypatch.setattr(
        "dfir_browser.core.registry.service.HiveReader",
        lambda path, settings: FakeReader(path, settings),
    )
    FakeReader.records = normal_key_records()
    FakeReader.fail = RegistryTimeoutError("registry index build timed out")
    target = entry_id(services, "Windows/appcompat/Programs/Amcache.hve")
    result = services.registry_browser.start_index(record, target)
    hive = wait_hive(services, result["hive"]["hive_id"])
    assert hive.state == "partial"
    assert hive.error_code == "registry_timeout"
    services.cleanup()


def test_corrupt_regf_hive_raises_not_crash(tmp_path) -> None:
    from dfir_browser.core.registry.reader import HiveReader
    from dfir_browser.core.config import Settings
    from dfir_browser.core.registry.models import RegistryCorruptError

    payload = bytearray(header_bytes())
    # Point the root cell far beyond the truncated file.
    payload[36:40] = (0x100000).to_bytes(4, "little")
    path = tmp_path / "corrupt.hve"
    path.write_bytes(bytes(payload) + b"garbage" * 10)
    settings = Settings.from_env()
    reader = HiveReader(path, settings)
    with pytest.raises((RegistryCorruptError, __import__("dfir_browser.core.registry.models", fromlist=["RegistryError"]).RegistryError)):
        list(reader.walk(time.monotonic() + 5))
