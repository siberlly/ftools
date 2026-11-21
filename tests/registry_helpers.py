from __future__ import annotations

import dataclasses
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import INDEX_SCHEMA_VERSION
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.registry.index import RegistryStore
from dfir_browser.core.registry.models import (
    REGISTRY_SCHEMA_VERSION,
    RegistryHiveRecord,
)
from dfir_browser.core.registry.reader import KeyRecord, RawValue, decode_value
from dfir_browser.core.services import build_services

EVIDENCE = "ev_0123456789ab"
SCAN = "scan_registry"
SOURCE_SHA = "c" * 64
SCANNER = "registry-test-scanner"
GUID = "{11517B7C-E79D-4e20-961B-75A811715ADD}"
SHA1 = "fa1002b02fc5551e075ec44bb4ff9cc13d563dcf"

REGISTRY_ROWS = [
    ("Windows/System32/config/SYSTEM", "SYSTEM", 100, 11010048, False),
    ("Windows/System32/config/SOFTWARE", "SOFTWARE", 101, 1024, False),
    ("Windows/System32/config/SAM", "SAM", 102, 65536, False),
    ("Windows/System32/config/SECURITY", "SECURITY", 103, 65536, False),
    ("Users/IEUser/NTUSER.DAT", "NTUSER.DAT", 104, 1024, False),
    (
        "Users/IEUser/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "UsrClass.dat",
        105,
        1024,
        False,
    ),
    ("Windows/appcompat/Programs/Amcache.hve", "Amcache.hve", 200, 1024, False),
    (
        "Windows/appcompat/Programs/Amcache.hve.LOG1",
        "Amcache.hve.LOG1",
        201,
        512,
        False,
    ),
    ("Users/Public/Downloads/old.hve", "old.hve", 202, 1024, True),
    ("Users/Public/Downloads/SysInternals.exe", "SysInternals.exe", 900, 57344, True),
    (
        "Windows/System32/winevt/Logs/Security.evtx",
        "Security.evtx",
        300,
        69632,
        False,
    ),
    (
        "Windows/System32/winevt/Logs/System.evtx",
        "System.evtx",
        301,
        69632,
        False,
    ),
    (
        "Windows/System32/winevt/Logs/"
        "Microsoft-Windows-PowerShell%4Operational.evtx",
        "Microsoft-Windows-PowerShell%4Operational.evtx",
        302,
        69632,
        False,
    ),
    (
        "Windows/System32/winevt/Logs/Deleted.evtx",
        "Deleted.evtx",
        303,
        69632,
        True,
    ),
    (
        "Users/Public/Downloads/notes.txt",
        "notes.txt",
        304,
        64,
        False,
    ),
]


def _row(full_path, name, inode, size, deleted):
    if deleted:
        parent = full_path.rsplit("/", 1)[0] if "/" in full_path else ""
    else:
        parent = full_path.rsplit("/", 1)[0] if "/" in full_path else ""
    return (
        EVIDENCE,
        SCAN,
        full_path,
        parent,
        name,
        name.rsplit(".", 1)[-1].lower() if "." in name else "",
        inode,
        1,
        128,
        "-/r" if deleted else "-/-",
        "file",
        0 if deleted else 1,
        1 if deleted else 0,
        size,
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "hash",
        None,
    )


def make_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EVIDENCE,
        resolved_source_path="/evidence/sample.E01",
        filename="sample.E01",
        extension=".e01",
        source_sha256=SOURCE_SHA,
        source_size=1024,
        source_mtime_ns=1,
        format="EWF",
        media_size=1024,
        sector_size=512,
        md5=None,
        sha1=None,
        ewfinfo_version="20200101",
        ewfinfo_duration_ms=1.0,
        ewfinfo_command={},
        raw_exposure_path="/raw/exposure",
        exposure_mode="explicit",
        exposure_verified_at="2020-01-01T00:00:00Z",
        exposure_details={},
        layout=Layout(
            scope="volume", filesystem="NTFS", offset_sectors=0, method="fsstat"
        ),
        registered_at="2020-01-01T00:00:00Z",
        status="ready",
        warnings=[],
    )


def build_registry_services(tmp_path: Path):
    index_path = tmp_path / "index" / "filesystem.db"
    store = IndexStore(index_path)
    store.ensure_schema()
    store.begin_scan(
        EVIDENCE,
        SCAN,
        {
            "source_sha256": SOURCE_SHA,
            "raw_exposure_path": "/raw/exposure",
            "filesystem": "NTFS",
            "offset_sectors": 0,
            "fls_version": "",
            "index_schema_version": INDEX_SCHEMA_VERSION,
            "scanner_version": SCANNER,
        },
        "2020-01-01T00:00:00Z",
    )
    rows = [
        _row(path, name, inode, size, deleted)
        for path, name, inode, size, deleted in REGISTRY_ROWS
    ]
    store.insert_entries(rows)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(rows),
        entries_indexed=len(rows),
        parse_errors=0,
        deleted_files=sum(1 for row in rows if row[12]),
        deleted_directories=0,
        allocated_files=sum(1 for row in rows if not row[12]),
        allocated_directories=0,
        error_code=None,
        error_message=None,
    )
    settings = dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=index_path,
        triage_db_path=tmp_path / "var" / "cases" / "triage.db",
        virustotal_db_path=tmp_path / "var" / "cases" / "virustotal.db",
        virustotal_secret_dir=tmp_path / "var" / "secrets",
        registry_db_path=tmp_path / "var" / "cases" / "registry.db",
        evtx_db_path=tmp_path / "var" / "cases" / "evtx.db",
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        secret_key_path=tmp_path / "var" / "secret.key",
        auto_index=False,
        index_scanner_version=SCANNER,
        registry_max_value_bytes=1024,
        registry_max_text_length=128,
        registry_binary_preview_bytes=16,
    )
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    return services, make_record()


def entry_id(services, path):
    return services.indexer.resolve_entry_path(make_record(), path).id


def stub_registry_extract(services, *, payload=b"regf" + b"\x00" * 4092):
    calls = []

    def extract(image_path, evidence_id, inode, case_id, offset_sectors=0, **kwargs):
        exports = services.policy.case_exports_dir(case_id)
        path = exports / f"registry_{inode}_{len(calls)}.hve"
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        calls.append(path)
        return SimpleNamespace(output_path=str(path), inode=inode)

    services.filesystem.extract = extract
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    return calls


def value(name, type_id, raw):
    return decode_value(
        name,
        type_id,
        raw,
        max_value_bytes=1024,
        max_text_length=256,
        preview_bytes=16,
    )


def amcache_key_records() -> list[KeyRecord]:
    """Synthetic modern + legacy Amcache keys (no real hive data)."""
    root = KeyRecord(
        path=GUID,
        name=GUID,
        parent_path=None,
        depth=0,
        last_write_time="2020-01-01T00:00:00Z",
        subkey_count=1,
        value_count=0,
        subkeys=[],
        values=[],
    )
    root_key = KeyRecord(
        path=f"{GUID}\\Root",
        name="Root",
        parent_path=GUID,
        depth=1,
        last_write_time="2020-01-01T00:00:00Z",
        subkey_count=2,
        value_count=0,
        subkeys=[],
        values=[],
    )
    inventory = KeyRecord(
        path=f"{GUID}\\Root\\InventoryApplicationFile",
        name="InventoryApplicationFile",
        parent_path=f"{GUID}\\Root",
        depth=2,
        last_write_time="2020-01-01T00:00:00Z",
        subkey_count=1,
        value_count=0,
        subkeys=[],
        values=[],
    )
    modern = KeyRecord(
        path=f"{GUID}\\Root\\InventoryApplicationFile\\sysinternals.exe|1a80e611058c98e5",
        name="sysinternals.exe|1a80e611058c98e5",
        parent_path=f"{GUID}\\Root\\InventoryApplicationFile",
        depth=3,
        last_write_time="2022-11-15T21:19:01Z",
        subkey_count=0,
        value_count=10,
        subkeys=[],
        values=[
            value("Name", 1, "SysInternals.exe".encode("utf-16le") + b"\x00\x00"),
            value(
                "LowerCaseLongPath",
                1,
                "c:\\users\\public\\downloads\\sysinternals.exe".encode("utf-16le")
                + b"\x00\x00",
            ),
            value("FileId", 1, ("0000" + SHA1).encode("utf-16le") + b"\x00\x00"),
            value("Size", 11, (57344).to_bytes(8, "little")),
            value("Publisher", 1, "sysinternals, inc.".encode("utf-16le") + b"\x00\x00"),
            value("ProductName", 1, "suite".encode("utf-16le") + b"\x00\x00"),
            value("BinFileVersion", 1, "2.0.0.1".encode("utf-16le") + b"\x00\x00"),
            value("LinkDate", 1, "11/18/2020 19:09:04".encode("utf-16le") + b"\x00\x00"),
            value("ProgramId", 1, "0006d7bf".encode("utf-16le") + b"\x00\x00"),
            value("BinaryType", 1, "pe32_i386".encode("utf-16le") + b"\x00\x00"),
        ],
    )
    legacy_root = KeyRecord(
        path=f"{GUID}\\Root\\File",
        name="File",
        parent_path=f"{GUID}\\Root",
        depth=2,
        last_write_time="2020-01-01T00:00:00Z",
        subkey_count=1,
        value_count=0,
        subkeys=[],
        values=[],
    )
    legacy = KeyRecord(
        path=f"{GUID}\\Root\\File\\{{VOL}}\\legacyexe",
        name="legacyexe",
        parent_path=f"{GUID}\\Root\\File\\{{VOL}}",
        depth=4,
        last_write_time="2019-01-01T00:00:00Z",
        subkey_count=0,
        value_count=4,
        subkeys=[],
        values=[
            value("0", 1, "c:\\legacy.exe".encode("utf-16le") + b"\x00\x00"),
            value("1", 4, (2048).to_bytes(4, "little")),
            value("100", 1, "program-id".encode("utf-16le") + b"\x00\x00"),
            value("101", 1, ("A" * 40).encode("utf-16le") + b"\x00\x00"),
        ],
    )
    return [root, root_key, inventory, modern, legacy_root, legacy]


def normal_key_records() -> list[KeyRecord]:
    return [
        KeyRecord(
            path=GUID,
            name=GUID,
            parent_path=None,
            depth=0,
            last_write_time="2020-01-01T00:00:00Z",
            subkey_count=1,
            value_count=0,
            subkeys=[],
            values=[],
        ),
        KeyRecord(
            path=f"{GUID}\\Root",
            name="Root",
            parent_path=GUID,
            depth=1,
            last_write_time="2020-01-01T00:00:00Z",
            subkey_count=1,
            value_count=1,
            subkeys=[],
            values=[value("DisplayName", 1, "Hello Unicode 日本語".encode("utf-16le") + b"\x00\x00")],
        ),
        KeyRecord(
            path=f"{GUID}\\Root\\Child",
            name="Child",
            parent_path=f"{GUID}\\Root",
            depth=2,
            last_write_time="2020-01-01T00:00:00Z",
            subkey_count=0,
            value_count=5,
            subkeys=[],
            values=[
                value("Dword", 4, (42).to_bytes(4, "little")),
                value("BigEndian", 5, (42).to_bytes(4, "big")),
                value("Qword", 11, (123456789).to_bytes(8, "little")),
                value("Multi", 7, "a\x00b\x00\x00".encode("utf-16le")),
                value("Binary", 3, b"\x00\x01\x02" * 20),
            ],
        ),
    ]


def make_hive_row(hive_id="hive_0123456789abcdef", entryid=200):
    return RegistryHiveRecord(
        hive_id=hive_id,
        evidence_id=EVIDENCE,
        entry_id=entryid,
        inode=200,
        path="Windows/appcompat/Programs/Amcache.hve",
        name="Amcache.hve",
        hive_type="amcache",
        owner=None,
        size=1024,
        sha256="a" * 64,
        extract_relpath="cases/case01/exports/registry.hve",
        state="ready",
        phase="ready",
        dirty=False,
        sequence1=1,
        sequence2=1,
        recovered=False,
        parser_version="test-parser",
        schema_version=REGISTRY_SCHEMA_VERSION,
        sensitive=False,
        signature_status="valid",
        transaction_logs=["Amcache.hve.LOG1"],
        warnings=[],
        key_count=0,
        value_count=0,
        amcache_count=0,
        created_at="2020-01-01T00:00:00Z",
        finished_at="2020-01-01T00:00:00Z",
    )


def seed_hive(services, records=None) -> str:
    records = records or (normal_key_records() + amcache_key_records())
    store: RegistryStore = services.registry_store
    hive = make_hive_row()
    store.upsert_hive(hive)
    keys, values, amcache, error = store.index_hive(hive.hive_id, iter(records))
    assert error is None
    hive.key_count = keys
    hive.value_count = values
    hive.amcache_count = len(amcache)
    store.finish_hive(hive)
    return hive.hive_id
