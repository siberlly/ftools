"""Synthetic fixtures for the read-only file preview.

All payloads are generated here; no real evidence content is committed. The
only exception is the hosts fixture, which is the standard Microsoft sample
text plus two synthetic mappings used by the tests.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import INDEX_SCHEMA_VERSION
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.registry.index import RegistryStore
from dfir_browser.core.registry.models import RegistryHiveRecord
from dfir_browser.core.services import build_services

EVIDENCE = "ev_0123456789ab"
SCAN = "scan_preview"
SOURCE_SHA = "e" * 64
SCANNER = "preview-test-scanner"

HOSTS_PATH = "Windows/System32/drivers/etc/hosts"
AMCACHE_PATH = "Windows/appcompat/Programs/Amcache.hve"
SYSTEM_PATH = "Windows/System32/config/SYSTEM"
TEXT_PATH = "Users/IEUser/Documents/notes.txt"
BIG_PATH = "Users/IEUser/Documents/big.log"
BINARY_PATH = "Users/IEUser/Documents/sample.bin"
SCRIPT_PATH = "Users/IEUser/Documents/evil.html"
DEEP_PATH = "Users/IEUser/Documents/deep.txt"
DIR_PATH = "Users/IEUser/Documents"

HOSTS_TEXT = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\n"
    "#\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
    "#\n"
    "192.168.15.10\twww.malware430.com\n"
    "192.168.15.10\twww.sysinternals.com\n"
)


def _row(
    full_path, name, inode, size, deleted=False, entry_type="file",
    fls_type=None,
):
    parent = full_path.rsplit("/", 1)[0] if "/" in full_path else ""
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return (
        EVIDENCE,
        SCAN,
        full_path,
        parent,
        name,
        extension,
        inode,
        1,
        128,
        fls_type or ("-/r" if deleted else "-/-"),
        entry_type,
        0 if deleted else 1,
        1 if deleted else 0,
        0 if entry_type == "directory" else size,
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "2020-01-01T00:00:00",
        "hash",
        None,
    )


def rows_for(payloads: dict[int, bytes]) -> list[tuple]:
    specs = [
        (HOSTS_PATH, "hosts", 42564),
        (AMCACHE_PATH, "Amcache.hve", 50001),
        (SYSTEM_PATH, "SYSTEM", 50002),
        (TEXT_PATH, "notes.txt", 50010),
        (BIG_PATH, "big.log", 50011),
        (BINARY_PATH, "sample.bin", 50012),
        (SCRIPT_PATH, "evil.html", 50013),
        (DEEP_PATH, "deep.txt", 50014),
    ]
    rows = []
    for path, name, inode in specs:
        data = payloads.get(inode, b"")
        rows.append(_row(path, name, inode, len(data)))
    # A directory entry for the "directory rejected" test.
    rows.append(_row(DIR_PATH, "Documents", 50020, 0, entry_type="directory"))
    # A file with an invalid (negative) inode.
    rows.append(_row("Users/IEUser/Documents/negative.txt", "negative.txt", -5, 4))
    return rows


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


def build_preview_services(
    tmp_path: Path, payloads: dict[int, bytes], *, rows=None, **overrides
):
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
    inserted = rows if rows is not None else rows_for(payloads)
    store.insert_entries(inserted)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(inserted),
        entries_indexed=len(inserted),
        parse_errors=0,
        deleted_files=sum(1 for row in inserted if row[12]),
        deleted_directories=0,
        allocated_files=sum(1 for row in inserted if row[10] == "file" and not row[12]),
        allocated_directories=sum(
            1 for row in inserted if row[10] == "directory" and not row[12]
        ),
        error_code=None,
        error_message=None,
    )
    settings_kwargs = dict(
        var_dir=tmp_path / "var",
        index_db_path=index_path,
        triage_db_path=tmp_path / "var" / "cases" / "triage.db",
        virustotal_db_path=tmp_path / "var" / "cases" / "virustotal.db",
        virustotal_secret_dir=tmp_path / "var" / "secrets",
        registry_db_path=tmp_path / "var" / "cases" / "registry.db",
        evtx_db_path=tmp_path / "var" / "cases" / "evtx.db",
        browser_db_path=tmp_path / "var" / "cases" / "browser_artifacts.db",
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        secret_key_path=tmp_path / "var" / "secret.key",
        auto_index=False,
        index_scanner_version=SCANNER,
    )
    settings_kwargs.update(overrides)
    settings = dataclasses.replace(Settings.from_env(), **settings_kwargs)
    services = build_services(settings)
    services.indexer._fls_version_cache = ""
    services.evidence.registry.upsert(make_record().to_dict())
    return services, make_record()


def entry_id(services, path):
    return services.indexer.resolve_entry_path(make_record(), path).id


def stub_preview_extract(services, payloads: dict[int, bytes]):
    """Write synthetic payloads into the case export directory as extractions."""
    calls: list[Path] = []

    def extract(image_path, evidence_id, inode, case_id, offset_sectors=0, **kwargs):
        exports = services.policy.case_exports_dir(case_id)
        path = exports / f"inode_{inode}_{len(calls)}.bin"
        payload = payloads.get(inode, b"")
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        sidecar = path.with_name(path.name + ".provenance.json")
        sidecar.write_text(
            json.dumps(
                {
                    "inode": inode,
                    "evidence_id": evidence_id,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "case_id": case_id,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(sidecar, 0o600)
        calls.append(path)
        return SimpleNamespace(
            output_path=str(path),
            inode=inode,
            sha256=hashlib.sha256(payload).hexdigest(),
        )

    services.filesystem.extract = extract
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    return calls


def regf_header(
    *,
    primary: int = 42,
    secondary: int = 42,
    major: int = 1,
    minor: int = 5,
    bins_size: int = 4096,
) -> bytes:
    header = bytearray(512)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 4, primary)
    struct.pack_into("<I", header, 8, secondary)
    struct.pack_into("<Q", header, 12, 131974739824631689)
    struct.pack_into("<I", header, 20, major)
    struct.pack_into("<I", header, 24, minor)
    struct.pack_into("<I", header, 36, 32)
    struct.pack_into("<I", header, 40, bins_size)
    return bytes(header)


def hive_payload(
    size: int = 8192, *, primary: int = 42, secondary: int = 42
) -> bytes:
    head = regf_header(primary=primary, secondary=secondary)
    return head + b"\x00" * (size - len(head))


def index_hive(services, entry_id_value: int, *, state: str = "ready") -> str:
    """Record an indexed hive without running the real parser."""
    from dfir_browser.core.registry.models import hive_id_for

    hive_id = hive_id_for(EVIDENCE, entry_id_value)
    record = RegistryHiveRecord(
        hive_id=hive_id,
        evidence_id=EVIDENCE,
        entry_id=entry_id_value,
        inode=50001,
        path=AMCACHE_PATH,
        name="Amcache.hve",
        hive_type="amcache",
        owner=None,
        size=8192,
        sha256="0" * 64,
        extract_relpath=None,
        state=state,
        phase="ready",
        dirty=False,
        sequence1=42,
        sequence2=42,
        recovered=False,
        parser_version="test",
        schema_version=1,
        sensitive=False,
        signature_status="valid",
    )
    services.registry_store.upsert_hive(record)
    return hive_id
