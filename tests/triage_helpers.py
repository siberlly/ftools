from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import struct
import time
from pathlib import Path
from types import SimpleNamespace

from dfir_browser.core.config import Settings
from dfir_browser.core.index_models import INDEX_SCHEMA_VERSION
from dfir_browser.core.index_store import IndexStore
from dfir_browser.core.models import EvidenceRecord, Layout

EVIDENCE = "ev_0123456789ab"
SCAN = "scan_triage"
SOURCE_SHA = "c" * 64
SCANNER = "triage-test-scanner"


def minimal_pe32() -> bytes:
    """A tiny, valid, harmless PE32 image with one .text section."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0x5F000000, 0, 0, 0xE0, 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into(
        "<HBBIIIII", optional, 0, 0x10B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000
    )
    struct.pack_into("<I", optional, 28, 0x400000)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<I", optional, 92, 16)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    image = bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + section
    image += b"\x00" * (0x200 - len(image))
    image += b"\xCC" * 0x200
    return image


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


def _row(
    full_path: str,
    entry_type: str,
    *,
    inode: int,
    size: int | None,
    deleted: bool = False,
    parent: str | None = None,
    modified: str | None = "2020-01-01T00:00:00",
):
    if parent is not None:
        parent_path = parent
    elif "/" in full_path:
        parent_path = full_path.rsplit("/", 1)[0]
    else:
        parent_path = ""
    basename = full_path.rsplit("/", 1)[-1]
    return (
        EVIDENCE,
        SCAN,
        full_path,
        parent_path,
        basename,
        basename.rsplit(".", 1)[-1].lower() if "." in basename else "",
        inode,
        1,
        128,
        "-/r" if deleted else "-/-",
        entry_type,
        0 if deleted else 1,
        1 if deleted else 0,
        size,
        modified,
        modified,
        modified,
        modified,
        "hash",
        None,
    )


def install_rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    source = Path(__file__).resolve().parents[1] / "rules" / "yara" / "test-fixture.yar"
    (rules / "test-fixture.yar").write_text(source.read_text())
    return rules


def build_services(
    tmp_path: Path,
    payload: bytes,
    *,
    filename: str = "sample.bin",
    deleted: bool = False,
    extra_payload: bytes | None = None,
    **overrides,
) -> tuple[object, EvidenceRecord, int]:
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
        _row("Files", "directory", inode=800, size=None),
        _row(
            f"Files/{filename}",
            "file",
            inode=900,
            size=len(payload),
            deleted=deleted,
        ),
    ]
    if extra_payload is not None:
        rows.append(
            _row("Files/other.bin", "file", inode=901, size=len(extra_payload))
        )
    store.insert_entries(rows)
    store.link_tree(EVIDENCE, SCAN)
    store.finish_scan(
        EVIDENCE,
        SCAN,
        status="ready",
        entries_seen=len(rows),
        entries_indexed=len(rows),
        parse_errors=0,
        deleted_files=1 if deleted else 0,
        deleted_directories=0,
        allocated_files=0 if deleted else 1,
        allocated_directories=1,
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
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        secret_key_path=tmp_path / "var" / "secret.key",
        auto_index=False,
        index_scanner_version=SCANNER,
        triage_yara_rules_dir=install_rules(tmp_path),
        triage_analyzer_timeout=10.0,
        triage_job_timeout=60.0,
        triage_yara_timeout=10.0,
        **overrides,
    )
    built = _build(settings)
    built.indexer._fls_version_cache = ""
    built.evidence.registry.upsert(make_record().to_dict())
    entry = built.indexer.resolve_entry_path(
        make_record(), f"Files/{filename}"
    )
    return built, make_record(), entry.id


def _build(settings: Settings):
    from dfir_browser.core.services import build_services as real_build

    return real_build(settings)


def stub_extraction(
    services,
    payload: bytes,
    *,
    block: object | None = None,
    mode: int = 0o600,
    by_inode: dict[int, bytes] | None = None,
) -> list[Path]:
    calls: list[Path] = []

    def extract(
        image_path,
        evidence_id,
        inode,
        case_id,
        offset_sectors=0,
        **kwargs,
    ):
        if block is not None:
            block.wait(15)
        exports = services.policy.case_exports_dir(case_id)
        path = exports / f"inode_{inode}_{len(calls)}.bin"
        content = by_inode.get(int(inode), payload) if by_inode else payload
        path.write_bytes(content)
        os.chmod(path, mode)
        sidecar = path.with_name(path.name + ".provenance.json")
        sidecar.write_text(
            json.dumps(
                {
                    "evidence_id": evidence_id,
                    "case_id": case_id,
                    "inode": int(inode),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                    "relative_path": str(path),
                }
            ),
            encoding="utf-8",
        )
        os.chmod(sidecar, 0o600)
        calls.append(path)
        return SimpleNamespace(
            output_path=str(path), relative_path=str(path), inode=inode
        )

    services.filesystem.extract = extract
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    return calls


def wait_job(services, job_id: str, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = services.triage.get_job(job_id)
        if job.status not in {"queued", "running"}:
            return job
        time.sleep(0.05)
    raise AssertionError(f"triage job {job_id} did not finish")


def sample_payload() -> bytes:
    text = (
        "DFIR_TRIAGE_TEST_MARKER\n"
        "https://example.com/path?q=1 192.168.1.10 user@example.org\n"
        "powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "C:\\Windows\\System32\\cmd.exe HKLM\\Software\\Run\n"
        "Global\\MyMutex123 UA Mozilla/5.0 (Windows NT 10.0)\n"
        "rundll32 regsvr32 mshta certutil taskmgr.exe\n"
    )
    return text.encode() + "DFIR_TRIAGE_TEST_MARKER".encode("utf-16le")
