from __future__ import annotations

import hashlib
import os
import stat as stat_module
from pathlib import Path

import pytest

from dfir_browser.core.config import EwfMapping, Settings
from dfir_browser.core.filesystem import ExtractionError
from dfir_browser.core.policy import PolicyError
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


@pytest.mark.skipif(SKIP_REASON is not None, reason=SKIP_REASON or "")
def test_real_evidence_end_to_end(tmp_path: Path) -> None:
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
        command_timeout=60.0,
        extract_timeout=120.0,
        max_metadata_bytes=65536,
    )
    services = build_services(settings)
    record = services.evidence.register(str(EVIDENCE))

    assert record.evidence_id.startswith("ev_")
    assert record.resolved_source_path == str(EVIDENCE.resolve())
    assert record.source_sha256 == before_hash
    assert record.source_size == before_stat.st_size
    assert record.source_mtime_ns == before_stat.st_mtime_ns
    assert record.format == "FTK Imager"
    assert record.media_size == 14720958464
    assert record.sector_size == 512
    assert record.md5 == "cc5807fa709ac4517160841f9480bad8"
    assert record.sha1 == "7a905de84e1dcf37d3cbb72a18ddfce01e0c5729"
    assert record.layout.scope == "volume"
    assert record.layout.filesystem == "NTFS"
    assert record.layout.offset_sectors == 0
    assert record.layout.method == "fsstat"
    assert any("mmls" in warning for warning in record.layout.warnings)
    assert record.exposure_mode == "explicit"
    assert record.raw_exposure_path == str(EWF1.resolve())
    assert record.exposure_verified_at
    assert record.exposure_details.get("read_only") is True
    assert record.exposure_details.get("fsstat", {}).get("filesystem") == "NTFS"
    assert services.provider.managed_mounts == set()

    image = services.evidence.ensure_image(record)
    assert image.resolve() == EWF1.resolve()

    root = services.filesystem.list_directory(
        image, record.evidence_id, inode=5, offset_sectors=0
    )
    assert root.complete is True
    assert root.truncated is False
    assert root.warning is None
    users = [entry for entry in root.entries if entry.name == "Users"]
    assert users, "root listing must contain Users"
    assert users[0].inode == 1746
    assert users[0].entry_type == "directory"
    assert any(entry.deleted for entry in root.entries)

    user_dir = services.filesystem.list_directory(
        image, record.evidence_id, inode=1746, offset_sectors=0
    )
    ieuser = [entry for entry in user_dir.entries if entry.name == "IEUser"]
    assert ieuser, "inode 1746 listing must contain IEUser"
    assert ieuser[0].inode == 83437
    assert ieuser[0].entry_type == "directory"
    assert user_dir.breadcrumb == [
        {"inode": 5, "name": "/"},
        {"inode": 1746, "name": "Users"},
    ]

    users_meta = services.filesystem.stat(
        image, record.evidence_id, inode=1746, offset_sectors=0
    )
    assert users_meta.summary["is_directory"] is True
    assert users_meta.summary["name"] == "Users"
    assert users_meta.raw
    assert len(users_meta.raw) <= settings.max_metadata_bytes

    bootmgr_meta = services.filesystem.stat(
        image, record.evidence_id, inode=60734, offset_sectors=0
    )
    assert bootmgr_meta.summary["name"] == "bootmgr"
    assert bootmgr_meta.summary["is_directory"] is False
    assert bootmgr_meta.summary["data_size"] == 408364
    assert bootmgr_meta.tool_version is not None

    extraction = services.filesystem.extract(
        image, record.evidence_id, inode=60021, case_id="smoke", offset_sectors=0
    )
    output = Path(extraction.output_path)
    assert extraction.untrusted is True
    assert extraction.size == 1
    assert output.read_bytes() == b"\x00"
    assert extraction.sha256 == hashlib.sha256(b"\x00").hexdigest()
    assert output.is_relative_to(settings.var_dir)
    assert output.is_relative_to(settings.var_dir / "cases" / "smoke" / "exports")
    assert stat_module.S_IMODE(output.stat().st_mode) == 0o600
    assert Path(str(output) + ".provenance.json").is_file()
    assert extraction.tool_version is not None
    assert "Sleuth Kit" in extraction.tool_version

    with pytest.raises(ExtractionError, match="directory"):
        services.filesystem.extract(
            image, record.evidence_id, inode=1746, case_id="smoke", offset_sectors=0
        )
    with pytest.raises(PolicyError):
        services.filesystem.extract(
            image, record.evidence_id, inode=60021, case_id="../evil", offset_sectors=0
        )
    with pytest.raises(PolicyError):
        services.filesystem.stat(
            image, record.evidence_id, inode="5; rm -rf /", offset_sectors=0
        )

    after_stat = EVIDENCE.stat()
    after_hash = sha256_file(EVIDENCE)
    assert before_hash == after_hash, "evidence content changed"
    assert before_stat.st_size == after_stat.st_size
    assert before_stat.st_mtime_ns == after_stat.st_mtime_ns
    assert stat_module.S_IMODE(before_stat.st_mode) == stat_module.S_IMODE(
        after_stat.st_mode
    )
