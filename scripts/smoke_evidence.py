#!/usr/bin/env python3
"""Smoke-test the DFIR core against the real E01 evidence (read-only)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dfir_browser.core.config import EwfMapping, Settings  # noqa: E402
from dfir_browser.core.services import build_services  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        default="/home/ubuntu/test/temp_extract_dir/SysInternals.E01",
    )
    parser.add_argument(
        "--exposure", default="/home/ubuntu/mnt/ewf/ewf1"
    )
    parser.add_argument("--allowlist", default="/home/ubuntu/test:/home/ubuntu/evidence")
    parser.add_argument("--var-dir", default=str(PROJECT_ROOT / "var" / "smoke"))
    parser.add_argument("--case", default="smoke")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    evidence = Path(args.evidence).resolve()
    exposure = Path(args.exposure).resolve()
    if not evidence.is_file():
        raise SystemExit(f"evidence not found: {evidence}")
    if not exposure.is_file():
        raise SystemExit(f"raw exposure not found: {exposure}")

    before_stat = evidence.stat()
    before_hash = sha256_file(evidence)
    print(
        f"[before] sha256={before_hash} size={before_stat.st_size} "
        f"mtime_ns={before_stat.st_mtime_ns}"
    )

    settings = Settings.from_env(
        var_dir=Path(args.var_dir),
        allowed_roots=tuple(
            Path(item) for item in args.allowlist.split(":") if item.strip()
        ),
        ewf_mappings={
            str(evidence): EwfMapping(
                exposure=str(exposure),
                source_sha256=before_hash,
                media_size=14720958464,
            )
        },
        ewf_automount=False,
        command_timeout=60.0,
        extract_timeout=300.0,
    )
    services = build_services(settings)

    record = services.evidence.register(str(evidence))
    print(
        json.dumps(
            {
                "evidence_id": record.evidence_id,
                "resolved_source_path": record.resolved_source_path,
                "source_sha256": record.source_sha256,
                "source_size": record.source_size,
                "source_mtime_ns": record.source_mtime_ns,
                "format": record.format,
                "media_size": record.media_size,
                "sector_size": record.sector_size,
                "md5": record.md5,
                "sha1": record.sha1,
                "raw_exposure_path": record.raw_exposure_path,
                "exposure_mode": record.exposure_mode,
                "exposure_verified_at": record.exposure_verified_at,
                "layout": record.layout.to_dict(),
                "warnings": record.warnings,
            },
            indent=2,
        )
    )
    assert record.resolved_source_path == str(evidence), record.resolved_source_path
    assert record.source_sha256 == before_hash, record.source_sha256
    assert record.source_size == before_stat.st_size, record.source_size
    assert record.source_mtime_ns == before_stat.st_mtime_ns
    assert record.layout.scope == "volume", record.layout
    assert record.layout.filesystem == "NTFS", record.layout
    assert record.layout.offset_sectors == 0, record.layout
    assert record.layout.method == "fsstat", record.layout
    assert record.exposure_mode == "explicit", record.exposure_mode
    assert record.raw_exposure_path == str(exposure), record.raw_exposure_path
    assert record.exposure_verified_at, record.exposure_verified_at
    assert record.md5 == "cc5807fa709ac4517160841f9480bad8", record.md5
    assert record.sha1 == "7a905de84e1dcf37d3cbb72a18ddfce01e0c5729", record.sha1

    image = services.evidence.ensure_image(record)
    assert image.resolve() == exposure
    print(f"[exposure] {image} (mode={record.exposure_mode})")

    root = services.filesystem.list_directory(
        image, record.evidence_id, inode=5, offset_sectors=0
    )
    assert root.complete is True, root.to_dict()
    assert root.truncated is False, root.to_dict()
    users = next(entry for entry in root.entries if entry.name == "Users")
    assert users.inode == 1746, users
    assert users.entry_type == "directory", users
    print(
        f"[root] complete={root.complete} truncated={root.truncated} "
        f"Users inode={users.inode} deleted={users.deleted} size={users.size}"
    )

    user_dir = services.filesystem.list_directory(
        image, record.evidence_id, inode=1746, offset_sectors=0
    )
    ieuser = next(entry for entry in user_dir.entries if entry.name == "IEUser")
    assert ieuser.inode == 83437, ieuser
    assert ieuser.entry_type == "directory", ieuser
    print(
        f"[inode 1746] complete={user_dir.complete} "
        f"IEUser inode={ieuser.inode} deleted={ieuser.deleted}"
    )

    users_meta = services.filesystem.stat(
        image, record.evidence_id, inode=1746, offset_sectors=0
    )
    assert users_meta.summary["is_directory"] is True
    assert users_meta.summary["name"] == "Users"
    assert users_meta.to_dict()["trust"] == "untrusted_evidence_data"
    print(f"[stat 1746] name={users_meta.summary['name']} directory=true")

    bootnxt = services.filesystem.stat(
        image, record.evidence_id, inode=60021, offset_sectors=0
    )
    assert bootnxt.summary["name"] == "BOOTNXT"
    print(
        f"[stat 60021] name={bootnxt.summary['name']} "
        f"size={bootnxt.summary['data_size']}"
    )

    extraction = services.filesystem.extract(
        image, record.evidence_id, inode=60021, case_id=args.case, offset_sectors=0
    )
    output = Path(extraction.output_path)
    assert extraction.size == 1, extraction
    assert output.read_bytes() == b"\x00", output
    assert extraction.sha256 == hashlib.sha256(b"\x00").hexdigest()
    assert extraction.untrusted is True
    assert extraction.to_dict()["trust"] == "untrusted_evidence_data"
    print(
        json.dumps(
            {
                "extraction": {
                    "inode": extraction.inode,
                    "name": extraction.name,
                    "output_path": extraction.output_path,
                    "relative_path": extraction.relative_path,
                    "size": extraction.size,
                    "sha256": extraction.sha256,
                    "tool_version": extraction.tool_version,
                    "untrusted": extraction.untrusted,
                    "warnings": extraction.warnings,
                }
            },
            indent=2,
        )
    )

    after_stat = evidence.stat()
    after_hash = sha256_file(evidence)
    print(
        f"[after]  sha256={after_hash} size={after_stat.st_size} "
        f"mtime_ns={after_stat.st_mtime_ns}"
    )
    assert before_hash == after_hash, "EVIDENCE CHANGED"
    assert before_stat.st_size == after_stat.st_size, "EVIDENCE SIZE CHANGED"
    assert before_stat.st_mtime_ns == after_stat.st_mtime_ns, (
        "EVIDENCE MTIME CHANGED"
    )
    print("[ok] evidence unchanged; all smoke assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
