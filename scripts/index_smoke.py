#!/usr/bin/env python3
"""Build the full filesystem index on real evidence and measure queries."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dfir_browser.core.config import EwfMapping, Settings  # noqa: E402
from dfir_browser.core.index_models import (  # noqa: E402
    DeletedFilesQuery,
    FileSearchQuery,
)
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
    parser.add_argument("--exposure", default="/home/ubuntu/mnt/ewf/ewf1")
    parser.add_argument("--allowlist", default="/home/ubuntu/test:/home/ubuntu/evidence")
    parser.add_argument("--var-dir", default=str(PROJECT_ROOT / "var" / "index-smoke"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    evidence = Path(args.evidence).resolve()
    exposure = Path(args.exposure).resolve()
    var_dir = Path(args.var_dir).resolve()
    allowed_roots = tuple(
        Path(item).resolve()
        for item in args.allowlist.split(":")
        if item.strip()
    )
    if not evidence.is_file():
        raise SystemExit(f"evidence not found: {evidence}")
    if not exposure.is_file():
        raise SystemExit(f"raw exposure not found: {exposure}")
    if var_dir in {Path("/"), Path.home()}:
        raise SystemExit(f"refusing to use unsafe var dir: {var_dir}")
    if any(var_dir.is_relative_to(root) for root in allowed_roots):
        raise SystemExit(
            "refusing to delete a var dir inside an evidence allowlist root"
        )
    shutil.rmtree(var_dir, ignore_errors=True)

    before_stat = evidence.stat()
    before_hash = sha256_file(evidence)
    print(
        f"[before] sha256={before_hash} size={before_stat.st_size} "
        f"mtime_ns={before_stat.st_mtime_ns}"
    )

    settings = Settings.from_env(
        var_dir=var_dir,
        allowed_roots=allowed_roots,
        ewf_mappings={
            str(evidence): EwfMapping(
                exposure=str(exposure),
                source_sha256=before_hash,
                media_size=14720958464,
            )
        },
        ewf_automount=False,
        auto_index=False,
        index_timeout=300.0,
        index_batch_size=1000,
        index_page_size_default=100,
        index_page_size_max=500,
    )
    services = build_services(settings)

    register_start = time.perf_counter()
    record = services.evidence.register(str(evidence))
    register_s = time.perf_counter() - register_start

    scan_start = time.perf_counter()
    started = services.indexer.start_scan(record.evidence_id)
    assert started.started is True, started.to_dict()
    last_report = 0.0
    while True:
        status = services.indexer.status_for_record(record)
        if status.status != "running":
            break
        now = time.perf_counter()
        if now - last_report >= 2.0:
            print(
                f"[scan] status={status.status} seen={status.entries_seen} "
                f"indexed={status.entries_indexed} parse={status.parse_errors}"
            )
            last_report = now
        time.sleep(0.2)
    scan_wall_s = time.perf_counter() - scan_start
    assert status.status == "ready", status.to_dict()
    assert status.complete is True, status.to_dict()
    assert status.parse_errors == 0, status.to_dict()

    db_path = settings.index_database()
    db_size = db_path.stat().st_size
    wal_path = db_path.with_name(db_path.name + "-wal")
    if wal_path.exists():
        db_size += wal_path.stat().st_size

    root_start = time.perf_counter()
    root = services.indexer.list_directory(record, "", page=1, page_size=100)
    root_ms = (time.perf_counter() - root_start) * 1000.0

    users_start = time.perf_counter()
    users = services.indexer.list_directory(record, "Users", page=1, page_size=100)
    users_ms = (time.perf_counter() - users_start) * 1000.0

    deleted_first_query = DeletedFilesQuery.create(
        page=1,
        page_size=100,
        default_page_size=100,
        max_page_size=500,
    )
    deleted_first_start = time.perf_counter()
    deleted_first = services.indexer.list_deleted(record, deleted_first_query)
    deleted_first_ms = (time.perf_counter() - deleted_first_start) * 1000.0

    deleted_query = DeletedFilesQuery.create(
        search="Sysinternals.exe",
        page=1,
        page_size=100,
        default_page_size=100,
        max_page_size=500,
    )
    deleted_start = time.perf_counter()
    deleted = services.indexer.list_deleted(record, deleted_query)
    deleted_ms = (time.perf_counter() - deleted_start) * 1000.0

    search_query = FileSearchQuery.create(
        query="Sysinternals.exe",
        exact=True,
        deleted_only=True,
        page=1,
        page_size=100,
        default_page_size=100,
        max_page_size=500,
    )
    search_start = time.perf_counter()
    search = services.indexer.search(record, search_query)
    search_ms = (time.perf_counter() - search_start) * 1000.0

    deleted_paths = {entry.full_path: entry for entry in deleted.results}
    sysinternals_path = "Users/Public/Downloads/SysInternals.exe"
    assert sysinternals_path in deleted_paths, list(deleted_paths)
    sysinternals = deleted_paths[sysinternals_path]
    assert sysinternals.deleted is True
    assert sysinternals.allocated is False
    assert sysinternals.inode == 124567
    search_paths = {entry.full_path for entry in search.results}
    assert sysinternals_path in search_paths

    root_users = [entry for entry in root.entries if entry.name == "Users"]
    assert root_users and root_users[0].inode == 1746
    ieuser = [entry for entry in users.entries if entry.name == "IEUser"]
    assert ieuser and ieuser[0].inode == 83437

    after_stat = evidence.stat()
    after_hash = sha256_file(evidence)
    assert before_hash == after_hash, "EVIDENCE CHANGED"
    assert before_stat.st_size == after_stat.st_size, "EVIDENCE SIZE CHANGED"
    assert before_stat.st_mtime_ns == after_stat.st_mtime_ns, (
        "EVIDENCE MTIME CHANGED"
    )

    summary = {
        "register_s": round(register_s, 3),
        "index_wall_s": round(scan_wall_s, 3),
        "index_reported_elapsed_s": status.elapsed_seconds,
        "status": status.status,
        "complete": status.complete,
        "entries_seen": status.entries_seen,
        "entries_indexed": status.entries_indexed,
        "parse_errors": status.parse_errors,
        "deleted_files": status.deleted_files,
        "deleted_directories": status.deleted_directories,
        "allocated_files": status.allocated_files,
        "allocated_directories": status.allocated_directories,
        "db_size_bytes": db_size,
        "root_total": root.total,
        "root_query_ms": round(root_ms, 3),
        "users_query_ms": round(users_ms, 3),
        "deleted_first_page_ms": round(deleted_first_ms, 3),
        "deleted_first_page_total": deleted_first.total,
        "deleted_search_ms": round(deleted_ms, 3),
        "deleted_search_total": deleted.total,
        "search_query_ms": round(search_ms, 3),
        "search_total": search.total,
        "sysinternals": {
            "full_path": sysinternals.full_path,
            "inode": sysinternals.inode,
            "entry_type": sysinternals.entry_type,
            "allocated": sysinternals.allocated,
            "deleted": sysinternals.deleted,
            "size": sysinternals.size,
            "fls_type": sysinternals.fls_type,
        },
        "evidence_sha256_before": before_hash,
        "evidence_sha256_after": after_hash,
        "evidence_size": after_stat.st_size,
        "evidence_mtime_ns": after_stat.st_mtime_ns,
        "evidence_unchanged": True,
    }
    print(json.dumps(summary, indent=2))
    print("[ok] full filesystem index and query smoke test passed")
    services.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
