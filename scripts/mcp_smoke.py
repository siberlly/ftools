#!/usr/bin/env python3
"""Exercise the dfir-browser MCP server and full filesystem index over stdio."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "evidence_register",
    "evidence_inspect",
    "filesystem_list",
    "filesystem_stat",
    "filesystem_extract",
    "filesystem_index_start",
    "filesystem_index_status",
    "filesystem_list_deleted",
    "filesystem_search",
    "filesystem_list_tree_children",
    "filesystem_tree_ancestors",
    "start_file_triage",
    "get_file_triage",
    "lookup_file_hash_virustotal",
    "registry_list_hives",
    "registry_index_start",
    "registry_index_status",
    "registry_list_subkeys",
    "registry_get_key",
    "registry_search",
    "amcache_search",
    "amcache_compare_triage",
    "amcache_lookup_virustotal",
    "evtx_list_logs",
    "evtx_index_start",
    "evtx_index_status",
    "evtx_query_events",
    "evtx_get_event",
    "evtx_get_context",
    "evtx_activity_summary",
    "browser_list_artifacts",
    "browser_index_start",
    "browser_index_status",
    "browser_list_profiles",
    "browser_query_downloads",
    "browser_query_history",
    "browser_query_cache",
    "browser_search_all",
    "browser_get_record",
    "browser_correlate_download",
    "browser_activity_summary",
    "preview_file_content",
    "find_related_artifacts",
    "get_timeline_event",
    "get_timeline_index_status",
    "query_timeline",
    "recycle_bin_metadata",
    "browser_credential_stores",

    "preview_sqlite_table",

    "shellbags_get_node",
    "shellbags_index_start",
    "shellbags_index_status",
    "shellbags_list_devices",
    "shellbags_search",
    "shellbags_tree",

    "start_timeline_index",
}


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
    parser.add_argument("--var-dir", default=str(PROJECT_ROOT / "var" / "mcp-smoke"))
    parser.add_argument("--case", default="mcp-smoke")
    return parser.parse_args()


def error_text(result) -> str:
    parts = []
    for content in result.content:
        text = getattr(content, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts) or "tool error"


def error_payload(result) -> dict:
    text = error_text(result)
    start = text.find("{")
    if start >= 0:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            pass
    raise AssertionError(f"MCP error did not contain structured JSON: {text!r}")


def payload(result):
    if result.isError:
        raise RuntimeError(error_text(result))
    data = result.structuredContent
    if data is None:
        for content in result.content:
            text = getattr(content, "text", None)
            if not text:
                continue
            try:
                data = json.loads(text)
                break
            except json.JSONDecodeError:
                continue
    if isinstance(data, dict) and set(data.keys()) == {"result"}:
        data = data["result"]
    return data


async def wait_for_index(session: ClientSession, evidence_id: str) -> dict:
    deadline = time.monotonic() + 240.0
    last_report = 0.0
    while time.monotonic() < deadline:
        status = payload(
            await session.call_tool(
                "filesystem_index_status", {"evidence_id": evidence_id}
            )
        )
        if status["status"] != "running":
            return status
        now = time.monotonic()
        if now - last_report >= 2.0:
            print(
                f"[index] status={status['status']} "
                f"seen={status['entries_seen']} "
                f"indexed={status['entries_indexed']} "
                f"parse={status['parse_errors']}"
            )
            last_report = now
        await asyncio.sleep(0.5)
    raise AssertionError("MCP index scan did not finish within timeout")


async def run(args: argparse.Namespace) -> int:
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

    mapping_document = {
        "version": 1,
        "mappings": {
            str(evidence): {
                "exposure": str(exposure),
                "source_sha256": before_hash,
                "media_size": 14720958464,
            }
        },
    }

    env = os.environ.copy()
    env["DFIR_VAR_DIR"] = str(Path(args.var_dir).resolve())
    env["DFIR_EVIDENCE_ALLOWLIST"] = args.allowlist
    env["DFIR_EWF_MAPPINGS"] = json.dumps(mapping_document)
    env.pop("DFIR_EWF_MOUNT_ROOT", None)
    env["DFIR_AUTO_INDEX"] = "1"
    env["DFIR_CMD_TIMEOUT"] = "60"
    env["DFIR_EXTRACT_TIMEOUT"] = "300"
    env["DFIR_INDEX_TIMEOUT"] = "240"

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "dfir_browser.mcp_server"],
        env=env,
        cwd=str(PROJECT_ROOT),
    )

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_map = {tool.name: tool for tool in tools.tools}
            print(f"[tools] {sorted(tool_map)}")
            assert set(tool_map) == EXPECTED_TOOLS, set(tool_map)
            for name in (
                "evidence_inspect",
                "filesystem_list",
                "filesystem_stat",
                "filesystem_index_status",
                "filesystem_list_deleted",
                "filesystem_search",
                "filesystem_list_tree_children",
                "filesystem_tree_ancestors",
                "get_file_triage",
                "browser_list_artifacts",
                "browser_index_status",
                "browser_list_profiles",
                "browser_query_downloads",
                "browser_query_history",
                "browser_query_cache",
                "browser_search_all",
                "browser_get_record",
                "browser_correlate_download",
                "browser_activity_summary",
                "preview_file_content",
            ):
                assert tool_map[name].annotations.readOnlyHint is True, name
            assert (
                tool_map["lookup_file_hash_virustotal"].annotations.readOnlyHint
                is False
            )
            assert (
                tool_map["lookup_file_hash_virustotal"].annotations.openWorldHint
                is True
            )
            assert (
                tool_map["filesystem_index_start"].annotations.readOnlyHint
                is False
            )
            assert (
                tool_map["filesystem_index_start"].annotations.idempotentHint
                is True
            )
            print("[tools] annotations verified")

            registered = payload(
                await session.call_tool(
                    "evidence_register", {"path": str(evidence)}
                )
            )
            evidence_id = registered["evidence_id"]
            print(
                json.dumps(
                    {
                        "evidence_id": evidence_id,
                        "source_sha256": registered["source_sha256"],
                        "exposure_mode": registered["exposure_mode"],
                        "raw_exposure_path": registered["raw_exposure_path"],
                        "layout": registered["layout"],
                        "auto_index": registered.get("auto_index", {}).get("status"),
                        "trust": registered["trust"],
                    },
                    indent=2,
                )
            )
            assert registered["trust"] == "untrusted_evidence_data"
            assert registered["layout"]["scope"] == "volume"
            assert registered["layout"]["filesystem"] == "NTFS"
            assert registered["layout"]["offset_sectors"] == 0
            assert registered["source_sha256"] == before_hash
            assert registered["exposure_mode"] == "explicit"

            index_status = await wait_for_index(session, evidence_id)
            print(
                json.dumps(
                    {
                        "index_status": index_status["status"],
                        "complete": index_status["complete"],
                        "entries_seen": index_status["entries_seen"],
                        "entries_indexed": index_status["entries_indexed"],
                        "parse_errors": index_status["parse_errors"],
                        "deleted_files": index_status["deleted_files"],
                        "deleted_directories": index_status["deleted_directories"],
                    },
                    indent=2,
                )
            )
            assert index_status["status"] == "ready", index_status
            assert index_status["complete"] is True, index_status
            assert index_status["parse_errors"] == 0, index_status
            assert index_status["entries_indexed"] > 100_000, index_status
            assert index_status["deleted_files"] > 0, index_status

            inspected = payload(
                await session.call_tool(
                    "evidence_inspect", {"evidence_id": evidence_id}
                )
            )
            assert inspected["trust"] == "untrusted_evidence_data"
            assert inspected["exposure"]["readable"] is True
            assert inspected["index"]["status"] == "ready"

            root = payload(
                await session.call_tool(
                    "filesystem_list", {"evidence_id": evidence_id}
                )
            )
            assert root["trust"] == "untrusted_evidence_data"
            assert root["source"] == "index", root
            assert root["complete"] is True, root
            assert root["truncated"] is False, root
            users = next(
                entry for entry in root["entries"] if entry["name"] == "Users"
            )
            assert users["inode"] == 1746, users
            assert users["entry_type"] == "directory", users
            print(f"[root] source={root['source']} Users inode={users['inode']}")

            user_dir = payload(
                await session.call_tool(
                    "filesystem_list",
                    {"evidence_id": evidence_id, "inode": 1746},
                )
            )
            assert user_dir["source"] == "index"
            ieuser = next(
                entry for entry in user_dir["entries"] if entry["name"] == "IEUser"
            )
            assert ieuser["inode"] == 83437, ieuser
            print(f"[inode 1746] IEUser inode={ieuser['inode']}")

            deleted = payload(
                await session.call_tool(
                    "filesystem_list_deleted",
                    {
                        "evidence_id": evidence_id,
                        "extension": "exe",
                        "page": 1,
                        "page_size": 100,
                    },
                )
            )
            assert deleted["trust"] == "untrusted_evidence_data"
            assert deleted["index_status"] == "ready"
            assert deleted["complete"] is True
            assert deleted["total"] > 0
            assert deleted["summary"]["deleted_files"] > 0
            print(
                f"[deleted] total={deleted['total']} "
                f"first_page={len(deleted['entries'])} "
                f"complete={deleted['complete']}"
            )

            search = payload(
                await session.call_tool(
                    "filesystem_search",
                    {
                        "evidence_id": evidence_id,
                        "query": "Sysinternals.exe",
                        "exact": True,
                        "deleted_only": True,
                        "page": 1,
                        "page_size": 100,
                    },
                )
            )
            assert search["trust"] == "untrusted_evidence_data"
            assert search["index_status"] == "ready"
            assert search["complete"] is True
            matches = [
                entry
                for entry in search["entries"]
                if entry["full_path"] == "Users/Public/Downloads/SysInternals.exe"
            ]
            assert matches, search["entries"]
            sysinternals = matches[0]
            assert sysinternals["deleted"] is True
            assert sysinternals["allocated"] is False
            assert sysinternals["inode"] == 124567
            assert sysinternals["size"] == 57344
            print(
                "[search] Users/Public/Downloads/SysInternals.exe "
                f"inode={sysinternals['inode']} deleted={sysinternals['deleted']}"
            )

            hosts_search = payload(
                await session.call_tool(
                    "filesystem_search",
                    {
                        "evidence_id": evidence_id,
                        "query": "Windows/System32/drivers/etc/hosts",
                        "exact": True,
                        "page_size": 10,
                    },
                )
            )
            hosts_entry = next(
                entry
                for entry in hosts_search["entries"]
                if entry["full_path"] == "Windows/System32/drivers/etc/hosts"
            )
            assert hosts_entry["inode"] == 42564
            hosts_preview = payload(
                await session.call_tool(
                    "preview_file_content",
                    {"evidence_id": evidence_id, "entry_id": hosts_entry["id"]},
                )
            )
            assert hosts_preview["preview_mode"] == "text"
            assert hosts_preview["trust"] == "untrusted_evidence_data"
            assert "www.malware430.com" in hosts_preview["content"]
            assert "192.168.15.10" in hosts_preview["content"]
            print(
                "[preview] hosts bytes=%s encoding=%s malware430=%s ip=%s"
                % (
                    hosts_preview["returned_bytes"],
                    hosts_preview["encoding"],
                    "www.malware430.com" in hosts_preview["content"],
                    "192.168.15.10" in hosts_preview["content"],
                )
            )
            amcache_search = payload(
                await session.call_tool(
                    "filesystem_search",
                    {
                        "evidence_id": evidence_id,
                        "query": "Windows/appcompat/Programs/Amcache.hve",
                        "exact": True,
                        "page_size": 10,
                    },
                )
            )
            amcache_entry = next(
                entry
                for entry in amcache_search["entries"]
                if entry["full_path"] == "Windows/appcompat/Programs/Amcache.hve"
            )
            amcache_preview = payload(
                await session.call_tool(
                    "preview_file_content",
                    {"evidence_id": evidence_id, "entry_id": amcache_entry["id"]},
                )
            )
            assert amcache_preview["preview_mode"] == "registry"
            assert amcache_preview["registry"]["header"]["signature_valid"] is True
            assert amcache_preview["returned_bytes"] <= 4096
            print(
                "[preview] Amcache.hve mode=%s regf=%s bytes=%s"
                % (
                    amcache_preview["preview_mode"],
                    amcache_preview["registry"]["header"]["signature"],
                    amcache_preview["returned_bytes"],
                )
            )
            rejected = await session.call_tool(
                "preview_file_content",
                {"evidence_id": evidence_id, "entry_id": hosts_entry["id"], "mode": "shell"},
            )
            assert rejected.isError is True
            print("[preview] invalid mode rejected")

            root_children = payload(
                await session.call_tool(
                    "filesystem_list_tree_children",
                    {
                        "evidence_id": evidence_id,
                        "parent_entry_id": 0,
                        "page": 1,
                        "page_size": 100,
                    },
                )
            )
            assert root_children["trust"] == "untrusted_evidence_data"
            assert root_children["total"] == 33, root_children["total"]
            root_names = {c["name"] for c in root_children["children"]}
            assert "Users" in root_names
            users_node = next(
                c for c in root_children["children"] if c["name"] == "Users"
            )
            assert users_node["type"] == "directory"
            assert users_node["has_children"] is True

            users_children = payload(
                await session.call_tool(
                    "filesystem_list_tree_children",
                    {
                        "evidence_id": evidence_id,
                        "parent_entry_id": users_node["entry_id"],
                    },
                )
            )
            ieuser = next(
                c for c in users_children["children"] if c["name"] == "IEUser"
            )
            assert ieuser["mft"] == 83437, ieuser
            assert ieuser["parent_id"] == users_node["entry_id"]

            revealed = payload(
                await session.call_tool(
                    "filesystem_tree_ancestors",
                    {
                        "evidence_id": evidence_id,
                        "entry_id": sysinternals["id"],
                    },
                )
            )
            assert [a["name"] for a in revealed["ancestors"]] == [
                "Users",
                "Public",
                "Downloads",
            ]
            assert revealed["entry"]["deleted"] is True
            print(
                "[tree] root=33 Users->IEUser inode=83437 "
                f"ancestors={'/'.join(a['name'] for a in revealed['ancestors'])}"
            )

            triage_start = payload(
                await session.call_tool(
                    "start_file_triage",
                    {
                        "evidence_id": evidence_id,
                        "entry_id": sysinternals["id"],
                        "case_id": args.case,
                        "force": True,
                    },
                )
            )
            triage_id = triage_start["job_id"]
            assert triage_start["trust"] == "untrusted_evidence_data"
            assert triage_id.startswith("tr_")
            triage_state = None
            triage_deadline = time.monotonic() + 180
            while time.monotonic() < triage_deadline:
                triage_state = payload(
                    await session.call_tool(
                        "get_file_triage",
                        {
                            "job_id": triage_id,
                            "strings_page": 1,
                            "strings_page_size": 5,
                        },
                    )
                )
                status = triage_state["job"]["status"]
                if status not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.5)
            assert triage_state is not None
            triage_job = triage_state["job"]
            assert triage_job["status"] in {"complete", "partial"}, triage_job
            assert triage_job["md5"] and triage_job["sha1"] and triage_job["sha256"]
            assert triage_job["size"] and triage_job["size"] > 0
            assert triage_state["strings"]["page_size"] == 5
            assert len(triage_state["strings"]["strings"]) <= 5
            print(
                "[triage] status=%s size=%s sha256=%s strings=%s "
                "yara=%s pe=%s findings=%s"
                % (
                    triage_job["status"],
                    triage_job["size"],
                    triage_job["sha256"],
                    triage_job["strings_count"],
                    triage_job["yara_status"],
                    triage_job["pe_status"],
                    triage_job["findings_count"],
                )
            )

            triage_cached = payload(
                await session.call_tool(
                    "start_file_triage",
                    {
                        "evidence_id": evidence_id,
                        "entry_id": sysinternals["id"],
                        "case_id": args.case,
                        "force": False,
                    },
                )
            )
            cached_state = None
            triage_deadline = time.monotonic() + 120
            while time.monotonic() < triage_deadline:
                cached_state = payload(
                    await session.call_tool(
                        "get_file_triage",
                        {"job_id": triage_cached["job_id"]},
                    )
                )
                if cached_state["job"]["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.5)
            assert cached_state is not None
            assert cached_state["job"]["cached"] is True, cached_state["job"]
            assert cached_state["job"]["sha256"] == triage_job["sha256"]
            print("[triage] second request reused the cached result")

            consent = await session.call_tool(
                "lookup_file_hash_virustotal",
                {"evidence_id": evidence_id, "entry_id": sysinternals["id"]},
            )
            assert consent.isError is True, consent
            consent_text = error_text(consent)
            assert "external_lookup_consent_required" in consent_text, consent_text
            print("[virustotal] consent is required and no request was made")

            hives = payload(
                await session.call_tool(
                    "registry_list_hives",
                    {"evidence_id": evidence_id, "page_size": 100},
                )
            )
            amcache_hives = [
                item for item in hives["items"] if item["hive_type"] == "amcache"
            ]
            assert amcache_hives, [item["name"] for item in hives["items"]]
            amcache_entry = amcache_hives[0]["entry_id"]
            registry_started = payload(
                await session.call_tool(
                    "registry_index_start",
                    {
                        "evidence_id": evidence_id,
                        "entry_id": amcache_entry,
                        "rebuild": True,
                    },
                )
            )
            registry_id = registry_started["hive"]["hive_id"]
            registry_state = None
            registry_deadline = time.monotonic() + 180
            while time.monotonic() < registry_deadline:
                registry_state = payload(
                    await session.call_tool(
                        "registry_index_status", {"hive_id": registry_id}
                    )
                )
                if registry_state["state"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.5)
            assert registry_state is not None
            assert registry_state["state"] == "ready", registry_state
            assert registry_state["amcache_count"] > 0
            root_keys = payload(
                await session.call_tool(
                    "registry_list_subkeys",
                    {"hive_id": registry_id, "page_size": 10},
                )
            )
            assert root_keys["items"][0]["name"] == "Root"
            registry_hits = payload(
                await session.call_tool(
                    "registry_search",
                    {"hive_id": registry_id, "query": "SysInternals", "page_size": 10},
                )
            )
            assert registry_hits["total"] > 0
            amcache_hits = payload(
                await session.call_tool(
                    "amcache_search",
                    {
                        "hive_id": registry_id,
                        "query": "SysInternals.exe",
                        "exact": True,
                        "page_size": 10,
                    },
                )
            )
            assert amcache_hits["total"] == 1, amcache_hits
            record = amcache_hits["items"][0]
            assert record["hash_normalized"] == (
                "fa1002b02fc5551e075ec44bb4ff9cc13d563dcf"
            )
            assert record["normalization_method"] == "strip-4-hex-prefix-sha1"
            comparison = payload(
                await session.call_tool(
                    "amcache_compare_triage",
                    {
                        "hive_id": registry_id,
                        "amcache_record_id": record["record_id"],
                        "filesystem_entry_id": sysinternals["id"],
                    },
                )
            )
            assert comparison["status"] in {
                "match",
                "mismatch",
                "unavailable",
                "incompatible",
                "unknown",
            }
            print(
                "[registry] Amcache keys=%s values=%s amcache=%s fileid=%s "
                "sha1=%s compare=%s"
                % (
                    registry_state["key_count"],
                    registry_state["value_count"],
                    registry_state["amcache_count"],
                    record["file_id_raw"],
                    record["hash_normalized"],
                    comparison["status"],
                )
            )

            evtx_logs = payload(
                await session.call_tool(
                    "evtx_list_logs",
                    {"evidence_id": evidence_id, "page_size": 200},
                )
            )
            evtx_names = {item["name"] for item in evtx_logs["items"]}
            assert "Security.evtx" in evtx_names, sorted(evtx_names)[:10]
            security_entry = next(
                item["entry_id"]
                for item in evtx_logs["items"]
                if item["name"] == "Security.evtx"
            )
            evtx_started = payload(
                await session.call_tool(
                    "evtx_index_start",
                    {
                        "evidence_id": evidence_id,
                        "entry_id": security_entry,
                        "rebuild": True,
                    },
                )
            )
            evtx_log_id = evtx_started["log"]["log_id"]
            evtx_state = None
            evtx_deadline = time.monotonic() + 300
            while time.monotonic() < evtx_deadline:
                evtx_state = payload(
                    await session.call_tool(
                        "evtx_index_status", {"log_id": evtx_log_id}
                    )
                )
                if evtx_state["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.5)
            assert evtx_state is not None
            assert evtx_state["status"] in {"ready", "partial"}, evtx_state
            assert evtx_state["records_indexed"] > 100

            evtx_hits = payload(
                await session.call_tool(
                    "evtx_query_events",
                    {
                        "evidence_id": evidence_id,
                        "log_id": evtx_log_id,
                        "event_ids": [4688],
                        "page_size": 5,
                    },
                )
            )
            assert evtx_hits["total"] > 0, evtx_hits
            first_event = evtx_hits["events"][0]
            assert first_event["event_id"] == 4688
            assert "raw_xml" not in first_event

            evtx_detail = payload(
                await session.call_tool(
                    "evtx_get_event",
                    {"log_id": evtx_log_id, "record_id": first_event["record_id"]},
                )
            )
            assert evtx_detail["message_status"] == "message_unavailable"
            assert "raw_xml" not in evtx_detail

            evtx_context = payload(
                await session.call_tool(
                    "evtx_get_context",
                    {"log_id": evtx_log_id, "record_id": first_event["record_id"]},
                )
            )
            assert len(evtx_context["events"]) > 1

            evtx_summary = payload(
                await session.call_tool(
                    "evtx_activity_summary",
                    {"evidence_id": evidence_id, "log_ids": [evtx_log_id]},
                )
            )
            assert evtx_summary["total_events"] == evtx_state["records_indexed"]
            print(
                "[evtx] Security records=%s errors=%s event4688=%s range=%s..%s"
                % (
                    evtx_state["records_indexed"],
                    evtx_state["parse_errors"],
                    evtx_hits["total"],
                    evtx_state["first_event_time"],
                    evtx_state["last_event_time"],
                )
            )

            artifacts = payload(
                await session.call_tool(
                    "browser_list_artifacts",
                    {"evidence_id": evidence_id, "include_deleted": True},
                )
            )
            assert artifacts["trust"] == "untrusted_evidence_data"
            webcache = next(
                (
                    item
                    for item in artifacts["items"]
                    if item["artifact_type"] == "webcache"
                ),
                None,
            )
            assert webcache is not None, [i["path"] for i in artifacts["items"]]
            browser_started = payload(
                await session.call_tool(
                    "browser_index_start",
                    {"evidence_id": evidence_id, "entry_id": webcache["entry_id"]},
                )
            )
            browser_id = browser_started["artifact"]["artifact_id"]
            for _ in range(600):
                browser_state = payload(
                    await session.call_tool(
                        "browser_index_status", {"artifact_id": browser_id}
                    )
                )
                if browser_state["status"] not in {"queued", "running"}:
                    break
                await asyncio.sleep(0.5)
            assert browser_state["status"] in {"ready", "partial"}, browser_state
            assert browser_state["records_indexed"] > 0
            print(
                "[browser] %s records=%s errors=%s range=%s..%s"
                % (
                    browser_state["artifact_type"],
                    browser_state["records_indexed"],
                    browser_state["parse_errors"],
                    browser_state["first_record_time"],
                    browser_state["last_record_time"],
                )
            )

            browser_downloads = payload(
                await session.call_tool(
                    "browser_query_downloads",
                    {"evidence_id": evidence_id, "query": "SysInternals"},
                )
            )
            assert browser_downloads["total"] >= 1, browser_downloads
            target = browser_downloads["items"][0]
            assert target["trust"] == "untrusted_evidence_data"
            print(
                "[browser] download %s state=%s bytes=%s url=%s"
                % (
                    target["filename"],
                    target["state"],
                    target["received_bytes"],
                    target["url"],
                )
            )

            browser_corr = payload(
                await session.call_tool(
                    "browser_correlate_download",
                    {
                        "evidence_id": evidence_id,
                        "download_id": target["download_id"],
                    },
                )
            )
            assert browser_corr["correlation"]["hits"], browser_corr
            print(
                "[browser] correlation confidence=%s hits=%s"
                % (
                    browser_corr["correlation"]["confidence"],
                    [
                        (hit["path"], hit["deleted"])
                        for hit in browser_corr["correlation"]["hits"]
                    ],
                )
            )

            browser_history = payload(
                await session.call_tool(
                    "browser_query_history",
                    {"evidence_id": evidence_id, "query": "SysInternals"},
                )
            )
            assert browser_history["total"] >= 1

            browser_summary = payload(
                await session.call_tool(
                    "browser_activity_summary", {"evidence_id": evidence_id}
                )
            )
            assert browser_summary["trust"] == "untrusted_evidence_data"
            print(
                "[browser] summary visits=%s downloads=%s exe_downloads=%s"
                % (
                    browser_summary["total_visits"],
                    browser_summary["total_downloads"],
                    browser_summary["executable_downloads"],
                )
            )

            idempotent = payload(
                await session.call_tool(
                    "filesystem_index_start",
                    {"evidence_id": evidence_id, "rebuild": False},
                )
            )
            assert idempotent["started"] is False, idempotent
            assert idempotent["status"] == "ready", idempotent
            print("[index] rebuild=false is idempotent while ready")

            metadata = payload(
                await session.call_tool(
                    "filesystem_stat", {"evidence_id": evidence_id, "inode": 60734}
                )
            )
            assert metadata["trust"] == "untrusted_evidence_data"
            assert metadata["summary"]["name"] == "bootmgr"
            assert metadata["summary"]["data_size"] == 408364
            print(f"[stat 60734] name={metadata['summary']['name']}")

            extraction = payload(
                await session.call_tool(
                    "filesystem_extract",
                    {
                        "evidence_id": evidence_id,
                        "inode": 60021,
                        "case_id": args.case,
                    },
                )
            )
            assert extraction["trust"] == "untrusted_evidence_data"
            assert extraction["untrusted"] is True
            assert extraction["size"] == 1
            assert extraction["sha256"] == (
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
            )
            print(
                f"[extract] inode={extraction['inode']} "
                f"sha256={extraction['sha256']}"
            )

            bad_inode = await session.call_tool(
                "filesystem_stat", {"evidence_id": evidence_id, "inode": -1}
            )
            assert bad_inode.isError is True
            assert error_payload(bad_inode)["error"]["code"] == "policy_error"
            print("[safety] negative inode rejected")

            outside = Path(tempfile.gettempdir()) / "dfir-outside.E01"
            outside.write_bytes(b"not an image")
            try:
                bad_path = await session.call_tool(
                    "evidence_register", {"path": str(outside)}
                )
                assert bad_path.isError is True
                assert error_payload(bad_path)["error"]["code"] == "policy_error"
                print("[safety] path outside allowlist rejected")
            finally:
                outside.unlink(missing_ok=True)

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
    print("[ok] MCP stdio/index smoke test passed; evidence unchanged")
    return 0


def main() -> int:
    return asyncio.run(run(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
