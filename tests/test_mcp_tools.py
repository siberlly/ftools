from __future__ import annotations

import asyncio
import json

from dfir_browser.core.errors import DFIRError
from dfir_browser.core.index_models import (
    IndexStartResult,
    IndexStatus,
    PaginatedEntries,
    TRUST_LABEL as INDEX_TRUST_LABEL,
)
from dfir_browser.core.models import (
    DirectoryListing,
    EvidenceRecord,
    ExtractionResult,
    Layout,
    MetadataResult,
    TRUST_LABEL,
    utc_now_iso,
)
from dfir_browser.mcp_server import _fail, mcp

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
}


def tools_by_name():
    tools = asyncio.run(mcp.list_tools())
    return {tool.name: tool for tool in tools}


def test_exactly_forty_two_tools() -> None:
    assert set(tools_by_name()) == EXPECTED_TOOLS
    assert len(EXPECTED_TOOLS) == 42


def test_tool_annotations() -> None:
    tools = tools_by_name()
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
        "registry_list_hives",
        "registry_index_status",
        "registry_list_subkeys",
        "registry_get_key",
        "registry_search",
        "amcache_search",
        "amcache_compare_triage",
        "evtx_list_logs",
        "evtx_index_status",
        "evtx_query_events",
        "evtx_get_event",
        "evtx_get_context",
        "evtx_activity_summary",
    ):
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is True
        assert annotations.destructiveHint is False

    for name in (
        "evidence_register",
        "filesystem_extract",
        "start_file_triage",
        "lookup_file_hash_virustotal",
        "registry_index_start",
        "amcache_lookup_virustotal",
        "evtx_index_start",
    ):
        annotations = tools[name].annotations
        assert annotations is not None
        assert annotations.readOnlyHint is False
        assert annotations.destructiveHint is False

    index_start = tools["filesystem_index_start"].annotations
    assert index_start is not None
    assert index_start.readOnlyHint is False
    assert index_start.destructiveHint is False
    assert index_start.idempotentHint is True

    assert tools["evidence_register"].annotations.idempotentHint is False
    assert tools["filesystem_extract"].annotations.idempotentHint is False
    assert tools["start_file_triage"].annotations.idempotentHint is False
    assert tools["lookup_file_hash_virustotal"].annotations.idempotentHint is False
    assert tools["lookup_file_hash_virustotal"].annotations.openWorldHint is True
    assert tools["filesystem_list"].annotations.idempotentHint is True


def test_descriptions_warn_about_untrusted_data_and_side_effects() -> None:
    tools = tools_by_name()
    for tool in tools.values():
        description = (tool.description or "").upper()
        assert "UNTRUSTED" in description
        assert "INSTRUCTIONS" in description
    assert "STATE" in (tools["evidence_register"].description or "").upper()
    assert "NOT READ-ONLY" in (
        tools["filesystem_extract"].description or ""
    ).upper()
    assert "TRUNCATED" in (
        tools["filesystem_list"].description or ""
    ).upper()
    assert "REBUILD" in (
        tools["filesystem_index_start"].description or ""
    ).upper()
    assert "PAGINATED" in (
        tools["filesystem_list_deleted"].description or ""
    ).upper()
    assert "PARAMETERIZED" in (
        tools["filesystem_search"].description or ""
    ).upper()


def test_fail_returns_structured_error_json() -> None:
    error = DFIRError(
        "no mapping", code="ewf_mapping_missing", details={"source": "/x.E01"}
    )
    tool_error = _fail(error)
    payload = json.loads(str(tool_error))
    assert payload["error"]["code"] == "ewf_mapping_missing"
    assert payload["error"]["message"] == "no mapping"
    assert payload["error"]["details"] == {"source": "/x.E01"}


def test_structured_models_carry_trust_label() -> None:
    listing = DirectoryListing(
        evidence_id="ev_0123456789ab",
        inode=5,
        offset_sectors=0,
        breadcrumb=[{"inode": 5, "name": "/"}],
        entries=[],
        warnings=[],
        tool_version="tsk",
        complete=True,
        truncated=False,
    )
    assert listing.to_dict()["trust"] == TRUST_LABEL

    metadata = MetadataResult(
        evidence_id="ev_0123456789ab",
        inode=60734,
        summary={},
        raw="raw",
        raw_truncated=False,
        warnings=[],
        tool_version="tsk",
    )
    assert metadata.to_dict()["trust"] == TRUST_LABEL

    extraction = ExtractionResult(
        evidence_id="ev_0123456789ab",
        case_id="case01",
        inode=60021,
        name="BOOTNXT",
        output_path="/tmp/out",
        relative_path="cases/case01/exports/out",
        size=1,
        sha256="a" * 64,
        source_size=1,
        tool_version="tsk",
        extracted_at=utc_now_iso(),
        untrusted=True,
    )
    payload = extraction.to_dict()
    assert payload["trust"] == TRUST_LABEL
    assert payload["untrusted"] is True

    record = EvidenceRecord(
        evidence_id="ev_0123456789ab",
        resolved_source_path="/home/ubuntu/test/disk.E01",
        filename="disk.E01",
        extension=".e01",
        source_sha256="a" * 64,
        source_size=1,
        source_mtime_ns=1,
        format="FTK Imager",
        media_size=1,
        sector_size=512,
        md5=None,
        sha1=None,
        ewfinfo_version=None,
        ewfinfo_duration_ms=0.0,
        ewfinfo_command={},
        raw_exposure_path="/home/ubuntu/mnt/ewf/ewf1",
        exposure_mode="explicit",
        exposure_verified_at=utc_now_iso(),
        exposure_details={},
        layout=Layout(
            scope="volume", filesystem="NTFS", offset_sectors=0, method="fsstat"
        ),
        registered_at=utc_now_iso(),
        status="ready",
        warnings=[],
    )
    assert record.to_dict()["trust"] == TRUST_LABEL


def test_index_models_carry_trust_label() -> None:
    status = IndexStatus(
        evidence_id="ev_0123456789ab",
        found=True,
        status="ready",
        stale=False,
        queryable=True,
        complete=True,
    )
    assert status.to_dict()["trust"] == INDEX_TRUST_LABEL

    paginated = PaginatedEntries(
        results=[],
        total=0,
        page=1,
        page_size=100,
        index_status=status,
        complete=True,
    )
    assert paginated.to_dict()["trust"] == INDEX_TRUST_LABEL

    start = IndexStartResult(
        started=True, scan_id="scan1", status=status
    )
    assert start.to_dict()["trust"] == INDEX_TRUST_LABEL
