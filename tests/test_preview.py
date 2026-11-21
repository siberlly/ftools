from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from dfir_browser.core.preview import (
    PreviewRejected,
    hexdump,
    looks_binary,
)

from preview_helpers import (
    AMCACHE_PATH,
    BIG_PATH,
    BINARY_PATH,
    DEEP_PATH,
    DIR_PATH,
    EVIDENCE,
    HOSTS_PATH,
    HOSTS_TEXT,
    SCRIPT_PATH,
    SYSTEM_PATH,
    TEXT_PATH,
    build_preview_services,
    entry_id,
    hive_payload,
    index_hive,
    stub_preview_extract,
)


def _payloads(**overrides):
    data = {
        42564: HOSTS_TEXT.encode("utf-8"),
        50001: hive_payload(),
        50002: hive_payload(primary=7, secondary=9),
        50010: b"plain ascii\nsecond line\n",
        50011: ("line\n" * 40000).encode("utf-8"),
        50012: bytes(range(0, 256)) * 4,
        50013: b"<html><script>alert('xss')</script>ok</html>\n",
        50014: b"deep content\n",
    }
    data.update({int(key): value for key, value in overrides.items()})
    return data


@pytest.fixture()
def env(tmp_path):
    payloads = _payloads()
    services, record = build_preview_services(tmp_path, payloads)
    stub_preview_extract(services, payloads)
    try:
        yield services, record, payloads
    finally:
        services.cleanup()


# ----------------------------------------------------------------------
# content
# ----------------------------------------------------------------------
def test_hosts_preview_contains_indicators(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, HOSTS_PATH))
    assert result.preview_mode == "text"
    assert result.detected_type == "text"
    assert result.encoding == "utf-8"
    assert result.truncated is False
    assert "www.malware430.com" in result.content
    assert "192.168.15.10" in result.content
    d = result.to_dict()
    for key in (
        "evidence_id", "entry_id", "filename", "evidence_path",
        "detected_type", "preview_mode", "encoding", "offset",
        "returned_bytes", "total_size", "truncated", "content", "warnings",
    ):
        assert key in d
    assert d["trust"] == "untrusted_evidence_data"


def test_plain_text_and_mime(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, TEXT_PATH))
    assert result.mime_type == "text/plain"
    assert "second line" in result.content


def test_hex_view_of_text_is_available(env):
    services, record, _ = env
    result = services.preview.preview(
        record, entry_id(services, TEXT_PATH), mode="hex"
    )
    assert result.preview_mode == "hex"
    assert result.content.startswith("00000000  ")


# ----------------------------------------------------------------------
# encodings
# ----------------------------------------------------------------------
def test_utf8_bom(env):
    services, record, payloads = env
    payloads[50010] = b"\xef\xbb\xbfBOM text\n"
    stub_preview_extract(services, payloads)
    result = services.preview.preview(record, entry_id(services, TEXT_PATH))
    assert result.encoding == "utf-8-sig"
    assert result.content.startswith("BOM text")
    assert "\ufeff" not in result.content


def test_utf16le_bom(env):
    services, record, payloads = env
    payloads[50010] = "Hello UTF-16\n".encode("utf-16")  # includes BOM
    stub_preview_extract(services, payloads)
    result = services.preview.preview(record, entry_id(services, TEXT_PATH))
    assert result.encoding in {"utf-16-le", "utf-16"}
    assert "Hello UTF-16" in result.content
    assert "\x00" not in result.content


def test_utf16be_bom(env):
    services, record, payloads = env
    payloads[50010] = b"\xfe\xff" + "Big endian\n".encode("utf-16-be")
    stub_preview_extract(services, payloads)
    result = services.preview.preview(record, entry_id(services, TEXT_PATH))
    assert result.encoding == "utf-16-be"
    assert "Big endian" in result.content


def test_invalid_utf8_falls_back_to_latin1(env):
    services, record, payloads = env
    payloads[50010] = b"caf\xe9 cr\xe8me\n"
    stub_preview_extract(services, payloads)
    result = services.preview.preview(record, entry_id(services, TEXT_PATH))
    assert result.encoding == "latin-1"
    assert "café crème" in result.content
    assert any("Latin-1" in warning for warning in result.warnings)


def test_encoding_helpers():
    assert looks_binary(b"\x00\x01\x02") is True
    assert looks_binary(b"plain text\n") is False
    dumped = hexdump(b"AB", base_offset=16)
    assert dumped.startswith("00000010  41 42 ")
    assert dumped.endswith("|AB|")


# ----------------------------------------------------------------------
# XSS / escaping
# ----------------------------------------------------------------------
def test_html_is_returned_as_plain_text(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, SCRIPT_PATH))
    assert result.preview_mode == "text"
    assert "<script>alert('xss')</script>" in result.content


# ----------------------------------------------------------------------
# truncation / pagination
# ----------------------------------------------------------------------
def test_truncated_by_limit(env):
    services, record, _ = env
    big = entry_id(services, BIG_PATH)
    result = services.preview.preview(record, big, limit=1024)
    assert result.truncated is True
    assert result.returned_bytes == 1024
    assert result.has_more is True
    assert result.next_offset == 1024
    assert any("truncated" in warning.lower() for warning in result.warnings)


def test_pagination_offsets(env):
    services, record, _ = env
    big = entry_id(services, BIG_PATH)
    first = services.preview.preview(record, big, limit=1000)
    second = services.preview.preview(
        record, big, offset=first.next_offset, limit=1000
    )
    assert second.offset == 1000
    assert second.returned_bytes == 1000
    assert first.offset == 0
    assert second.offset + second.returned_bytes <= second.total_size


def test_offset_at_eof_returns_empty(env):
    services, record, _ = env
    hosts = entry_id(services, HOSTS_PATH)
    result = services.preview.preview(record, hosts, offset=10_000)
    assert result.offset == result.total_size
    assert result.returned_bytes == 0
    assert result.truncated is False
    assert result.content == ""


def test_offset_past_end_does_not_overread(env):
    services, record, _ = env
    hosts = entry_id(services, HOSTS_PATH)
    result = services.preview.preview(
        record, hosts, offset=result_size(services, record, hosts), limit=4096
    )
    assert result.returned_bytes == 0
    assert result.offset == result.total_size


def result_size(services, record, entry) -> int:
    return services.preview.preview(record, entry, limit=64).total_size


def test_line_limit_truncation(tmp_path):
    payloads = _payloads()
    services, record = build_preview_services(
        tmp_path, payloads, preview_text_max_lines=10
    )
    stub_preview_extract(services, payloads)
    try:
        result = services.preview.preview(record, entry_id(services, BIG_PATH))
        assert result.lines_returned == 10
        assert result.truncated is True
        assert any("lines" in warning for warning in result.warnings)
    finally:
        services.cleanup()


def test_invalid_range_rejected(env):
    services, record, _ = env
    hosts = entry_id(services, HOSTS_PATH)
    with pytest.raises(PreviewRejected):
        services.preview.preview(record, hosts, offset=-1)
    with pytest.raises(PreviewRejected):
        services.preview.preview(record, hosts, limit=0)
    with pytest.raises(PreviewRejected):
        services.preview.preview(record, hosts, limit=2 * 1024 * 1024)
    with pytest.raises(PreviewRejected):
        services.preview.preview(record, hosts, mode="shell")


# ----------------------------------------------------------------------
# binary / hex
# ----------------------------------------------------------------------
def test_binary_switches_to_hex(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, BINARY_PATH))
    assert result.preview_mode == "hex"
    assert result.detected_type == "binary"
    assert len(result.content.splitlines()) >= 1
    assert result.content.startswith("00000000  ")


def test_binary_text_mode_request_is_honoured(env):
    services, record, _ = env
    result = services.preview.preview(
        record, entry_id(services, BINARY_PATH), mode="text"
    )
    assert result.preview_mode == "text"


# ----------------------------------------------------------------------
# registry
# ----------------------------------------------------------------------
def test_registry_hive_detected_by_regf(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, AMCACHE_PATH))
    assert result.preview_mode == "registry"
    assert result.detected_type == "windows_registry_hive"
    assert result.registry["header"]["signature_valid"] is True
    assert result.registry["header"]["signature"] == "regf"
    assert result.registry["hive_type"] == "amcache"
    assert result.registry["index_state"] == "not_indexed"
    # Never dumps the whole hive.
    assert result.returned_bytes <= 4096
    assert result.content.startswith("00000000  72 65 67 66")


def test_registry_hive_reports_index_state(env):
    services, record, _ = env
    amcache = entry_id(services, AMCACHE_PATH)
    hive_id = index_hive(services, amcache)
    result = services.preview.preview(record, amcache)
    assert result.registry["index_state"] == "ready"
    assert result.registry["indexed_hive_id"] == hive_id


def test_dirty_hive_warning(env):
    services, record, _ = env
    result = services.preview.preview(record, entry_id(services, SYSTEM_PATH))
    assert result.registry["header"]["dirty"] is True
    assert any("dirty" in warning for warning in result.warnings)


def test_registry_hex_mode_allows_explicit_hex(env):
    services, record, _ = env
    result = services.preview.preview(
        record, entry_id(services, AMCACHE_PATH), mode="hex"
    )
    assert result.preview_mode == "hex"


# ----------------------------------------------------------------------
# rejections
# ----------------------------------------------------------------------
def test_directory_rejected(env):
    services, record, _ = env
    with pytest.raises(PreviewRejected) as exc:
        services.preview.preview(record, entry_id(services, DIR_PATH))
    assert exc.value.code == "preview_directory_rejected"


def test_negative_inode_rejected(env):
    services, record, _ = env
    with pytest.raises(PreviewRejected) as exc:
        services.preview.preview(
            record, entry_id(services, "Users/IEUser/Documents/negative.txt")
        )
    assert exc.value.code == "preview_invalid_inode"


def test_fake_entry_and_evidence_rejected(env):
    services, record, _ = env
    with pytest.raises(Exception):
        services.preview.preview(record, 99999999)
    with pytest.raises(Exception):
        services.evidence.get("ev_deadbeef0000")


def test_traversal_entry_path_rejected(env):
    services, record, _ = env

    class FakeEntry:
        id = 1
        entry_type = "file"
        inode = 42564
        full_path = "Users/IEUser/../../Windows/System32/config/SAM"
        basename = "SAM"

    services.indexer.tree_entry = lambda rec, value: FakeEntry()
    with pytest.raises(PreviewRejected) as exc:
        services.preview.preview(record, 1)
    assert exc.value.code == "preview_unsafe_path"


def test_no_filesystem_path_parameter(env):
    services, record, _ = env
    # The public API has no path argument at all; extra kwargs are rejected.
    with pytest.raises(TypeError):
        services.preview.preview(record, entry_id(services, HOSTS_PATH), path="/etc/passwd")


# ----------------------------------------------------------------------
# copy reuse, cache, permissions, audit
# ----------------------------------------------------------------------
def test_copy_is_reused_across_requests(env):
    services, record, _ = env
    hosts = entry_id(services, HOSTS_PATH)
    calls = stub_preview_extract(services, _payloads())
    services.preview.preview(record, hosts, limit=100)
    services.preview.preview(record, hosts, limit=200)
    services.preview.preview(record, hosts, limit=100)
    assert len(calls) == 1


def test_cache_hit_avoids_second_extraction(tmp_path):
    payloads = _payloads()
    services, record = build_preview_services(tmp_path, payloads)
    calls = stub_preview_extract(services, payloads)
    try:
        hosts = entry_id(services, HOSTS_PATH)
        first = services.preview.preview(record, hosts)
        second = services.preview.preview(record, hosts)
        assert first.content == second.content
        assert len(calls) == 1
    finally:
        services.cleanup()


def test_extracted_copy_permissions_and_location(env):
    services, record, _ = env
    services.preview.preview(record, entry_id(services, HOSTS_PATH))
    exports = services.policy.case_exports_dir("case01")
    files = [p for p in exports.glob("inode_42564_*") if not p.name.endswith(".json")]
    assert files
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert files[0].resolve().is_relative_to(exports.resolve())


def test_audit_event_has_no_content(env):
    services, record, _ = env
    services.preview.preview(record, entry_id(services, HOSTS_PATH))
    log_path = services.settings.audit_log_path
    content = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert "file_preview" in content
    assert "www.malware430.com" not in content
    assert "malware430" not in content


def test_symlinked_copy_rejected(env, tmp_path):
    services, record, _ = env
    hosts = entry_id(services, HOSTS_PATH)
    exports = services.policy.case_exports_dir("case01")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = exports / "inode_42564_evil.bin"
    link.symlink_to(outside)
    result = services.preview.preview(record, hosts)
    assert "www.malware430.com" in result.content
