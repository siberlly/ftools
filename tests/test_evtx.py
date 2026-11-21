from __future__ import annotations

import time
from pathlib import Path

import pytest

from dfir_browser.core.config import Settings
from dfir_browser.core.evtx.detector import (
    channel_from_filename,
    classify_entry,
    inspect_evtx_header,
    is_priority_channel,
)
from dfir_browser.core.evtx.index import EvtxStore, _fts_query, escape_like
from dfir_browser.core.evtx.models import EventQuery, EvtxLog, log_id_for
from dfir_browser.core.evtx.parser import EvtxBackend, normalize_event
from dfir_browser.core.evtx.presets import PRESETS, get_preset, list_presets

from evtx_helpers import (
    SYNTHETIC_EMPTY,
    sample_event_xml,
    synthetic_empty_evtx,
)


def settings(**overrides):
    return Settings.from_env(**overrides)


def parsed(xml: str, **overrides):
    raw = type(
        "Raw",
        (),
        {"record_id": 1, "chunk_number": 0, "xml": xml, "xml_too_large": False, "error": None},
    )()
    return normalize_event(
        log_id="log_x",
        raw=raw,
        xml_text=xml,
        settings=settings(**overrides),
        channel_fallback="Security",
    )


# ---------------------------------------------------------------------------
# detector
# ---------------------------------------------------------------------------
def test_channel_from_filename() -> None:
    assert channel_from_filename("Security.evtx") == "Security"
    assert channel_from_filename("System.evtx") == "System"
    assert channel_from_filename("Windows PowerShell.evtx") == "Windows PowerShell"
    assert (
        channel_from_filename("Microsoft-Windows-Sysmon%4Operational.evtx")
        == "Microsoft-Windows-Sysmon/Operational"
    )
    assert (
        channel_from_filename("Microsoft-Windows-DNS-Client%4Operational.evtx")
        == "Microsoft-Windows-DNS-Client/Operational"
    )
    assert (
        channel_from_filename(
            "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
        )
        == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    )


def test_priority_channels() -> None:
    assert is_priority_channel("Security")
    assert is_priority_channel("Microsoft-Windows-Sysmon/Operational")
    assert is_priority_channel(
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    )
    assert not is_priority_channel("Microsoft-Windows-Store/Operational")


def test_classify_non_evtx_returns_none() -> None:
    entry = type(
        "Entry",
        (),
        {
            "basename": "SYSTEM",
            "full_path": "Windows/System32/config/SYSTEM",
            "id": 1,
            "inode": 2,
            "size": 100,
            "allocated": True,
            "deleted": False,
            "created_time": None,
            "modified_time": None,
            "accessed_time": None,
            "mft_modified_time": None,
        },
    )()
    assert classify_entry(entry, evidence_id="ev_0123456789ab") is None


def test_classify_small_evtx_warns() -> None:
    entry = type(
        "Entry",
        (),
        {
            "basename": "Security.evtx",
            "full_path": "Windows/System32/winevt/Logs/Security.evtx",
            "id": 5,
            "inode": 6,
            "size": 100,
            "allocated": True,
            "deleted": False,
            "created_time": None,
            "modified_time": None,
            "accessed_time": None,
            "mft_modified_time": None,
        },
    )()
    candidate = classify_entry(entry, evidence_id="ev_0123456789ab")
    assert candidate is not None
    assert candidate.channel == "Security"
    # A suspiciously small file keeps the path-based match but loses confidence.
    assert 0.3 <= candidate.confidence < 0.9
    assert candidate.warnings and "small" in candidate.warnings[0]


def test_inspect_evtx_header_on_fixture_and_bad_file(tmp_path) -> None:
    good = inspect_evtx_header(SYNTHETIC_EMPTY)
    assert good.signature_valid is True
    assert good.chunk_count == 1
    bad = tmp_path / "not.evtx"
    bad.write_bytes(b"NOTEVTX" + b"\x00" * 200)
    assert inspect_evtx_header(bad).signature_valid is False
    short = tmp_path / "short.evtx"
    short.write_bytes(b"Elf")
    assert inspect_evtx_header(short).signature_valid is False


# ---------------------------------------------------------------------------
# parser / normalizer
# ---------------------------------------------------------------------------
def test_normalize_full_event() -> None:
    event = parsed(sample_event_xml())
    assert event.event_id == 4688
    assert event.channel == "Security"
    assert event.provider_name == "Microsoft-Windows-Security-Auditing"
    assert event.provider_guid.startswith("{54849625")
    assert event.computer == "SYNTHETIC-PC"
    assert event.user_sid == "S-1-5-18"
    assert event.process_id == 4
    assert event.thread_id == 32
    assert event.level == 0
    assert event.task == 13312
    assert event.keywords == "0x8020000000000000"
    assert event.activity_id.startswith("{11111111")
    assert event.timestamp_utc == "2022-11-15T21:18:10.740504Z"
    assert event.event_data["NewProcessName"] == "C:\\Synthetic\\sample.exe"
    assert event.message_status == "message_unavailable"
    assert event.message is None
    assert event.raw_xml and event.raw_xml_sha256
    assert "4688" in (event.summary or "")


def test_normalize_duplicate_event_data_names() -> None:
    xml = sample_event_xml(
        duplicate_data=[("NewProcessName", "second.exe")]
    )
    event = parsed(xml)
    assert isinstance(event.event_data["NewProcessName"], list)
    assert event.event_data["NewProcessName"] == [
        "C:\\Synthetic\\sample.exe",
        "second.exe",
    ]


def test_normalize_user_data_and_message() -> None:
    event = parsed(
        sample_event_xml(
            user_data="synthetic user data",
            message="Synthetic rendered message",
        )
    )
    assert event.user_data == "synthetic user data"
    assert event.message == "Synthetic rendered message"
    assert event.message_status == "available"


def test_normalize_invalid_xml_does_not_raise() -> None:
    event = parsed("<Event><System><EventID>1")
    assert event.event_id is None
    assert event.warnings
    assert "invalid XML" in event.warnings[0]


def test_normalize_rejects_xxe_and_entities() -> None:
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<Event><System><EventID>&xxe;</EventID></System></Event>"
    )
    event = parsed(payload)
    assert event.event_id is None
    assert event.warnings
    # The DTD/entity is preserved only as inert raw text, never resolved.
    assert event.event_data == {}
    assert "root:" not in (event.raw_xml or "")


def test_normalize_xml_bomb_is_bounded() -> None:
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        "<Event><System><EventID>&b;</EventID></System></Event>"
    )
    event = parsed(payload)
    assert event.warnings


def test_normalize_truncates_long_fields_and_xml() -> None:
    long_value = "x" * 500
    event = parsed(
        sample_event_xml(data={"LongValue": long_value}),
        evtx_max_field_length=50,
        evtx_max_raw_xml_bytes=100,
    )
    assert len(event.event_data["LongValue"]) == 50
    assert event.truncated is True
    assert len(event.raw_xml) == 100
    assert any("truncated" in warning for warning in event.warnings)


def test_normalize_timestamp_and_hex_ids() -> None:
    xml = sample_event_xml(
        timestamp="2019-03-19 20:55:20.018962+00:00",
        process_id=0,
        thread_id=0,
    ).replace('ProcessID="0"', 'ProcessID="0x1f"').replace(
        'ThreadID="0"', 'ThreadID="0x0"'
    )
    event = parsed(xml)
    assert event.timestamp_utc == "2019-03-19T20:55:20.018962Z"
    assert event.process_id == 31
    assert event.thread_id == 0


def test_normalize_missing_fields() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Channel></Channel></System></Event>"
    )
    event = normalize_event(
        log_id="log_x",
        raw=type(
            "Raw",
            (),
            {
                "record_id": 1,
                "chunk_number": 0,
                "xml": xml,
                "xml_too_large": False,
                "error": None,
            },
        )(),
        xml_text=xml,
        settings=settings(),
        channel_fallback=None,
    )
    assert event.channel is None
    assert event.event_id is None
    assert event.timestamp_utc is None
    assert event.event_data == {}


def test_rust_backend_reads_synthetic_empty_log() -> None:
    backend = EvtxBackend(SYNTHETIC_EMPTY, settings())
    records = list(backend.records(time.monotonic() + 10))
    assert records == []


def test_backend_rejects_non_evtx(tmp_path) -> None:
    from dfir_browser.core.evtx.models import EvtxNotEvtx

    bad = tmp_path / "x.evtx"
    bad.write_bytes(b"nope" * 100)
    with pytest.raises(EvtxNotEvtx):
        EvtxBackend(bad, settings())


def test_backend_rejects_truncated_chunk(tmp_path) -> None:
    """A header with no chunk data must fail cleanly, not crash."""
    data = synthetic_empty_evtx(1)[:4096 + 100]
    path = tmp_path / "truncated.evtx"
    path.write_bytes(data)
    backend = EvtxBackend(path, settings())
    # A truncated chunk must yield no records or a handled error, never crash.
    try:
        records = list(backend.records(time.monotonic() + 5))
    except Exception as exc:  # noqa: BLE001 - must be a DFIR error, not a crash
        assert getattr(exc, "code", "") or "evtx" in str(exc).lower()
    else:
        assert records == [] or all(r.error or r.xml for r in records)


# ---------------------------------------------------------------------------
# presets
# ---------------------------------------------------------------------------
def test_presets_are_structured_and_unique() -> None:
    ids = [preset.preset_id for preset in PRESETS]
    assert len(ids) == len(set(ids))
    for preset in PRESETS:
        data = preset.to_dict()
        assert data["rule_id"].startswith("preset.")
        assert data["event_ids"]
        assert data["limitations"]
    assert get_preset("authentication").event_ids == (4624, 4625, 4634, 4647, 4648, 4672)
    assert 7045 in get_preset("service_persistence").event_ids
    assert 4104 in get_preset("powershell").event_ids
    assert 1102 in get_preset("log_clearing").event_ids
    assert {3, 7, 11, 13} <= set(get_preset("sysmon_network_file_registry").event_ids)
    assert len(list_presets()) == len(PRESETS)


def test_unknown_preset_raises() -> None:
    with pytest.raises(ValueError):
        get_preset("does-not-exist")


# ---------------------------------------------------------------------------
# index helpers
# ---------------------------------------------------------------------------
def test_fts_query_sanitises_tokens() -> None:
    assert _fts_query("SysInternals.exe") == '"SysInternals.exe"'
    quoted = _fts_query('x" OR "y') or ""
    # Every token is quoted, so FTS operators cannot be injected as syntax.
    assert quoted.count('"') % 2 == 0
    assert _fts_query("...") is None
    assert _fts_query("") is None
    long_query = " ".join(f"token{i}" for i in range(40))
    assert (_fts_query(long_query) or "").count("AND") <= 15


def test_escape_like() -> None:
    assert escape_like("100%") == "100\\%"
    assert escape_like("a_b") == "a\\_b"


def test_store_query_pagination_and_filters(tmp_path) -> None:
    store = EvtxStore(tmp_path / "evtx.db")
    store.ensure_schema()
    log = EvtxLog(
        log_id="log_0123456789abcdef",
        evidence_id="ev_0123456789ab",
        entry_id=1,
        inode=2,
        evidence_path="Windows/System32/winevt/Logs/Security.evtx",
        filename="Security.evtx",
        detected_channel="Security",
        size=69632,
        sha256="a" * 64,
        allocated=True,
        deleted=False,
        parser="evtx",
        parser_version="0.15.0-v1",
        index_schema=1,
        status="ready",
        phase="ready",
        records_seen=0,
        records_indexed=0,
        parse_errors=0,
        first_event_time=None,
        last_event_time=None,
    )
    store.upsert_log(log)
    from dfir_browser.core.evtx.models import EvtxEvent

    events = []
    for index in range(12):
        events.append(
            EvtxEvent(
                log_id=log.log_id,
                record_id=index + 1,
                chunk_number=0,
                timestamp_utc=f"2022-11-15T21:{index:02d}:00.000000Z",
                timestamp_raw=None,
                channel="Security",
                provider_name="Microsoft-Windows-Security-Auditing",
                provider_guid=None,
                event_id=4688 if index % 2 == 0 else 4624,
                event_id_raw=None,
                qualifiers=None,
                level=0,
                level_name="LogAlways",
                task=None,
                opcode=None,
                keywords=None,
                computer="SYNTHETIC-PC",
                user_sid="S-1-5-18",
                process_id=4,
                thread_id=32,
                activity_id=None,
                related_activity_id=None,
                version=2,
                event_data={"NewProcessName": f"C:\\Synthetic\\f{index}.exe"},
                user_data=None,
                rendering_info=None,
                message=None,
                message_status="message_unavailable",
                raw_xml="<Event/>",
                raw_xml_sha256="b" * 64,
                summary=f"EventID {4688 if index % 2 == 0 else 4624}",
                truncated=False,
            )
        )
    assert store.insert_events(log.log_id, events) == 12

    page = store.query_events(EventQuery(log_ids=[log.log_id], page_size=5))
    assert page.total == 12
    assert len(page.events) == 5
    assert page.pages == 3
    page3 = store.query_events(
        EventQuery(log_ids=[log.log_id], page=3, page_size=5)
    )
    assert len(page3.events) == 2

    filtered = store.query_events(
        EventQuery(log_ids=[log.log_id], event_ids=[4688], page_size=20)
    )
    assert filtered.total == 6

    desc = store.query_events(
        EventQuery(log_ids=[log.log_id], sort_dir="desc", page_size=1)
    )
    assert desc.events[0].record_id == 12

    text = store.query_events(
        EventQuery(log_ids=[log.log_id], text="f3.exe", page_size=5)
    )
    assert text.total == 1
    assert text.events[0].record_id == 4 if text.total else True

    context = store.context(log.log_id, 6, 2, 2)
    assert [event.record_id for event in context] == [4, 5, 6, 7, 8]

    summary = store.summary([log.log_id], time_from=None, time_to=None, top_n=5)
    assert summary.total_events == 12
    assert summary.by_event_id["4688"] == 6
    assert summary.by_channel["Security"] == 12
    assert summary.time_from.startswith("2022-11-15T21:00")


def test_store_cache_fields_and_cache_hit(tmp_path) -> None:
    store = EvtxStore(tmp_path / "evtx.db")
    store.ensure_schema()
    log = EvtxLog(
        log_id=log_id_for("ev_0123456789ab", 42),
        evidence_id="ev_0123456789ab",
        entry_id=42,
        inode=43,
        evidence_path="Windows/System32/winevt/Logs/System.evtx",
        filename="System.evtx",
        detected_channel="System",
        size=69632,
        sha256="c" * 64,
        allocated=True,
        deleted=False,
        parser="evtx",
        parser_version="0.15.0-v1",
        index_schema=1,
        status="ready",
        phase="ready",
        records_seen=3,
        records_indexed=3,
        parse_errors=0,
        first_event_time="2022-11-15T21:00:00Z",
        last_event_time="2022-11-15T22:00:00Z",
        extract_relpath="cases/case01/exports/system.evtx",
        completed_at="2022-11-16T00:00:00Z",
    )
    store.upsert_log(log)
    found = store.find_by_entry("ev_0123456789ab", 42)
    assert found is not None
    assert found.log_id == log.log_id
    assert found.records_indexed == 3
    assert found.first_event_time == "2022-11-15T21:00:00Z"
    assert store.find_by_entry("ev_0123456789ab", 999) is None
