"""EVTX fixtures.

The committed `.evtx` fixture is a **synthetic, empty** Windows Event Log file
built by `synthetic_empty_evtx()` in this module: a valid `ElfFile` header plus
one empty `ElfChnk` chunk. It contains no user data.

Real event records cannot be produced here without a BinXML writer, so record
parsing, normalization and job behaviour are tested with:

* synthetic XML strings fed straight to the normalizer (`sample_event_xml`), and
* a fake parser backend that yields those synthetic records.

No real event log, user SID, computer name or command line from the evidence
image is committed to this repository.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SYNTHETIC_EMPTY = FIXTURES / "synthetic-empty.evtx"


def synthetic_empty_evtx(chunks: int = 1) -> bytes:
    """A valid EVTX header plus empty chunks. No records, no user data."""
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    struct.pack_into("<Q", chunk, 8, 0)
    struct.pack_into("<Q", chunk, 16, 0)
    struct.pack_into("<Q", chunk, 24, 0)
    struct.pack_into("<Q", chunk, 32, 0)
    struct.pack_into("<I", chunk, 40, 128)
    struct.pack_into("<I", chunk, 44, 512)
    struct.pack_into("<I", chunk, 48, 65536 - 512)
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", header, 8, 0)
    struct.pack_into("<Q", header, 16, chunks - 1)
    struct.pack_into("<Q", header, 24, 1)
    struct.pack_into("<I", header, 32, 128)
    struct.pack_into("<H", header, 36, 1)
    struct.pack_into("<H", header, 38, 3)
    struct.pack_into("<H", header, 40, 4096)
    struct.pack_into("<H", header, 42, chunks)
    return bytes(header) + bytes(chunk) * chunks


def sample_event_xml(
    *,
    event_id: int = 4688,
    timestamp: str = "2022-11-15T21:18:10.740504Z",
    channel: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
    computer: str = "SYNTHETIC-PC",
    user_sid: str = "S-1-5-18",
    process_id: int = 4,
    thread_id: int = 32,
    data: dict[str, str] | None = None,
    duplicate_data: list[tuple[str, str]] | None = None,
    level: int = 0,
    user_data: str | None = None,
    message: str | None = None,
    extra_system: str = "",
) -> str:
    """Build a synthetic event XML document (no real evidence content)."""
    payload = data if data is not None else {
        "SubjectUserSid": "S-1-5-18",
        "NewProcessName": "C:\\Synthetic\\sample.exe",
        "CommandLine": "sample.exe -flag",
    }
    data_xml = "".join(
        f'<Data Name="{name}">{value}</Data>' for name, value in payload.items()
    )
    if duplicate_data:
        data_xml += "".join(
            f'<Data Name="{name}">{value}</Data>'
            for name, value in duplicate_data
        )
    user_xml = (
        f"<UserData><Synthetic xmlns=\"urn:synthetic\">{user_data}</Synthetic></UserData>"
        if user_data is not None
        else ""
    )
    rendering = (
        f'<RenderingInfo Culture="en-US"><Message>{message}</Message></RenderingInfo>'
        if message is not None
        else ""
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        f'<Provider Name="{provider}" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>'
        f"<EventID>{event_id}</EventID>"
        "<Version>2</Version>"
        f"<Level>{level}</Level>"
        "<Task>13312</Task><Opcode>0</Opcode>"
        "<Keywords>0x8020000000000000</Keywords>"
        f'<TimeCreated SystemTime="{timestamp}"/>'
        "<EventRecordID>1</EventRecordID>"
        '<Correlation ActivityID="{11111111-1111-1111-1111-111111111111}" '
        'RelatedActivityID="{22222222-2222-2222-2222-222222222222}"/>'
        f'<Execution ProcessID="{process_id}" ThreadID="{thread_id}"/>'
        f"<Channel>{channel}</Channel>"
        f"<Computer>{computer}</Computer>"
        f'<Security UserID="{user_sid}"/>'
        f"{extra_system}"
        "</System>"
        f"<EventData>{data_xml}</EventData>"
        f"{user_xml}{rendering}"
        "</Event>"
    )


@dataclass
class FakeRawEvent:
    record_id: int
    chunk_number: int | None
    xml: str
    xml_too_large: bool = False
    error: str | None = None


class FakeBackend:
    """Stands in for the Rust parser; yields synthetic XML records."""

    name = "evtx"
    version = "0.15.0"

    events: list[FakeRawEvent] = []
    fail: Exception | None = None
    header_signature_valid = True

    def __init__(self, path, settings):
        self.path = Path(path)
        self.settings = settings
        self.header = type(
            "Header",
            (),
            {
                "signature_valid": self.header_signature_valid,
                "size": None,
                "chunk_count": 1,
                "flags": 0,
                "error": None,
                "to_dict": lambda self_: {},
            },
        )()

    def records(self, deadline):
        for event in self.events:
            yield event
        if self.fail is not None:
            raise self.fail

    def close(self):
        pass


def synthetic_events() -> list[FakeRawEvent]:
    return [
        FakeRawEvent(
            record_id=1,
            chunk_number=0,
            xml=sample_event_xml(
                timestamp="2022-11-15T21:18:10.740504Z",
                data={"NewProcessName": "C:\\Synthetic\\sample.exe"},
            ),
        ),
        FakeRawEvent(
            record_id=2,
            chunk_number=0,
            xml=sample_event_xml(
                event_id=4624,
                timestamp="2022-11-15T21:19:00.000000Z",
                data={"TargetUserName": "synthetic-user"},
            ),
        ),
        FakeRawEvent(
            record_id=3,
            chunk_number=0,
            xml=sample_event_xml(
                event_id=7045,
                channel="System",
                provider="Service Control Manager",
                timestamp="2022-11-15T21:20:00.000000Z",
                data={"ServiceName": "SyntheticSvc"},
            ),
        ),
    ]


def write_event_json(path: Path, events: list[dict]) -> None:
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")
