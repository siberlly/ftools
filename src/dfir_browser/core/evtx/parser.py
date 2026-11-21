from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .detector import EvtxHeader, inspect_evtx_header
from .models import EvtxError, EvtxNotEvtx

MAX_XML_DEPTH = 64
MAX_XML_NODES = 20_000

XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class EvtxTimeout(EvtxError):
    default_code = "evtx_timeout"


class EvtxLimit(EvtxError):
    default_code = "evtx_limit"


class EvtxParseError(EvtxError):
    default_code = "evtx_parse_error"


@dataclass(slots=True)
class RawEvent:
    record_id: int
    chunk_number: int | None
    xml: str
    xml_too_large: bool = False
    error: str | None = None


@dataclass(slots=True)
class ParsedEvent:
    record_id: int
    chunk_number: int | None
    timestamp_utc: str | None
    timestamp_raw: str | None
    channel: str | None
    provider_name: str | None
    provider_guid: str | None
    event_id: int | None
    event_id_raw: str | None
    qualifiers: int | None
    level: int | None
    task: int | None
    opcode: int | None
    keywords: str | None
    computer: str | None
    user_sid: str | None
    process_id: int | None
    thread_id: int | None
    activity_id: str | None
    related_activity_id: str | None
    version: int | None
    event_data: dict[str, Any]
    user_data: str | None
    rendering_info: str | None
    message: str | None
    message_status: str
    raw_xml: str | None
    raw_xml_sha256: str | None
    summary: str | None
    truncated: bool
    warnings: list[str] = field(default_factory=list)


_SAFE_XML_PARSER = None


def _parser():
    global _SAFE_XML_PARSER
    if _SAFE_XML_PARSER is None:
        from defusedxml import ElementTree as SafeET

        _SAFE_XML_PARSER = SafeET
    return _SAFE_XML_PARSER


def parse_xml_safely(text: str):
    """Parse with defusedxml: no DTD, entities, external fetch or network."""
    return _parser().fromstring(text)


def _int(value: str | None, *, base: int = 10) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, base) if base != 10 else int(text)
    except ValueError:
        try:
            return int(text, 0)
        except ValueError:
            return None


def _iso(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    for candidate in (text, text.replace(" ", "T", 1)):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")
        except ValueError:
            continue
    return None


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _collect_event_data(element) -> tuple[dict[str, Any], bool]:
    """EventData <Data Name=...> into a map that never silently overwrites."""
    data: dict[str, Any] = {}
    truncated = False
    for child in list(element):
        if _local(child.tag) != "Data":
            continue
        name = child.attrib.get("Name") or "(unnamed)"
        value = (child.text or "").strip()
        if name in data:
            existing = data[name]
            if isinstance(existing, list):
                existing.append(value)
            else:
                data[name] = [existing, value]
        else:
            data[name] = value
    return data, truncated


def _collect_user_data(element) -> str | None:
    text = "".join(element.itertext()).strip()
    return text or None


def normalize_event(
    *,
    log_id: str,
    raw: RawEvent,
    xml_text: str,
    settings,
    channel_fallback: str | None,
) -> ParsedEvent:
    warnings: list[str] = []
    max_field = int(settings.evtx_max_field_length)
    max_xml = int(settings.evtx_max_raw_xml_bytes)
    timestamp_utc = None
    timestamp_raw = None
    channel = None
    provider_name = None
    provider_guid = None
    event_id = None
    event_id_raw = None
    qualifiers = None
    level = None
    task = None
    opcode = None
    keywords = None
    computer = None
    user_sid = None
    process_id = None
    thread_id = None
    activity_id = None
    related_activity_id = None
    version = None
    event_data: dict[str, Any] = {}
    user_data = None
    rendering_info = None
    message = None
    message_status = "message_unavailable"
    truncated = False

    try:
        root = parse_xml_safely(xml_text)
    except Exception as exc:  # noqa: BLE001 - malformed XML must not crash the job
        return ParsedEvent(
            record_id=raw.record_id,
            chunk_number=raw.chunk_number,
            timestamp_utc=None,
            timestamp_raw=None,
            channel=channel_fallback,
            provider_name=None,
            provider_guid=None,
            event_id=None,
            event_id_raw=None,
            qualifiers=None,
            level=None,
            task=None,
            opcode=None,
            keywords=None,
            computer=None,
            user_sid=None,
            process_id=None,
            thread_id=None,
            activity_id=None,
            related_activity_id=None,
            version=None,
            event_data={},
            user_data=None,
            rendering_info=None,
            message=None,
            message_status="message_unavailable",
            raw_xml=xml_text[:max_xml],
            raw_xml_sha256=hashlib.sha256(xml_text.encode("utf-8", "replace")).hexdigest(),
            summary="invalid XML event",
            truncated=len(xml_text) > max_xml,
            warnings=[f"invalid XML: {str(exc)[:200]}"],
        )

    system = None
    for child in root:
        tag = _local(child.tag)
        if tag == "System":
            system = child
        elif tag == "EventData":
            event_data, _ = _collect_event_data(child)
        elif tag == "UserData":
            user_data = _collect_user_data(child)
        elif tag == "RenderingInfo":
            # RenderingInfo may carry the message as an attribute or as a
            # <Message> child element depending on the producer.
            message = (child.attrib.get("Message") or "").strip() or None
            if not message:
                for item in child:
                    if _local(item.tag) == "Message":
                        message = (item.text or "").strip() or None
                        if message:
                            break
            rendering_info = "".join(child.itertext()).strip() or None
            if message:
                message_status = "available"

    if system is not None:
        for node in system:
            tag = _local(node.tag)
            if tag == "Provider":
                provider_name = node.attrib.get("Name")
                provider_guid = node.attrib.get("Guid")
            elif tag == "EventID":
                event_id_raw = (node.text or "").strip() or None
                event_id = _int(event_id_raw)
                qualifiers = _int(node.attrib.get("Qualifiers"))
            elif tag == "Version":
                version = _int(node.text)
            elif tag == "Level":
                level = _int(node.text)
            elif tag == "Task":
                task = _int(node.text)
            elif tag == "Opcode":
                opcode = _int(node.text)
            elif tag == "Keywords":
                keywords = (node.text or "").strip() or None
            elif tag == "TimeCreated":
                timestamp_raw = node.attrib.get("SystemTime")
                timestamp_utc = _iso(timestamp_raw)
            elif tag == "Correlation":
                activity_id = node.attrib.get("ActivityID") or None
                related_activity_id = (
                    node.attrib.get("RelatedActivityID") or None
                )
            elif tag == "Execution":
                process_id = _int(node.attrib.get("ProcessID"), base=0)
                thread_id = _int(node.attrib.get("ThreadID"), base=0)
            elif tag == "Channel":
                channel = (node.text or "").strip() or None
            elif tag == "Computer":
                computer = (node.text or "").strip() or None
            elif tag == "Security":
                user_sid = node.attrib.get("UserID") or None

    channel = channel or channel_fallback
    if not timestamp_utc and timestamp_raw:
        warnings.append("timestamp could not be normalized")

    # Decode long structured fields with an explicit truncation flag.
    for key, value in list(event_data.items()):
        if isinstance(value, str) and len(value) > max_field:
            event_data[key], cut = _truncate(value, max_field)
            truncated = truncated or cut
            warnings.append(f"EventData {key} truncated")

    raw_kept = xml_text[:max_xml]
    raw_truncated = len(xml_text) > max_xml
    if raw_truncated:
        warnings.append("raw XML truncated for storage")

    summary_bits = []
    if event_id is not None:
        summary_bits.append(f"EventID {event_id}")
    if event_data:
        for key in ("Image", "NewProcessName", "ProcessName", "CommandLine", "ServiceName", "TaskName"):
            if key in event_data and isinstance(event_data[key], str):
                value = event_data[key]
                summary_bits.append(f"{key}={value[:120]}")
                break

    return ParsedEvent(
        record_id=raw.record_id,
        chunk_number=raw.chunk_number,
        timestamp_utc=timestamp_utc,
        timestamp_raw=timestamp_raw,
        channel=channel,
        provider_name=provider_name,
        provider_guid=provider_guid,
        event_id=event_id,
        event_id_raw=event_id_raw,
        qualifiers=qualifiers,
        level=level,
        task=task,
        opcode=opcode,
        keywords=keywords,
        computer=computer,
        user_sid=user_sid,
        process_id=process_id,
        thread_id=thread_id,
        activity_id=activity_id,
        related_activity_id=related_activity_id,
        version=version,
        event_data=event_data,
        user_data=user_data,
        rendering_info=rendering_info,
        message=message,
        message_status=message_status,
        raw_xml=raw_kept,
        raw_xml_sha256=hashlib.sha256(
            xml_text.encode("utf-8", "replace")
        ).hexdigest(),
        summary="; ".join(summary_bits)[:512] or None,
        truncated=truncated or raw_truncated,
        warnings=warnings,
    )


class EvtxBackend:
    """Rust ``evtx`` backend behind a narrow adapter interface.

    ``python-evtx`` serialises a full ElementTree per record (~4 ms/record on
    the 4.2k-record Security log); the Rust parser yields the same XML in about
    3 microseconds/record. Records still go through the same safe XML
    normalizer before storage.
    """

    name = "evtx"
    version = "0.15.0"

    def __init__(self, path: Path | str, settings) -> None:
        self.path = Path(path)
        self.settings = settings
        self.header: EvtxHeader = inspect_evtx_header(self.path)
        if not self.header.signature_valid:
            raise EvtxNotEvtx(
                "file is not a valid EVTX log",
                details={"error": self.header.error},
            )

    def records(self, deadline: float) -> Iterator[RawEvent]:
        try:
            from evtx import PyEvtxParser  # type: ignore
        except Exception as exc:  # pragma: no cover - dependency guard
            raise EvtxError(
                "evtx parser is not installed",
                code="evtx_parser_unavailable",
            ) from exc
        max_xml = int(self.settings.evtx_max_event_xml_bytes)
        max_records = int(self.settings.evtx_max_records)
        hard_deadline = min(
            deadline,
            time.monotonic() + float(self.settings.evtx_parser_timeout),
        )
        try:
            parser = PyEvtxParser(str(self.path))
        except Exception as exc:
            raise EvtxError(
                f"cannot open EVTX log: {exc}"[:400],
                code="evtx_open_failed",
            ) from exc
        emitted = 0
        try:
            iterator = parser.records()
        except Exception as exc:
            raise EvtxError(
                f"cannot iterate EVTX records: {exc}"[:400],
                code="evtx_open_failed",
            ) from exc
        while True:
            if time.monotonic() > hard_deadline:
                raise EvtxTimeout("EVTX parsing timed out")
            try:
                record = next(iterator)
            except StopIteration:
                break
            except Exception as exc:  # noqa: BLE001 - corrupt chunk/record
                emitted += 1
                yield RawEvent(
                    record_id=emitted,
                    chunk_number=None,
                    xml="",
                    error=f"parser error: {str(exc)[:300]}",
                )
                if emitted >= max_records:
                    raise EvtxLimit(
                        f"EVTX record limit {max_records} reached"
                    )
                continue
            emitted += 1
            if emitted > max_records:
                raise EvtxLimit(f"EVTX record limit {max_records} reached")
            try:
                record_id = int(record.get("event_record_id") or emitted)
            except (TypeError, ValueError):
                record_id = emitted
            xml_text = record.get("data") or ""
            if isinstance(xml_text, bytes):
                xml_text = xml_text.decode("utf-8", "replace")
            if not xml_text:
                yield RawEvent(
                    record_id=record_id,
                    chunk_number=None,
                    xml="",
                    error="parser returned no record data",
                )
                continue
            too_large = len(xml_text.encode("utf-8", "replace")) > max_xml
            yield RawEvent(
                record_id=record_id,
                chunk_number=(
                    int(record["chunk_num"])
                    if record.get("chunk_num") is not None
                    else None
                ),
                xml=xml_text,
                xml_too_large=too_large,
            )
