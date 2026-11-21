from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .triage_models import AnalyzerResult, TriageFinding

CHUNK = 1024 * 1024
STRING_CHUNK = 1024 * 1024

PRINTABLE_ASCII = frozenset(range(0x20, 0x7F))

FINDING_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "url",
        re.compile(r"https?://[^\s\"'<>]{4,2048}", re.IGNORECASE),
        "HTTP(S) URL in a printable string",
    ),
    (
        "ipv4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        "IPv4 address in a printable string",
    ),
    (
        "domain",
        re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|local|"
            r"internal|co|uk|de|fr|jp|kr)\b",
            re.IGNORECASE,
        ),
        "domain name in a printable string",
    ),
    (
        "email",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"
        ),
        "email address in a printable string",
    ),
    (
        "windows_path",
        re.compile(
            r"(?:\b[A-Za-z]:\\[^\r\n\t\"'<>|]{1,512})"
            r"|(?:\\\\[A-Za-z0-9._-]{1,64}\\[^\r\n\t\"'<>|]{1,512})"
        ),
        "Windows path in a printable string",
    ),
    (
        "registry_path",
        re.compile(
            r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\r\n\t\"']{2,512}",
            re.IGNORECASE,
        ),
        "Windows registry path in a printable string",
    ),
    (
        "powershell",
        re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE),
        "PowerShell invocation reference",
    ),
    (
        "cmd",
        re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
        "cmd.exe reference",
    ),
    (
        "rundll32",
        re.compile(r"\brundll32(?:\.exe)?\b", re.IGNORECASE),
        "rundll32 reference",
    ),
    (
        "regsvr32",
        re.compile(r"\bregsvr32(?:\.exe)?\b", re.IGNORECASE),
        "regsvr32 reference",
    ),
    (
        "mshta",
        re.compile(r"\bmshta(?:\.exe)?\b", re.IGNORECASE),
        "mshta reference",
    ),
    (
        "certutil",
        re.compile(r"\bcertutil(?:\.exe)?\b", re.IGNORECASE),
        "certutil reference",
    ),
    (
        "base64",
        re.compile(
            r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,512}(?:={1,2})?"
            r"(?![A-Za-z0-9+/])"
        ),
        "base64-like string (not decoded)",
    ),
    (
        "mutex",
        re.compile(
            r"(?i)(?:(?:Global|Local)\\[A-Za-z0-9_.{}:@-]{3,128}"
            r"|mutex[_:=\s-]{1,4}[A-Za-z0-9_.{}:@-]{3,128})"
        ),
        "mutex-like string",
    ),
    (
        "user_agent",
        re.compile(
            r"(?i)(?:user-agent:\s*[^\r\n]{3,300}"
            r"|Mozilla/\d\.\d[^\r\n]{0,250})"
        ),
        "HTTP user-agent string",
    ),
    (
        "executable_name",
        re.compile(
            r"(?i)\b[A-Za-z0-9_.-]{1,120}\."
            r"(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js)\b"
        ),
        "executable or script filename reference",
    ),
)


class AnalyzerDeadline(Exception):
    pass


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise AnalyzerDeadline("triage job deadline exceeded")
    return value


def hash_file(path: Path, deadline: float) -> tuple[dict[str, str], int]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            if total % (8 * CHUNK) == 0:
                remaining(deadline)
            block = handle.read(CHUNK)
            if not block:
                break
            total += len(block)
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return (
        {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()},
        total,
    )


def _entropy(counter: list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    value = 0.0
    for count in counter:
        if count:
            probability = count / total
            value -= probability * math.log2(probability)
    return round(value, 6)


def entropy_analysis(
    path: Path, settings, deadline: float
) -> AnalyzerResult:
    start = time.monotonic()
    counter = [0] * 256
    total = 0
    chunks: list[float] = []
    chunk_size = int(settings.triage_entropy_chunk_size)
    max_bytes = int(settings.triage_entropy_max_bytes)
    chunk_limit = max(1, max_bytes // max(1, chunk_size))
    current = [0] * 256
    current_len = 0
    chunks_truncated = False
    try:
        with open(path, "rb") as handle:
            while True:
                if total % (8 * CHUNK) == 0:
                    remaining(deadline)
                block = handle.read(CHUNK)
                if not block:
                    break
                for byte in block:
                    counter[byte] += 1
                total += len(block)
                if len(chunks) < chunk_limit:
                    position = 0
                    while position < len(block):
                        take = min(chunk_size - current_len, len(block) - position)
                        for byte in block[position : position + take]:
                            current[byte] += 1
                        current_len += take
                        position += take
                        if current_len == chunk_size:
                            chunks.append(_entropy(current, current_len))
                            current = [0] * 256
                            current_len = 0
                            if len(chunks) >= chunk_limit:
                                chunks_truncated = True
                                break
                else:
                    chunks_truncated = True
        if current_len:
            chunks.append(_entropy(current, current_len))
        return AnalyzerResult(
            name="entropy",
            status="ok",
            duration_ms=(time.monotonic() - start) * 1000.0,
            data={
                "whole": _entropy(counter, total),
                "bytes": total,
                "chunk_size": chunk_size,
                "chunks": chunks,
                "chunks_truncated": chunks_truncated,
            },
            truncated=chunks_truncated,
        )
    except AnalyzerDeadline as exc:
        return AnalyzerResult(
            name="entropy",
            status="timeout",
            duration_ms=(time.monotonic() - start) * 1000.0,
            error=str(exc),
        )


class StringScanner:
    def __init__(self, settings) -> None:
        self.min_len = max(1, int(settings.triage_min_string_length))
        self.max_len = max(self.min_len, int(settings.triage_max_string_length))
        self.max_total = max(1, int(settings.triage_max_strings))
        self.strings: list[tuple[str, int, str]] = []
        self.truncated = False
        self._ascii: list[int] = []
        self._ascii_start: int | None = None
        self._ascii_truncated = False
        self._utf16: list[int] = []
        self._utf16_start: int | None = None
        self._utf16_truncated = False
        self._utf16_low: int | None = None
        self._utf16_low_offset: int | None = None
        self._offset = 0

    @property
    def full(self) -> bool:
        return len(self.strings) >= self.max_total

    def _emit(self, encoding: str, start: int | None, chars: list[int], truncated: bool) -> None:
        if start is None or len(chars) < self.min_len or self.full:
            return
        value = "".join(chr(code) for code in chars[: self.max_len])
        self.strings.append((encoding, start, value))
        if len(self.strings) >= self.max_total:
            self.truncated = True

    def _flush_ascii(self) -> None:
        if self._ascii:
            self._emit("ascii", self._ascii_start, self._ascii, self._ascii_truncated)
        self._ascii = []
        self._ascii_start = None
        self._ascii_truncated = False

    def _flush_utf16(self) -> None:
        if self._utf16:
            self._emit(
                "utf-16le",
                self._utf16_start,
                self._utf16,
                self._utf16_truncated,
            )
        self._utf16 = []
        self._utf16_start = None
        self._utf16_truncated = False
        self._utf16_low = None
        self._utf16_low_offset = None

    def feed(self, data: bytes, deadline: float) -> None:
        for index, byte in enumerate(data):
            if index % 65536 == 0:
                remaining(deadline)
            offset = self._offset + index
            # ASCII run
            if byte in PRINTABLE_ASCII:
                if self._ascii_start is None:
                    self._ascii_start = offset
                if len(self._ascii) < self.max_len:
                    self._ascii.append(byte)
                else:
                    self._ascii_truncated = True
            else:
                self._flush_ascii()
            # UTF-16LE run: printable low byte followed by 0x00
            if self._utf16_low is None:
                if byte in PRINTABLE_ASCII:
                    self._utf16_low = byte
                    self._utf16_low_offset = offset
                else:
                    self._flush_utf16()
            else:
                if byte == 0:
                    if self._utf16_start is None:
                        self._utf16_start = self._utf16_low_offset
                    if len(self._utf16) < self.max_len:
                        self._utf16.append(self._utf16_low)
                    else:
                        self._utf16_truncated = True
                    self._utf16_low = None
                    self._utf16_low_offset = None
                else:
                    self._flush_utf16()
                    if byte in PRINTABLE_ASCII:
                        self._utf16_low = byte
                        self._utf16_low_offset = offset
        self._offset += len(data)

    def finish(self) -> list[tuple[str, int, str]]:
        self._flush_ascii()
        self._flush_utf16()
        return self.strings


def scan_strings(path: Path, settings, deadline: float) -> tuple[list[tuple[str, int, str]], bool]:
    scanner = StringScanner(settings)
    with open(path, "rb") as handle:
        while not scanner.full:
            remaining(deadline)
            block = handle.read(STRING_CHUNK)
            if not block:
                break
            scanner.feed(block, deadline)
    return scanner.finish(), scanner.truncated


def derive_findings(
    strings: list[tuple[str, int, str]], settings
) -> list[TriageFinding]:
    max_findings = max(1, int(settings.triage_max_findings))
    seen: set[tuple[str, str, str]] = set()
    findings: list[TriageFinding] = []
    for encoding, offset, value in strings:
        if len(findings) >= max_findings:
            break
        for category, pattern, reason in FINDING_RULES:
            for match in pattern.finditer(value):
                text = match.group(0)[:512]
                key = (category, text, encoding)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    TriageFinding(
                        category=category,
                        value=text,
                        encoding=encoding,
                        offset=offset + match.start(),
                        rule_id=f"string.{category}.v1",
                        reason=reason,
                    )
                )
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
    return findings


def run_file_identification(
    path: Path, settings, runner, deadline: float
) -> AnalyzerResult:
    start = time.monotonic()
    command = list(settings.triage_file_command)
    if not command:
        return AnalyzerResult(
            name="file",
            status="unavailable",
            error="file command is not configured",
        )
    limit = int(settings.triage_max_tool_output)
    timeout = min(float(settings.triage_analyzer_timeout), remaining(deadline))
    try:
        mime_result = runner.run(
            [*command, "-b", "--mime-type", str(path)],
            timeout=timeout,
            evidence_id=None,
            max_output_bytes=limit,
        )
        type_result = runner.run(
            [*command, "-b", str(path)],
            timeout=timeout,
            evidence_id=None,
            max_output_bytes=limit,
        )
    except OSError as exc:
        return AnalyzerResult(
            name="file",
            status="unavailable",
            duration_ms=(time.monotonic() - start) * 1000.0,
            error=f"cannot execute file: {exc}",
        )
    if mime_result.timed_out or type_result.timed_out:
        return AnalyzerResult(
            name="file",
            status="timeout",
            duration_ms=(time.monotonic() - start) * 1000.0,
            error="file command timed out",
        )
    version = runner.version(command[0])
    if not mime_result.ok and not type_result.ok:
        return AnalyzerResult(
            name="file",
            status="failed",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=version,
            error=(mime_result.stderr or type_result.stderr or "file failed")[:500],
        )
    mime_type = (mime_result.stdout or "").strip().splitlines()
    file_type = (type_result.stdout or "").strip().splitlines()
    return AnalyzerResult(
        name="file",
        status="ok",
        duration_ms=(time.monotonic() - start) * 1000.0,
        version=version,
        data={
            "mime_type": mime_type[0][:128] if mime_type else None,
            "file_type": file_type[0][:512] if file_type else None,
        },
        warnings=(
            ["file output truncated"] if type_result.stdout_truncated else []
        ),
    )


def run_exiftool(path: Path, settings, runner, deadline: float) -> AnalyzerResult:
    start = time.monotonic()
    command = list(settings.triage_exiftool_command)
    if not command:
        return AnalyzerResult(
            name="exiftool",
            status="unavailable",
            error="exiftool command is not configured",
        )
    try:
        version_result = runner.run(
            [*command, "-ver"],
            timeout=min(10.0, remaining(deadline)),
            audit=False,
        )
    except OSError as exc:
        return AnalyzerResult(
            name="exiftool",
            status="unavailable",
            duration_ms=(time.monotonic() - start) * 1000.0,
            error=f"cannot execute exiftool: {exc}",
        )
    version = (version_result.stdout or "").strip().splitlines()
    version_text = version[0][:64] if version else None
    timeout = min(float(settings.triage_analyzer_timeout), remaining(deadline))
    try:
        result = runner.run(
            [*command, "-j", "-G1", "-s", str(path)],
            timeout=timeout,
            max_output_bytes=int(settings.triage_max_tool_output),
        )
    except OSError as exc:
        return AnalyzerResult(
            name="exiftool",
            status="unavailable",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=version_text,
            error=f"cannot execute exiftool: {exc}",
        )
    if result.timed_out:
        return AnalyzerResult(
            name="exiftool",
            status="timeout",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=version_text,
            error="exiftool timed out",
        )
    warnings: list[str] = []
    try:
        payload = json.loads(result.stdout or "[]")
        raw = payload[0] if isinstance(payload, list) and payload else {}
        if not isinstance(raw, dict):
            raw = {}
    except (ValueError, TypeError):
        raw = {}
        warnings.append("exiftool returned malformed JSON")
    if not result.ok and not raw:
        return AnalyzerResult(
            name="exiftool",
            status="failed",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=version_text,
            error=(result.stderr or "exiftool failed")[:500],
        )
    if not result.ok:
        warnings.append(
            "exiftool reported a format warning for this file "
            f"(exit {result.exit_code})"
        )
    if result.stdout_truncated:
        warnings.append("exiftool output was truncated")
    items = []
    for key, value in list(raw.items())[: int(settings.triage_max_exiftool_items)]:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        items.append({"tag": str(key)[:128], "value": str(text)[:1024]})
    return AnalyzerResult(
        name="exiftool",
        status="ok",
        duration_ms=(time.monotonic() - start) * 1000.0,
        version=version_text,
        data={"tags": items, "tag_count": len(raw)},
        warnings=warnings,
        truncated=bool(result.stdout_truncated),
    )


def _yara_rule_files(settings) -> list[Path]:
    directory = settings.triage_rules_directory()
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file()
        and path.suffix.lower() in {".yar", ".yara"}
        and not path.is_symlink()
    )


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.hex()[:128]
    if isinstance(value, dict):
        return {str(k)[:64]: _json_safe(v) for k, v in list(value.items())[:50]}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in list(value)[:50]]
    return str(value)[:256]


def run_yara(path: Path, settings, deadline: float) -> tuple[AnalyzerResult, list[dict[str, Any]]]:
    start = time.monotonic()
    rules = _yara_rule_files(settings)
    files = [rule for rule in rules]
    if not files:
        return (
            AnalyzerResult(
                name="yara",
                status="no_rules",
                duration_ms=(time.monotonic() - start) * 1000.0,
                data={"rule_files": [], "matches": 0},
                warnings=["No active YARA rules"],
            ),
            [],
        )
    try:
        import yara  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency guard
        return (
            AnalyzerResult(
                name="yara",
                status="unavailable",
                duration_ms=(time.monotonic() - start) * 1000.0,
                error=f"yara-python is not available: {exc}",
                data={"rule_files": [rule.name for rule in files]},
            ),
            [],
        )
    namespace_map: dict[str, str] = {}
    for index, rule in enumerate(files):
        slug = re.sub(r"[^A-Za-z0-9_]+", "_", rule.stem).strip("_") or "rules"
        namespace = f"rules_{index}_{slug}"[:64]
        namespace_map[namespace] = str(rule)
    try:
        compiled = yara.compile(filepaths=namespace_map)
    except Exception as exc:
        return (
            AnalyzerResult(
                name="yara",
                status="failed",
                duration_ms=(time.monotonic() - start) * 1000.0,
                error=f"YARA rule compilation failed: {exc}"[:1000],
                data={"rule_files": [rule.name for rule in files]},
            ),
            [],
        )
    version = getattr(yara, "__version__", None)
    timeout = min(float(settings.triage_yara_timeout), remaining(deadline))
    try:
        matches = compiled.match(
            str(path), timeout=max(1, int(math.ceil(timeout)))
        )
    except Exception as exc:
        text = str(exc)
        status = "timeout" if "timeout" in text.lower() else "failed"
        return (
            AnalyzerResult(
                name="yara",
                status=status,
                duration_ms=(time.monotonic() - start) * 1000.0,
                version=str(version) if version else None,
                error=text[:1000],
                data={"rule_files": [rule.name for rule in files]},
            ),
            [],
        )
    max_matches = max(1, int(settings.triage_max_yara_matches))
    payload: list[dict[str, Any]] = []
    truncated = False
    for match in matches:
        if len(payload) >= max_matches:
            truncated = True
            break
        string_hits = []
        for string_match in list(getattr(match, "strings", []) or [])[:20]:
            instances = []
            for instance in list(getattr(string_match, "instances", []) or [])[:5]:
                data = getattr(instance, "matched_data", b"") or b""
                preview = bytes(data[:64]).decode("utf-8", "replace")
                instances.append(
                    {
                        "offset": int(getattr(instance, "offset", 0)),
                        "length": int(getattr(instance, "matched_length", len(data))),
                        "preview": preview,
                    }
                )
            string_hits.append(
                {
                    "identifier": str(getattr(string_match, "identifier", ""))[:64],
                    "instances": instances,
                }
            )
        payload.append(
            {
                "rule": str(getattr(match, "rule", ""))[:256],
                "namespace": str(getattr(match, "namespace", "default"))[:128],
                "tags": [str(tag)[:64] for tag in list(getattr(match, "tags", []) or [])][:20],
                "meta": _json_safe(getattr(match, "meta", {}) or {}),
                "strings": string_hits,
            }
        )
    result = AnalyzerResult(
        name="yara",
        status="ok",
        duration_ms=(time.monotonic() - start) * 1000.0,
        version=str(version) if version else None,
        data={
            "rule_files": [rule.name for rule in files],
            "matches": len(payload),
            "match_limit": max_matches,
        },
        truncated=truncated,
        warnings=([] if payload else ["YARA rules ran; no matches"]),
    )
    return result, payload


def run_pe(path: Path, settings, deadline: float) -> AnalyzerResult:
    start = time.monotonic()
    try:
        import pefile  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency guard
        return AnalyzerResult(
            name="pe",
            status="unavailable",
            duration_ms=(time.monotonic() - start) * 1000.0,
            error=f"pefile is not available: {exc}",
        )
    version = getattr(pefile, "__version__", None)
    with open(path, "rb") as handle:
        magic = handle.read(2)
    if magic != b"MZ":
        return AnalyzerResult(
            name="pe",
            status="skipped",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=str(version) if version else None,
            data={"is_pe": False},
        )
    remaining(deadline)
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
    except Exception as exc:
        return AnalyzerResult(
            name="pe",
            status="failed",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=str(version) if version else None,
            error=f"PE parsing failed: {exc}"[:1000],
            warnings=["PE parser failure is reported as a warning; other analyzers continue."],
        )
    warnings: list[str] = []
    try:
        kind = "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32"
        machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        timestamp = int(pe.FILE_HEADER.TimeDateStamp)
        from datetime import datetime, timezone

        try:
            compiled_at = datetime.fromtimestamp(
                timestamp, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            compiled_at = None
        warnings.append("PE compile timestamp can be forged")
        sections = []
        max_raw_end = 0
        section_limit = 96
        file_size = path.stat().st_size
        for section in list(pe.sections)[:section_limit]:
            name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
            raw_size = int(section.SizeOfRawData)
            virtual_size = int(section.Misc_VirtualSize)
            raw_end = int(section.PointerToRawData) + raw_size
            max_raw_end = max(max_raw_end, raw_end)
            data = b""
            try:
                with open(path, "rb") as section_handle:
                    section_handle.seek(int(section.PointerToRawData))
                    data = section_handle.read(
                        min(
                            int(section.SizeOfRawData),
                            int(settings.triage_entropy_max_bytes),
                        )
                    )
            except Exception:
                pass
            counter = [0] * 256
            for byte in data:
                counter[byte] += 1
            sections.append(
                {
                    "name": name[:64],
                    "raw_size": raw_size,
                    "virtual_size": virtual_size,
                    "entropy": _entropy(counter, len(data)),
                }
            )
        if len(pe.sections) > section_limit:
            warnings.append("section list truncated")
        imports: dict[str, list[str]] = {}
        import_count = 0
        for entry in list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []):
            dll = entry.dll.decode("utf-8", "replace")[:128]
            functions: list[str] = []
            for symbol in list(entry.imports)[:200]:
                name_value = getattr(symbol, "name", None)
                if name_value:
                    functions.append(name_value.decode("utf-8", "replace")[:128])
                else:
                    functions.append(f"ordinal_{getattr(symbol, 'ordinal', '?')}")
                import_count += 1
                if import_count >= 2000:
                    break
            imports[dll] = functions
            if import_count >= 2000:
                warnings.append("import list truncated")
                break
        exports: list[str] = []
        export_entry = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_entry is not None:
            for symbol in list(getattr(export_entry, "symbols", []))[:500]:
                name_value = getattr(symbol, "name", None)
                if name_value:
                    exports.append(name_value.decode("utf-8", "replace")[:128])
                else:
                    exports.append(f"ordinal_{getattr(symbol, 'ordinal', '?')}")
            if len(export_entry.symbols) > 500:
                warnings.append("export list truncated")
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        has_signature = bool(security.VirtualAddress and security.Size)
        pdb_path = None
        for entry in list(getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []):
            try:
                if entry.entry is not None and getattr(entry.entry, "PdbFileName", None):
                    pdb_path = bytes(entry.entry.PdbFileName).rstrip(b"\x00").decode(
                        "utf-8", "replace"
                    )[:512]
                    break
            except Exception:
                continue
        version_info: dict[str, str] = {}
        try:
            for file_info in getattr(pe, "FileInfo", []) or []:
                for entry in file_info:
                    if getattr(entry, "Key", b"") == b"StringFileInfo":
                        for table in entry.StringTable:
                            for key, value in list(table.entries.items())[:50]:
                                version_info[
                                    key.decode("utf-8", "replace")[:64]
                                ] = value.decode("utf-8", "replace")[:256]
        except Exception:
            pass
        overlay_size = max(0, file_size - max_raw_end) if max_raw_end else 0
        if overlay_size:
            warnings.append(f"overlay data present ({overlay_size} bytes)")
        if not has_signature:
            warnings.append("no embedded Authenticode signature directory")
        return AnalyzerResult(
            name="pe",
            status="ok",
            duration_ms=(time.monotonic() - start) * 1000.0,
            version=str(version) if version else None,
            data={
                "is_pe": True,
                "kind": kind,
                "machine": machine,
                "compile_timestamp": timestamp,
                "compile_time_utc": compiled_at,
                "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
                "sections": sections,
                "imports": imports,
                "exports": exports[:500],
                "has_signature_directory": has_signature,
                "signature_size": int(security.Size),
                "pdb_path": pdb_path,
                "version_info": version_info,
                "overlay_size": overlay_size,
                "file_size": file_size,
            },
            warnings=warnings,
        )
    finally:
        try:
            pe.close()
        except Exception:
            pass
