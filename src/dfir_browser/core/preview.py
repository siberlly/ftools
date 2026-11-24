from __future__ import annotations

import codecs
import time
import hashlib
import json
import logging
import os
import stat
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .audit import get_correlation_id
from .config import Settings
from .errors import DFIRError
from .filesystem import FilesystemService
from .index_models import validate_entry_id
from .indexer import FilesystemIndexer
from .models import TRUST_LABEL

logger = logging.getLogger("dfir_browser.preview")

CASE_ID = "case01"
PREVIEW_MODES = ("auto", "text", "hex")
BINARY_MODES = ("hex", "registry")

TEXT_EXTENSIONS = {
    "txt", "log", "text", "md", "markdown", "rst", "cfg", "conf", "config",
    "ini", "inf", "xml", "json", "jsonl", "ndjson", "csv", "tsv", "yaml", "yml",
    "properties", "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "mjs",
    "cjs", "ts", "jsx", "tsx", "py", "rb", "pl", "sh", "bash", "zsh", "php",
    "java", "cs", "c", "h", "cpp", "hpp", "go", "rs", "sql", "html", "htm",
    "css", "scss", "less", "svg", "diff", "patch", "reg", "manifest", "xaml",
    "resx", "sln", "csproj", "vbproj", "gradle", "makefile", "dockerfile",
}

# Extension-less files that are plain text on Windows.
TEXT_BASENAMES = {
    "hosts", "services", "networks", "protocol", "lmhosts", "networks",
    "resolv.conf", "passwd", "group", "shadow", "fstab", "crontab",
    "makefile", "dockerfile", "license", "readme", "changelog", "authors",
    "install", "configure", "notice", "version",
}

MIME_BY_EXTENSION = {
    "txt": "text/plain", "log": "text/plain", "text": "text/plain",
    "md": "text/markdown", "csv": "text/csv", "tsv": "text/tab-separated-values",
    "xml": "application/xml", "json": "application/json",
    "jsonl": "application/x-ndjson", "html": "text/html", "htm": "text/html",
    "css": "text/css", "svg": "image/svg+xml", "js": "text/javascript",
    "ini": "text/plain", "cfg": "text/plain", "conf": "text/plain",
    "ps1": "text/plain", "bat": "text/plain", "cmd": "text/plain",
    "yaml": "application/yaml", "yml": "application/yaml",
    "reg": "text/plain",
}

MAGIC_TYPES = (
    (b"regf", "windows_registry_hive", "application/x-windows-registry"),
    (b"MZ", "pe_executable", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "elf_executable", "application/x-elf"),
    (b"PK\x03\x04", "zip_archive", "application/zip"),
    (b"\xd0\xcf\x11\xe0", "ole_compound", "application/x-ole-storage"),
    (b"\x89PNG\r\n\x1a\n", "png_image", "image/png"),
    (b"\xff\xd8\xff", "jpeg_image", "image/jpeg"),
    (b"GIF87a", "gif_image", "image/gif"),
    (b"GIF89a", "gif_image", "image/gif"),
    (b"BM", "bmp_image", "image/bmp"),
    (b"%PDF", "pdf_document", "application/pdf"),
    (b"\x1f\x8b", "gzip_archive", "application/gzip"),
    (b"SQLite format 3\x00", "sqlite_database", "application/vnd.sqlite3"),
    (b"RIFF", "riff_container", "application/x-riff"),
    (b"II*\x00", "tiff_image", "image/tiff"),
    (b"MM\x00*", "tiff_image", "image/tiff"),
)

# Only raster formats the browser renders safely are served as images.
IMAGE_TYPES = {
    "png_image": "image/png",
    "jpeg_image": "image/jpeg",
    "gif_image": "image/gif",
    "bmp_image": "image/bmp",
    "tiff_image": "image/tiff",
    "webp_image": "image/webp",
}

KNOWN_HIVE_NAMES = {
    "system", "software", "sam", "security", "default", "ntuser.dat",
    "usrclass.dat", "amcache.hve", "bcd", "components", "drivers",
    "elam", "userclass.dat",
}

BOM_ENCODINGS = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

# Control characters that are normal in text files.
_TEXT_CONTROL = {0x09, 0x0A, 0x0D, 0x0C, 0x0B, 0x1B, 0x08}


class PreviewError(DFIRError):
    default_code = "preview_error"


class PreviewRejected(PreviewError):
    default_code = "preview_rejected"


@dataclass(slots=True)
class PreviewResult:
    evidence_id: str
    entry_id: int
    filename: str
    evidence_path: str
    detected_type: str
    preview_mode: str
    encoding: str | None
    offset: int
    returned_bytes: int
    total_size: int
    truncated: bool
    content: str
    mime_type: str | None = None
    lines_returned: int = 0
    line_limit: int | None = None
    byte_limit: int = 0
    next_offset: int | None = None
    has_more: bool = False
    sha256: str | None = None
    registry: dict[str, Any] | None = None
    image: dict[str, Any] | None = None
    sqlite: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)
    state: str = "ready"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class _Copy:
    path: Path
    reused: bool
    note: str | None
    sha256: str | None


def _split_lines(text: str) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.split("\n")


def looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    # A Unicode BOM means text even though UTF-16/32 contain NUL bytes.
    for bom, _encoding in BOM_ENCODINGS:
        if sample.startswith(bom):
            return False
    if b"\x00" in sample:
        return True
    control = sum(
        1
        for byte in sample
        if byte < 0x20 and byte not in _TEXT_CONTROL or byte == 0x7F
    )
    return control / len(sample) > 0.10


def decode_bytes(data: bytes, *, final: bool) -> tuple[str, str, list[str]]:
    """Decode bytes using BOM detection, UTF-8, then Latin-1 fallback."""
    warnings: list[str] = []
    for bom, encoding in BOM_ENCODINGS:
        if data.startswith(bom):
            body = data[len(bom):]
            decoder = codecs.getincrementaldecoder(encoding)()
            text = decoder.decode(body, final=final)
            return text, encoding, warnings
    try:
        decoder = codecs.getincrementaldecoder("utf-8")()
        text = decoder.decode(data, final=final)
        return text, "utf-8", warnings
    except UnicodeDecodeError:
        warnings.append(
            "invalid UTF-8; decoded as Latin-1 (ISO-8859-1) so bytes map 1:1"
        )
        return data.decode("latin-1"), "latin-1", warnings


def detect_magic(sample: bytes) -> tuple[str, str] | None:
    for magic, kind, mime in MAGIC_TYPES:
        if sample.startswith(magic):
            return kind, mime
    return None


def classify_name(name: str) -> tuple[str, str | None, bool]:
    """Return (detected_type, mime, is_text_name) from a filename."""
    lowered = (name or "").lower()
    if lowered in KNOWN_HIVE_NAMES:
        return "windows_registry_hive", "application/x-windows-registry", False
    if lowered.endswith(".hve"):
        return "windows_registry_hive", "application/x-windows-registry", False
    extension = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if extension in TEXT_EXTENSIONS:
        return "text", MIME_BY_EXTENSION.get(extension, "text/plain"), True
    if not extension and lowered in TEXT_BASENAMES:
        return "text", "text/plain", True
    return "unknown", None, False


def image_info(data: bytes) -> dict[str, Any] | None:
    """Return raster image metadata for an allowlisted format, else None."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        width = height = None
        if len(data) >= 24:
            width = int.from_bytes(data[16:20], "big")
            height = int.from_bytes(data[20:24], "big")
        return {"media_type": "image/png", "format": "png", "width": width, "height": height}
    if data.startswith(b"\xff\xd8\xff"):
        width = height = None
        index = 2
        while index + 9 < len(data):
            if data[index] != 0xFF:
                index += 1
                continue
            marker = data[index + 1]
            if marker in (0xD8, 0xD9):
                index += 2
                continue
            length = int.from_bytes(data[index + 2:index + 4], "big")
            if marker in (
                0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
            ):
                height = int.from_bytes(data[index + 5:index + 7], "big")
                width = int.from_bytes(data[index + 7:index + 9], "big")
                break
            index += 2 + max(2, length)
        return {"media_type": "image/jpeg", "format": "jpeg", "width": width, "height": height}
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        return {
            "media_type": "image/gif",
            "format": "gif",
            "width": int.from_bytes(data[6:8], "little"),
            "height": int.from_bytes(data[8:10], "little"),
        }
    if data.startswith(b"BM") and len(data) >= 26:
        return {
            "media_type": "image/bmp",
            "format": "bmp",
            "width": int.from_bytes(data[18:22], "little", signed=True),
            "height": int.from_bytes(data[22:26], "little", signed=True),
        }
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return {"media_type": "image/webp", "format": "webp", "width": None, "height": None}
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return {"media_type": "image/tiff", "format": "tiff", "width": None, "height": None}
    return None


def hexdump(data: bytes, *, base_offset: int = 0, width: int = 16) -> str:
    lines: list[str] = []
    for start in range(0, len(data), width):
        block = data[start:start + width]
        offset = base_offset + start
        hex_part = " ".join(f"{byte:02x}" for byte in block)
        hex_part = hex_part.ljust(width * 3 - 1)
        printable = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in block
        )
        lines.append(f"{offset:08x}  {hex_part}  |{printable}|")
    return "\n".join(lines)


def _registry_header(sample: bytes) -> dict[str, Any]:
    import struct

    header: dict[str, Any] = {
        "signature": sample[:4].decode("latin-1") if len(sample) >= 4 else None,
        "signature_valid": sample[:4] == b"regf",
    }
    if len(sample) >= 0x4C:
        header["primary_sequence"] = struct.unpack_from("<I", sample, 4)[0]
        header["secondary_sequence"] = struct.unpack_from("<I", sample, 8)[0]
        header["last_written_filetime"] = struct.unpack_from("<Q", sample, 12)[0]
        header["major_version"] = struct.unpack_from("<I", sample, 20)[0]
        header["minor_version"] = struct.unpack_from("<I", sample, 24)[0]
        header["root_cell_offset"] = struct.unpack_from("<I", sample, 36)[0]
        header["hive_bins_data_size"] = struct.unpack_from("<I", sample, 40)[0]
        header["minor_format_version"] = struct.unpack_from("<I", sample, 0x18)[0]
        header["dirty"] = (
            header["primary_sequence"] != header["secondary_sequence"]
        )
    return header


class FilePreviewService:
    """Read-only content preview for a single indexed evidence entry.

    Content always comes from an extracted working copy inside the case export
    directory. Nothing is executed, imported or opened with an external
    application, and no caller-supplied path is ever accepted.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        policy,
        filesystem: FilesystemService,
        evidence,
        indexer: FilesystemIndexer,
        audit,
        index_store=None,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.audit = audit
        self.index_store = index_store
        self._cache: OrderedDict[tuple, PreviewResult] = OrderedDict()
        self._lock = threading.Lock()

    def cleanup(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------
    # validation
    # ------------------------------------------------------------------
    @staticmethod
    def validate_mode(mode: str | None) -> str:
        value = (mode or "auto").strip().lower()
        if value not in PREVIEW_MODES:
            raise PreviewRejected(
                f"mode must be one of {', '.join(PREVIEW_MODES)}",
                code="preview_invalid_mode",
            )
        return value

    def validate_range(self, offset: Any, limit: Any) -> tuple[int, int]:
        try:
            start = int(offset or 0)
        except (TypeError, ValueError):
            raise PreviewRejected(
                "offset must be an integer", code="preview_invalid_offset"
            )
        if start < 0:
            raise PreviewRejected(
                "offset must be zero or positive", code="preview_invalid_offset"
            )
        max_bytes = int(self.settings.preview_max_bytes)
        if limit is None or limit == "":
            size = int(self.settings.preview_default_limit)
        else:
            try:
                size = int(limit)
            except (TypeError, ValueError):
                raise PreviewRejected(
                    "limit must be an integer", code="preview_invalid_limit"
                )
        if size < 1:
            raise PreviewRejected(
                "limit must be positive", code="preview_invalid_limit"
            )
        if size > max_bytes:
            raise PreviewRejected(
                "limit exceeds the configured maximum",
                code="preview_limit_too_large",
                details={"limit": size, "max": max_bytes},
            )
        return start, size

    @staticmethod
    def _reject_unsafe_path(path: str) -> None:
        text = (path or "").replace("\\", "/")
        if "\x00" in text:
            raise PreviewRejected(
                "entry path contains a NUL byte", code="preview_unsafe_path"
            )
        if any(part == ".." for part in text.split("/")):
            raise PreviewRejected(
                "entry path contains traversal segments",
                code="preview_unsafe_path",
            )

    def resolve_entry(self, record, entry_id: Any):
        entry = self.indexer.tree_entry(record, validate_entry_id(entry_id))
        if entry.entry_type != "file":
            raise PreviewRejected(
                "content preview only applies to files",
                code="preview_directory_rejected",
                details={"entry_id": entry.id},
            )
        if entry.inode is None and entry.backend_type != "ad1":
            raise PreviewRejected(
                "entry has no MFT/inode and cannot be extracted",
                code="preview_entry_without_inode",
            )
        # Re-validates the MFT range (rejects negatives) through the policy.
        try:
            if entry.inode is not None:
                self.policy.validate_inode(entry.inode)
        except DFIRError as exc:
            raise PreviewRejected(
                "entry has an invalid MFT/inode value",
                code="preview_invalid_inode",
                details={"inode": entry.inode},
            ) from exc
        self._reject_unsafe_path(entry.full_path)
        return entry

    # ------------------------------------------------------------------
    # working copy reuse
    # ------------------------------------------------------------------
    def _existing_copy(self, record, entry) -> _Copy | None:
        exports = self.policy.case_exports_dir(CASE_ID)
        pattern = f"inode_{entry.inode}_*"
        best: _Copy | None = None
        for candidate in sorted(exports.glob(pattern)):
            if candidate.name.endswith(".provenance.json"):
                continue
            try:
                if candidate.is_symlink():
                    continue
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_relative_to(exports.resolve()):
                continue
            if not resolved.is_file():
                continue
            sidecar = resolved.with_name(resolved.name + ".provenance.json")
            if not sidecar.is_file() or sidecar.is_symlink():
                continue
            try:
                data = json.loads(sidecar.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if entry.backend_type == "ad1":
                if data.get("backend_type") != "ad1" or str(data.get("source_ref")) != str(entry.source_ref):
                    continue
            elif int(data.get("inode", -1)) != int(entry.inode):
                continue
            if str(data.get("evidence_id") or "") != record.evidence_id:
                continue
            try:
                info = resolved.stat()
            except OSError:
                continue
            if data.get("size") is not None and int(data["size"]) != info.st_size:
                continue
            sha256 = data.get("sha256")
            verify_limit = int(self.settings.preview_verify_hash_bytes)
            if sha256 and info.st_size <= verify_limit:
                digest = hashlib.sha256()
                try:
                    with open(resolved, "rb") as handle:
                        for block in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(block)
                except OSError:
                    continue
                if digest.hexdigest() != str(sha256):
                    continue
            best = _Copy(
                path=resolved,
                reused=True,
                note="reused the existing extraction copy",
                sha256=str(sha256) if sha256 else None,
            )
            break
        return best

    def _ensure_copy(self, record, entry) -> _Copy:
        existing = self._existing_copy(record, entry)
        if existing is not None:
            return existing
        extraction = self.filesystem.extract_entry(record, entry, CASE_ID)
        path = self._validate_copy(Path(extraction.output_path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return _Copy(
            path=path, reused=False, note=None, sha256=extraction.sha256
        )

    def _validate_copy(self, path: Path) -> Path:
        exports = self.policy.case_exports_dir(CASE_ID)
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise PreviewRejected(
                "extracted copy is not accessible",
                code="preview_extract_missing",
                details={"error": str(exc)},
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise PreviewRejected(
                "extracted copy must not be a symlink",
                code="preview_symlink_rejected",
            )
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(exports.resolve()):
            raise PreviewRejected(
                "extracted copy is outside the case export directory",
                code="preview_extract_outside_case",
            )
        if not resolved.is_file():
            raise PreviewRejected(
                "extracted copy is not a regular file",
                code="preview_extract_not_file",
            )
        return resolved

    # ------------------------------------------------------------------
    # preview
    # ------------------------------------------------------------------
    def preview(
        self,
        record,
        entry_id: Any,
        *,
        mode: str | None = "auto",
        offset: Any = 0,
        limit: Any = None,
    ) -> PreviewResult:
        mode = self.validate_mode(mode)
        start, size = self.validate_range(offset, limit)
        entry = self.resolve_entry(record, entry_id)
        link_note = None
        if str(entry.fls_type or "").startswith("l"):
            target_entry, link_note = self._follow_symlink(record, entry)
            if target_entry is None:
                return self._symlink_result(record, entry, link_note, start, size)
            entry = target_entry
        before = self._cache_fingerprint(record, entry)
        cached = self._cache_get((record.evidence_id, entry.id, before, start, size, mode))
        if cached is not None:
            return cached

        copy = self._ensure_copy(record, entry)
        try:
            info = copy.path.stat()
        except OSError as exc:
            raise PreviewRejected(
                "extracted copy is not readable",
                code="preview_extract_unreadable",
                details={"error": str(exc)},
            ) from exc
        total_size = int(info.st_size)
        if entry.size is not None and int(entry.size) != total_size:
            size_note = (
                f"indexed size {entry.size} differs from extracted size {total_size}"
            )
        else:
            size_note = None
        warnings: list[str] = []

        with open(copy.path, "rb") as handle:
            header = handle.read(int(self.settings.preview_binary_sample))
            header_type, header_mime = self._classify(entry, header)
            effective = self._effective_mode(mode, header_type)
            if start > total_size:
                start = total_size
            read_limit = size
            if effective == "registry":
                read_limit = min(
                    size, int(self.settings.preview_registry_hex_bytes)
                )
            elif effective == "sqlite":
                read_limit = min(
                    int(self.settings.preview_binary_sample) * 4, total_size
                )
            elif effective == "image":
                max_image = int(self.settings.preview_max_image_bytes)
                if total_size > max_image:
                    effective = "hex"
                    if start == 0:
                        start, size = self.validate_range(0, size)
                    warnings.append(
                        f"image is {total_size} bytes, above the "
                        f"{max_image}-byte inline limit; showing hex instead"
                    )
                else:
                    read_limit = total_size
            handle.seek(start)
            data = handle.read(read_limit)

        if link_note:
            warnings.append(link_note)
        if copy.note:
            pass  # reuse is normal, not a warning
        if size_note:
            warnings.append(size_note)
        if effective == "registry":
            result = self._registry_result(
                record, entry, copy, data, start, total_size, header, size
            )
        elif effective == "hex":
            encoded = hexdump(data, base_offset=start)
            truncated = start + len(data) < total_size
            if truncated:
                warnings.append(
                    "Preview truncated: file is larger than the requested range"
                )
            result = PreviewResult(
                evidence_id=record.evidence_id,
                entry_id=entry.id,
                filename=entry.basename,
                evidence_path=entry.full_path,
                detected_type=header_type,
                preview_mode="hex",
                encoding=None,
                offset=start,
                returned_bytes=len(data),
                total_size=total_size,
                truncated=truncated,
                content=encoded,
                mime_type=header_mime,
                lines_returned=encoded.count("\n") + 1 if encoded else 0,
                byte_limit=read_limit,
                sha256=copy.sha256,
                warnings=warnings,
            )
        elif effective == "sqlite":
            result = self._sqlite_result(
                record, entry, copy, header_type, total_size
            )
            result.warnings = list(dict.fromkeys([*warnings, *result.warnings]))
        elif effective == "image":
            info = image_info(data) or {
                "media_type": "application/octet-stream",
                "format": "unknown",
                "width": None,
                "height": None,
            }
            result = PreviewResult(
                evidence_id=record.evidence_id,
                entry_id=entry.id,
                filename=entry.basename,
                evidence_path=entry.full_path,
                detected_type=header_type,
                preview_mode="image",
                encoding=None,
                offset=0,
                returned_bytes=len(data),
                total_size=total_size,
                truncated=False,
                content="",
                mime_type=info["media_type"],
                byte_limit=read_limit,
                sha256=copy.sha256,
                image={
                    **info,
                    "bytes": len(data),
                    "url": (
                        f"/evidence/{record.evidence_id}/entries/"
                        f"{entry.id}/image"
                    ),
                },
            )
        else:
            # Do not end the decoded text in the middle of a UTF-8 sequence.
            final = start + len(data) >= total_size
            text, encoding, decode_warnings = decode_bytes(data, final=final)
            if final:
                text = text.rstrip("\x00")
            warnings.extend(decode_warnings)
            lines = _split_lines(text)
            max_lines = int(self.settings.preview_text_max_lines)
            truncated = start + len(data) < total_size
            line_next_offset = None
            if len(lines) > max_lines:
                lines = lines[:max_lines]
                truncated = True
                warnings.append(
                    f"Preview truncated: stopped at {max_lines} lines"
                )
                # Continue from the byte right after the last shown line so the
                # line cap does not block reading the rest of the file.
                try:
                    consumed = len(
                        "\n".join(lines).encode(encoding, errors="ignore")
                    )
                    newline_bytes = len("\n".encode(encoding))
                except (LookupError, UnicodeError):
                    consumed = len("\n".join(lines).encode("utf-8"))
                    newline_bytes = 1
                line_next_offset = min(
                    total_size, start + consumed + newline_bytes
                )
            if truncated and (start + len(data) < total_size):
                warnings.append(
                    "Preview truncated: file is larger than the requested range"
                )
            content = "\n".join(lines)
            result = PreviewResult(
                evidence_id=record.evidence_id,
                entry_id=entry.id,
                filename=entry.basename,
                evidence_path=entry.full_path,
                detected_type=header_type,
                preview_mode="text",
                encoding=encoding,
                offset=start,
                returned_bytes=len(data),
                total_size=total_size,
                truncated=truncated,
                content=content,
                mime_type=header_mime or "text/plain",
                lines_returned=len(lines),
                line_limit=max_lines,
                byte_limit=read_limit,
                sha256=copy.sha256,
                warnings=list(dict.fromkeys(warnings)),
            )
        if "line_next_offset" in locals() and line_next_offset is not None:
            if line_next_offset > result.offset and line_next_offset < total_size:
                result.next_offset = line_next_offset
                result.has_more = True
        if result.offset + result.returned_bytes < total_size:
            if result.next_offset is None:
                result.next_offset = result.offset + result.returned_bytes
            result.has_more = True
        if result.offset > 0:
            result.warnings = list(
                dict.fromkeys(
                    [
                        *result.warnings,
                        "partial view: this preview starts at byte offset "
                        f"{result.offset}",
                    ]
                )
            )
        self._cache_put(
            (record.evidence_id, entry.id, before, start, size, mode), result
        )
        self.audit.event(
            "file_preview",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "entry_id": entry.id,
                "inode": entry.inode,
                "offset": start,
                "limit": size,
                "mode": mode,
                "preview_mode": result.preview_mode,
                "detected_type": result.detected_type,
                "encoding": result.encoding,
                "returned_bytes": result.returned_bytes,
                "truncated": result.truncated,
                "reused_copy": copy.reused,
            },
        )
        return result

    def _follow_symlink(self, record, entry):
        from .symlink import resolve_target

        return resolve_target(
            record, entry, filesystem=self.filesystem, index_store=self.index_store
        )

    def _symlink_result(
        self, record, entry, note: str, start: int, size: int
    ) -> PreviewResult:
        return PreviewResult(
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            filename=entry.basename,
            evidence_path=entry.full_path,
            detected_type="symbolic_link",
            preview_mode="symlink",
            encoding=None,
            offset=0,
            returned_bytes=0,
            total_size=int(entry.size or 0),
            truncated=False,
            content="",
            mime_type="inode/symlink",
            warnings=[note],
            state="partial",
        )

    def _sqlite_connect(self, path):
        import sqlite3

        connection = sqlite3.connect(
            f"file:{path}?mode=ro&immutable=1", uri=True, timeout=5.0
        )
        connection.row_factory = None
        connection.execute("PRAGMA query_only = 1")
        return connection

    def _sqlite_result(
        self, record, entry, copy, header_type: str, total_size: int
    ) -> PreviewResult:
        warnings: list[str] = []
        info: dict[str, Any] = {
            "tables": [],
            "table_count": 0,
            "page_size": None,
            "encoding": None,
            "user_version": None,
            "journal_mode": None,
            "truncated": False,
        }
        try:
            connection = self._sqlite_connect(copy.path)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"SQLite database could not be opened read-only: {exc}")
            connection = None
        if connection is not None:
            try:
                for pragma, key in (
                    ("page_size", "page_size"),
                    ("encoding", "encoding"),
                    ("user_version", "user_version"),
                    ("journal_mode", "journal_mode"),
                ):
                    try:
                        row = connection.execute(f"PRAGMA {pragma}").fetchone()
                        info[key] = row[0] if row else None
                    except Exception:  # noqa: BLE001
                        pass
                max_tables = int(self.settings.preview_sqlite_max_tables)
                rows = connection.execute(
                    "SELECT name, type FROM sqlite_master "
                    "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
                    "ORDER BY name LIMIT ?",
                    (max_tables + 1,),
                ).fetchall()
                if len(rows) > max_tables:
                    info["truncated"] = True
                    warnings.append(
                        f"only the first {max_tables} tables are listed"
                    )
                for name, kind in rows[:max_tables]:
                    entry_info: dict[str, Any] = {
                        "name": str(name),
                        "type": str(kind),
                        "columns": [],
                        "row_estimate": None,
                        "error": None,
                    }
                    try:
                        quoted = '"' + str(name).replace('"', '""') + '"'
                        cols = connection.execute(
                            f"PRAGMA table_info({quoted})"
                        ).fetchall()
                        entry_info["columns"] = [
                            {
                                "name": str(col[1]),
                                "type": str(col[2] or ""),
                                "not_null": bool(col[3]),
                                "primary_key": bool(col[5]),
                            }
                            for col in cols[: int(self.settings.preview_sqlite_max_columns)]
                        ]
                        if kind == "table":
                            count = connection.execute(
                                f"SELECT COUNT(*) FROM (SELECT 1 FROM {quoted} LIMIT 1001)"
                            ).fetchone()
                            entry_info["row_estimate"] = int(count[0]) if count else 0
                    except Exception as exc:  # noqa: BLE001
                        entry_info["error"] = str(exc)[:200]
                    info["tables"].append(entry_info)
                info["table_count"] = len(info["tables"])
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"SQLite schema could not be read: {exc}")
            finally:
                connection.close()
        return PreviewResult(
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            filename=entry.basename,
            evidence_path=entry.full_path,
            detected_type=header_type,
            preview_mode="sqlite",
            encoding=None,
            offset=0,
            returned_bytes=0,
            total_size=total_size,
            truncated=False,
            content="",
            mime_type="application/vnd.sqlite3",
            sha256=copy.sha256,
            sqlite=info,
            warnings=warnings,
        )

    def sqlite_rows(
        self,
        record,
        entry_id: Any,
        table: str,
        *,
        offset: int = 0,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Bounded, read-only rows from one table of an evidence SQLite file."""
        entry = self.resolve_entry(record, entry_id)
        if str(entry.fls_type or "").startswith("l"):
            target_entry, note = self._follow_symlink(record, entry)
            if target_entry is None:
                raise PreviewRejected(
                    note or "symbolic link target is unavailable",
                    code="preview_symlink_unresolved",
                )
            entry = target_entry
        copy = self._ensure_copy(record, entry)
        try:
            start = max(0, int(offset))
        except (TypeError, ValueError):
            raise PreviewRejected(
                "offset must be an integer", code="preview_invalid_offset"
            )
        max_rows = int(self.settings.preview_sqlite_max_rows)
        try:
            size = int(limit) if limit else int(self.settings.preview_sqlite_default_rows)
        except (TypeError, ValueError):
            size = max_rows
        size = max(1, min(size, max_rows))
        try:
            connection = self._sqlite_connect(copy.path)
        except Exception as exc:  # noqa: BLE001
            raise PreviewRejected(
                f"SQLite database could not be opened: {exc}",
                code="preview_sqlite_unreadable",
            ) from exc
        deadline = time.monotonic() + float(self.settings.preview_sqlite_timeout)
        try:
            known = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
                )
            }
            if table not in known:
                raise PreviewRejected(
                    "unknown table", code="preview_sqlite_unknown_table"
                )
            quoted = '"' + table.replace('"', '""') + '"'
            connection.set_progress_handler(
                lambda: 1 if time.monotonic() > deadline else 0, 10_000
            )
            cursor = connection.execute(
                f"SELECT * FROM {quoted} LIMIT ? OFFSET ?", (size, start)
            )
            columns = [desc[0] for desc in cursor.description or []]
            cell_chars = int(self.settings.preview_sqlite_cell_chars)
            full_chars = int(self.settings.preview_sqlite_cell_full_chars)
            rows = []
            for row in cursor.fetchall():
                rendered = []
                for value in row:
                    if value is None:
                        rendered.append({"kind": "null", "text": "NULL"})
                    elif isinstance(value, bytes):
                        blob_hex = value[:64].hex()
                        rendered.append(
                            {
                                "kind": "blob",
                                "text": value[:32].hex(),
                                "length": len(value),
                                "full": blob_hex,
                                "full_truncated": len(value) > 64,
                            }
                        )
                    elif isinstance(value, (int, float)):
                        rendered.append(
                            {"kind": "number", "text": str(value), "length": None}
                        )
                    else:
                        text = str(value)
                        entry_cell = {
                            "kind": "text",
                            "text": text[:cell_chars],
                            "length": len(text),
                            "full": None,
                            "full_truncated": False,
                        }
                        if len(text) > cell_chars:
                            entry_cell["full"] = text[:full_chars]
                            entry_cell["full_truncated"] = len(text) > full_chars
                            entry_cell["preview"] = text[:2000]
                        rendered.append(entry_cell)
                rows.append(rendered)
        except PreviewRejected:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PreviewRejected(
                f"SQLite query failed: {exc}",
                code="preview_sqlite_query_failed",
            ) from exc
        finally:
            try:
                connection.set_progress_handler(None, 0)
            except Exception:  # noqa: BLE001
                pass
            connection.close()
        self.audit.event(
            "file_preview_sqlite",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "entry_id": entry.id,
                "table": table,
                "offset": start,
                "limit": size,
                "rows": len(rows),
            },
        )
        return {
            "trust": TRUST_LABEL,
            "entry_id": entry.id,
            "table": table,
            "columns": columns,
            "rows": rows,
            "offset": start,
            "limit": size,
            "returned": len(rows),
            "has_more": len(rows) == size,
        }

    def download_copy(self, record, entry_id: Any) -> tuple[Path, str, int]:
        """Validated working copy for an explicit analyst download.

        Bounded by ``preview_max_download_bytes``; nothing is written outside
        the case export directory and the path is never caller-controlled.
        """
        entry = self.resolve_entry(record, entry_id)
        if str(entry.fls_type or "").startswith("l"):
            target_entry, note = self._follow_symlink(record, entry)
            if target_entry is None:
                raise PreviewRejected(
                    note or "symbolic link target is unavailable",
                    code="preview_symlink_unresolved",
                )
            entry = target_entry
        copy = self._ensure_copy(record, entry)
        try:
            size = copy.path.stat().st_size
        except OSError as exc:
            raise PreviewRejected(
                "extracted copy is not readable",
                code="preview_extract_unreadable",
                details={"error": str(exc)},
            ) from exc
        limit = int(self.settings.preview_max_download_bytes)
        if size > limit:
            raise PreviewRejected(
                "extracted copy exceeds the download limit",
                code="preview_download_too_large",
                details={"size": size, "limit": limit},
            )
        name = entry.basename or f"entry_{entry.id}.bin"
        self.audit.event(
            "file_download",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={"entry_id": entry.id, "inode": entry.inode, "bytes": size},
        )
        return copy.path, name, size

    def image_bytes(self, record, entry_id: Any) -> tuple[dict[str, Any], bytes]:
        """Raw bytes of an allowlisted raster image, for inline display.

        Only formats the browser renders safely are served; SVG and other
        markup-capable formats stay in the text/hex view. The size cap prevents
        a huge file from being streamed to the browser.
        """
        entry = self.resolve_entry(record, entry_id)
        if str(entry.fls_type or "").startswith("l"):
            target_entry, note = self._follow_symlink(record, entry)
            if target_entry is None:
                raise PreviewRejected(
                    note or "symbolic link target is unavailable",
                    code="preview_symlink_unresolved",
                )
            entry = target_entry
        copy = self._ensure_copy(record, entry)
        try:
            size = copy.path.stat().st_size
        except OSError as exc:
            raise PreviewRejected(
                "extracted copy is not readable",
                code="preview_extract_unreadable",
                details={"error": str(exc)},
            ) from exc
        limit = int(self.settings.preview_max_image_bytes)
        if size > limit:
            raise PreviewRejected(
                "image exceeds the inline preview limit",
                code="preview_image_too_large",
                details={"size": size, "limit": limit},
            )
        with open(copy.path, "rb") as handle:
            data = handle.read(limit + 1)
        info = image_info(data)
        if info is None:
            raise PreviewRejected(
                "entry is not a supported raster image",
                code="preview_not_an_image",
            )
        self.audit.event(
            "file_preview_image",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={
                "entry_id": entry.id,
                "inode": entry.inode,
                "media_type": info["media_type"],
                "bytes": len(data),
            },
        )
        return info, data

    def _effective_mode(self, requested: str, header_type: str) -> str:
        if requested == "hex":
            return "hex"
        if header_type == "windows_registry_hive":
            return "registry"
        if requested == "text":
            return "text"
        if header_type in IMAGE_TYPES:
            return "image"
        if header_type == "sqlite_database":
            return "sqlite"
        return "text" if header_type in {"text", "unknown"} else "hex"

    def _classify(self, entry, header: bytes) -> tuple[str, str | None]:
        magic = detect_magic(header)
        name_type, name_mime, text_name = classify_name(entry.basename)
        if magic is not None:
            kind, mime = magic
            if kind == "windows_registry_hive":
                return kind, mime
            if name_type == "windows_registry_hive":
                return name_type, name_mime
            if kind in {"pe_executable", "elf_executable", "sqlite_database",
                        "zip_archive", "ole_compound", "png_image",
                        "jpeg_image", "pdf_document", "gzip_archive"}:
                return kind, mime
            return kind, mime
        if text_name and not looks_binary(header):
            return "text", name_mime
        if looks_binary(header):
            return "binary", "application/octet-stream"
        return name_type, name_mime

    def _registry_result(
        self,
        record,
        entry,
        copy: _Copy,
        data: bytes,
        start: int,
        total_size: int,
        header: bytes,
        requested_limit: int,
    ) -> PreviewResult:
        header_info = _registry_header(header[:4112])
        hive_type = (
            entry.basename.rsplit(".", 1)[0].lower()
            if "." in entry.basename
            else entry.basename.lower()
        )
        warnings = [
            "Registry hive is binary: showing a bounded hex preview and header "
            "metadata only. Use the Registry tab to browse keys and values."
        ]
        if not header_info.get("signature_valid"):
            warnings.append("hive header does not start with the regf signature")
        if header_info.get("dirty"):
            warnings.append(
                "primary and secondary sequence numbers differ: hive may be dirty"
            )
        try:
            hive = self.registry_lookup(record.evidence_id, entry.id)
        except Exception:  # noqa: BLE001 - registry index is optional
            hive = None
        registry_meta = {
            "header": header_info,
            "hive_type": hive_type,
            "known_hive": entry.basename.lower() in KNOWN_HIVE_NAMES,
            "indexed_hive_id": (hive or {}).get("hive_id"),
            "index_state": (hive or {}).get("state") or "not_indexed",
            "key_count": (hive or {}).get("key_count"),
            "value_count": (hive or {}).get("value_count"),
            "suggested_tool": "registry_list_hives / registry_get_key",
        }
        encoded = hexdump(data, base_offset=start) if data else ""
        truncated = start + len(data) < total_size
        return PreviewResult(
            evidence_id=record.evidence_id,
            entry_id=entry.id,
            filename=entry.basename,
            evidence_path=entry.full_path,
            detected_type="windows_registry_hive",
            preview_mode="registry",
            encoding=None,
            offset=start,
            returned_bytes=len(data),
            total_size=total_size,
            truncated=truncated,
            content=encoded,
            mime_type="application/x-windows-registry",
            lines_returned=encoded.count("\n") + 1 if encoded else 0,
            byte_limit=min(
                requested_limit,
                int(self.settings.preview_registry_hex_bytes),
            ),
            sha256=copy.sha256,
            registry=registry_meta,
            warnings=warnings,
        )

    def registry_lookup(self, evidence_id: str, entry_id: int) -> dict[str, Any] | None:
        """Look up an existing registry index record, without starting a job."""
        lookup = getattr(self, "_registry_lookup", None)
        if lookup is None:
            return None
        return lookup(evidence_id, entry_id)

    def attach_registry_lookup(self, function) -> None:
        self._registry_lookup = function

    # ------------------------------------------------------------------
    # cache
    # ------------------------------------------------------------------
    @staticmethod
    def _cache_fingerprint(record, entry) -> tuple:
        return (
            record.evidence_id,
            entry.inode,
            entry.size,
            entry.modified_time,
            entry.allocated,
        )

    def _cache_get(self, key: tuple) -> PreviewResult | None:
        with self._lock:
            value = self._cache.get(key)
            if value is None:
                return None
            self._cache.move_to_end(key)
            return value

    def _cache_put(self, key: tuple, value: PreviewResult) -> None:
        limit = max(1, int(self.settings.preview_cache_entries))
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            while len(self._cache) > limit:
                self._cache.popitem(last=False)
