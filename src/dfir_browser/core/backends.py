"""Evidence read backends.

The AD1 adapter is deliberately isolated here because dissect.evidence is
AGPL-3.0-or-later. It never exposes an AD1 container as a sector image.
"""
from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

from .errors import DFIRError


class BackendError(DFIRError):
    default_code = "evidence_backend_error"


@dataclass(slots=True)
class BackendEntry:
    source_ref: str
    path: str
    parent_path: str
    name: str
    entry_type: str
    size: int
    created: str | None
    modified: str | None
    accessed: str | None
    metadata_changed: str | None
    md5: str | None
    sha1: str | None
    item_type: str
    allocated: bool
    deleted: bool


class EvidenceBackend(Protocol):
    def iter_entries(self, record) -> Iterator[BackendEntry]: ...
    def open_entry(self, record, source_ref: str) -> BinaryIO: ...


class TskEvidenceBackend:
    """Adapter for the existing inode based Sleuth Kit operations."""

    def inspect(self, filesystem, record, entry):
        image = Path(record.raw_exposure_path or record.resolved_source_path)
        return filesystem.stat(image, record.evidence_id, entry.inode, record.layout.offset_sectors)

    def extract_entry(self, filesystem, record, entry, case_id: str):
        image = filesystem._image_for(record)
        return filesystem.extract(image, record.evidence_id, entry.inode, case_id,
            record.layout.offset_sectors, assume_file=True)


def ad1_segments(primary: Path, allowed_roots: tuple[Path, ...]) -> list[Path]:
    """Resolve an AD1 and contiguous numbered siblings without following escapes."""
    primary = primary.resolve(strict=True)
    if primary.suffix.lower() != ".ad1":
        raise BackendError("register the primary .ad1 segment", code="ad1_segment_invalid")
    if not any(primary.is_relative_to(root) for root in allowed_roots):
        raise BackendError("AD1 segment is outside allowed roots", code="path_outside_allowed_root")
    result = [primary]
    for number in range(2, 1001):
        candidate = primary.with_suffix(f".ad{number}")
        if not candidate.exists():
            # A later segment after a gap is a malformed sequence.
            later = [primary.with_suffix(f".ad{i}") for i in range(number + 1, 1001)]
            if any(item.exists() for item in later):
                raise BackendError("AD1 segment sequence has a gap", code="ad1_segment_order")
            break
        resolved = candidate.resolve(strict=True)
        if resolved != candidate.absolute() or not any(resolved.is_relative_to(root) for root in allowed_roots):
            raise BackendError("AD1 segment escapes the allowed root or is a symlink", code="path_outside_allowed_root")
        if not resolved.is_file():
            raise BackendError("AD1 segment is not a regular file", code="ad1_segment_invalid")
        result.append(resolved)
    return result


def segment_manifest(paths: list[Path]) -> list[dict[str, object]]:
    manifest = []
    for path in paths:
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise BackendError("AD1 segment changed while hashing", code="source_changed")
        manifest.append({"path": str(path), "size": before.st_size, "mtime_ns": before.st_mtime_ns, "sha256": digest.hexdigest()})
    return manifest


def ad1_open(path: str, manifest: list[dict[str, object]]):
    """Open the pinned segments with the optional AGPL parser."""
    try:
        from dissect.evidence.ad1 import AD1
    except ImportError as exc:
        raise BackendError("AD1 support requires dissect.evidence", code="ad1_parser_unavailable") from exc
    streams = [open(str(item["path"]), "rb") for item in manifest]
    try:
        fs = AD1(streams)
    except Exception as exc:
        for stream in streams:
            stream.close()
        if "crypt" in str(exc).lower() or "locked" in str(exc).lower():
            raise BackendError("Encrypted AD1 is not supported in this MVP", code="ad1_encrypted") from exc
        raise BackendError(f"invalid AD1 container: {type(exc).__name__}", code="ad1_corrupt") from exc
    if fs.is_adcrypt() or fs.is_locked():
        for stream in streams:
            stream.close()
        raise BackendError("Encrypted AD1 is not supported in this MVP", code="ad1_encrypted")
    chunk_size = int(fs.logical_image.chunk_size)
    if chunk_size <= 0 or chunk_size > 1024 * 1024:
        for stream in streams:
            stream.close()
        raise BackendError("AD1 declares an unsafe compression chunk size", code="ad1_chunk_size_invalid")
    expected_segments = int(fs.segment(0).count)
    if expected_segments > 1000:
        for stream in streams:
            stream.close()
        raise BackendError("AD1 declares too many segments", code="ad1_segment_limit")
    if expected_segments != len(streams):
        for stream in streams:
            stream.close()
        raise BackendError("AD1 segment is missing", code="ad1_segment_missing")
    return fs, streams


class AD1EvidenceBackend:
    max_depth = 128
    max_segments = 1000
    max_item_size = (1 << 63) - 1

    @staticmethod
    def _safe_name(name: str) -> str:
        if not name or "\x00" in name or name in {".", ".."} or "/" in name or "\\" in name or name.startswith("/"):
            raise BackendError("AD1 contains an unsafe path component", code="ad1_path_invalid")
        return name

    def iter_entries(self, record) -> Iterator[BackendEntry]:
        fs, streams = ad1_open(record.resolved_source_path, record.exposure_details["segments"])
        seen: set[int] = set()
        stack = [(iter(fs.root.iterdir()), "", 1)]
        try:
            while stack:
                iterator, parent, depth = stack[-1]
                try:
                    item = next(iterator)
                except StopIteration:
                    stack.pop()
                    continue
                ref = int(item.offset)
                if ref in seen:
                    raise BackendError("AD1 entry cycle detected", code="ad1_cycle")
                seen.add(ref)
                if depth > self.max_depth:
                    raise BackendError("AD1 directory depth limit exceeded", code="ad1_depth_limit")
                name = self._safe_name(str(item.name))
                path = f"{parent}/{name}" if parent else name
                if not parent and re.match(r"^[A-Za-z]:", name):
                    raise BackendError("AD1 contains an absolute drive path", code="ad1_path_invalid")
                if len(path) > 32768:
                    raise BackendError("AD1 path exceeds the supported length", code="ad1_path_invalid")
                if int(item.size) < 0 or int(item.size) > self.max_item_size:
                    raise BackendError("AD1 entry declares an invalid size", code="ad1_size_invalid")
                item_type = getattr(item.type, "name", None) or "Unknown"
                deleted = item_type.lower() == "deleted"
                yield BackendEntry(str(ref), path, parent, name, "directory" if item.is_dir() else "file", int(item.size), item.btime.isoformat(), item.mtime.isoformat(), item.atime.isoformat(), item.ctime.isoformat(), item.md5, item.sha1, item_type, not deleted, deleted)
                if item.is_dir():
                    if depth >= self.max_depth:
                        raise BackendError("AD1 directory depth limit exceeded", code="ad1_depth_limit")
                    stack.append((iter(item.iterdir()), path, depth + 1))
        finally:
            for stream in streams:
                stream.close()

    def open_entry(self, record, source_ref: str):
        if not re.fullmatch(r"[0-9]{1,20}", str(source_ref)):
            raise BackendError("invalid AD1 source reference", code="source_ref_invalid")
        fs, streams = ad1_open(record.resolved_source_path, record.exposure_details["segments"])
        try:
            target = int(source_ref)
            item = None
            stack = [(iter(fs.root.iterdir()), 1)]
            visited = set()
            while stack:
                iterator, depth = stack[-1]
                try:
                    candidate = next(iterator)
                except StopIteration:
                    stack.pop()
                    continue
                if len(visited) >= 2_000_000:
                    raise BackendError("AD1 entry limit exceeded", code="ad1_entry_limit")
                if candidate.offset in visited:
                    raise BackendError("AD1 entry cycle detected", code="ad1_cycle")
                visited.add(candidate.offset)
                if candidate.offset == target:
                    item = candidate
                    break
                if candidate.is_dir():
                    if depth >= AD1EvidenceBackend.max_depth:
                        raise BackendError("AD1 directory depth limit exceeded", code="ad1_depth_limit")
                    stack.append((iter(candidate.iterdir()), depth + 1))
            if item is None or item.is_dir() or item.is_symlink():
                raise BackendError("AD1 entry cannot be opened as a regular file", code="entry_not_file")
            file_stream = item.open()
            _install_bounded_ad1_reader(file_stream)
            return _OwnedStream(file_stream, streams)
        except Exception:
            for stream in streams:
                stream.close()
            raise


class _OwnedStream:
    def __init__(self, stream, owners):
        self.stream, self.owners = stream, owners
    def __getattr__(self, name): return getattr(self.stream, name)
    def __enter__(self): return self
    def __exit__(self, *exc): self.close()
    def close(self):
        try: self.stream.close()
        finally:
            for owner in self.owners: owner.close()


def _install_bounded_ad1_reader(file_stream) -> None:
    """Replace parser decompression with chunk bounded zlib reads."""
    chunk_size = int(file_stream.chunk_size)

    def bounded_read(offset: int, length: int) -> bytes:
        result = []
        chunk, offset_in_chunk = divmod(offset, chunk_size)
        chunk_count = (length + chunk_size - 1) // chunk_size
        chunk_offsets = file_stream.chunks[chunk : chunk + chunk_count + 1]
        for index, chunk_offset in enumerate(chunk_offsets[:-1]):
            compressed_size = int(chunk_offsets[index + 1] - chunk_offset)
            if compressed_size <= 0 or compressed_size > chunk_size * 2 + 65536:
                raise BackendError("AD1 compressed chunk length is invalid", code="ad1_chunk_size_invalid")
            file_stream.stream.seek(chunk_offset)
            compressed = file_stream.stream.read(compressed_size)
            if len(compressed) != compressed_size:
                raise BackendError("short read in AD1 compressed chunk", code="ad1_short_read")
            inflater = zlib.decompressobj()
            data = inflater.decompress(compressed, chunk_size + 1)
            if len(data) > chunk_size or inflater.unconsumed_tail or not inflater.eof:
                raise BackendError("AD1 decompression exceeded its declared chunk bound", code="ad1_decompression_limit")
            read_size = min(length, chunk_size - offset_in_chunk)
            result.append(data[offset_in_chunk : offset_in_chunk + read_size])
            offset += read_size
            length -= read_size
            offset_in_chunk = 0
        output = b"".join(result)
        if len(output) == 0 and length:
            raise BackendError("short read from AD1 file stream", code="ad1_short_read")
        return output

    file_stream._read = bounded_read
