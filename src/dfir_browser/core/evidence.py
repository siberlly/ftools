from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import shutil
import stat as stat_module
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .command import CommandResult, CommandRunner
from .config import EwfMapping, Settings
from .errors import DFIRError
from .filesystem import FilesystemError, FilesystemService, detect_layout
from .hashing import HashTimeout, sha256_file
from .models import EvidenceRecord, Layout, TRUST_LABEL, utc_now_iso
from .parsers import parse_ewfinfo, parse_fsstat, parse_img_stat
from .policy import SecurityPolicy

REGISTRY_SCHEMA_VERSION = 2


class RegistryError(DFIRError):
    """Raised when the evidence registry cannot be read or written."""

    default_code = "registry_error"


class EvidenceError(DFIRError):
    """Raised for evidence registration or access problems."""

    default_code = "evidence_error"


class EvidenceNotFound(EvidenceError):
    """Raised when an evidence id is unknown."""

    default_code = "evidence_not_found"


class EvidenceAccessError(EvidenceError):
    """Raised when the read-only view of an evidence image is unavailable."""

    default_code = "evidence_access_error"


def make_evidence_id(canonical_path: Path) -> str:
    digest = hashlib.sha256(str(canonical_path).encode("utf-8")).hexdigest()
    return f"ev_{digest[:12]}"


def _stderr_excerpt(result: CommandResult, limit: int = 500) -> str:
    text = (result.stderr or "").strip()
    if not text:
        return "no stderr output"
    return text[:limit].replace("\n", " ")


def _has_write_bits(st_mode: int) -> bool:
    return bool(stat_module.S_IMODE(st_mode) & 0o222)


@dataclass(frozen=True, slots=True)
class ExposureResolution:
    path: Path
    mode: str
    verified_at: str
    warnings: list[str]
    details: dict[str, Any]


class Registry:
    """Small JSON registry with cross-process file locking.

    Writes use a temporary file in the same directory followed by
    ``os.replace``. Malformed registry files are never silently reset.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(".lock")
        self._thread_lock = threading.RLock()

    @contextmanager
    def _locked(self, exclusive: bool) -> Iterator[None]:
        with self._thread_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(
                    descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                )
                yield
            finally:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": REGISTRY_SCHEMA_VERSION, "evidences": {}}
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(
                f"cannot read registry {self.path}: {exc}",
                code="registry_corrupt",
                details={"path": str(self.path)},
            ) from exc
        if not isinstance(data, dict):
            raise RegistryError(
                "registry root must be an object",
                code="registry_corrupt",
                details={"path": str(self.path)},
            )
        version = data.get("version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RegistryError(
                f"invalid registry schema version: {version!r}",
                code="registry_corrupt",
                details={"path": str(self.path)},
            )
        if version > REGISTRY_SCHEMA_VERSION:
            raise RegistryError(
                "registry schema is newer than this application supports",
                code="registry_schema_newer",
                details={
                    "path": str(self.path),
                    "version": version,
                    "supported": REGISTRY_SCHEMA_VERSION,
                },
            )
        evidences = data.setdefault("evidences", {})
        if not isinstance(evidences, dict):
            raise RegistryError(
                "registry 'evidences' must be an object",
                code="registry_corrupt",
                details={"path": str(self.path)},
            )
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if os.path.exists(temporary):
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        with self._locked(exclusive=False):
            return self._read()["evidences"].get(evidence_id)

    def upsert(self, record: dict[str, Any]) -> None:
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str):
            raise RegistryError("record has no evidence_id")
        with self._locked(exclusive=True):
            data = self._read()
            data["evidences"][evidence_id] = record
            data["version"] = REGISTRY_SCHEMA_VERSION
            self._write(data)

    def list_all(self) -> list[dict[str, Any]]:
        with self._locked(exclusive=False):
            records = list(self._read()["evidences"].values())
        return sorted(
            records,
            key=lambda item: str(item.get("registered_at", "")),
            reverse=True,
        )


class ImageProvider:
    """Resolve a read-only raw view of evidence.

    E01 identity is never inferred from media size or by scanning a directory.
    It comes from an explicit mapping or from a managed ``ewfmount`` exposure
    whose marker is tied to this evidence id, source path and source SHA-256.
    """

    def __init__(
        self,
        mappings: dict[str, EwfMapping],
        automount: bool,
        runner: CommandRunner,
        mounts_dir: Path,
        logger: logging.Logger | None = None,
    ) -> None:
        self.mappings = dict(mappings)
        self.automount = automount
        self.runner = runner
        self.mounts_dir = Path(mounts_dir)
        self._logger = logger or logging.getLogger("dfir_browser.evidence")
        self._created_mounts: set[Path] = set()

    @property
    def managed_mounts(self) -> set[Path]:
        return set(self._created_mounts)

    def verify_exposure(
        self, exposure: Path | str, media_size: int, evidence_id: str | None
    ) -> tuple[list[str], dict[str, Any]]:
        try:
            resolved = Path(exposure).resolve(strict=True)
        except FileNotFoundError as exc:
            raise EvidenceAccessError(
                f"raw exposure does not exist: {exposure}",
                code="exposure_missing",
                details={"path": str(exposure)},
            ) from exc
        except OSError as exc:
            raise EvidenceAccessError(
                f"cannot resolve raw exposure: {exc}",
                code="exposure_unavailable",
                details={"path": str(exposure)},
            ) from exc

        if not resolved.is_file():
            raise EvidenceAccessError(
                f"raw exposure is not a regular file: {resolved}",
                code="exposure_not_file",
                details={"path": str(resolved)},
            )
        if not os.access(resolved, os.R_OK):
            raise EvidenceAccessError(
                f"raw exposure is not readable: {resolved}",
                code="exposure_not_readable",
                details={"path": str(resolved)},
            )

        exposure_stat = resolved.stat()
        if _has_write_bits(exposure_stat.st_mode):
            raise EvidenceAccessError(
                "raw exposure must be read-only for the application",
                code="exposure_writable",
                details={
                    "path": str(resolved),
                    "mode": oct(stat_module.S_IMODE(exposure_stat.st_mode)),
                },
            )
        if exposure_stat.st_size != media_size:
            raise EvidenceAccessError(
                "raw exposure size does not match EWF media size",
                code="exposure_size_mismatch",
                details={
                    "path": str(resolved),
                    "exposure_size": exposure_stat.st_size,
                    "media_size": media_size,
                },
            )

        details: dict[str, Any] = {
            "path": str(resolved),
            "size": exposure_stat.st_size,
            "mode": oct(stat_module.S_IMODE(exposure_stat.st_mode)),
            "read_only": True,
        }
        warnings: list[str] = []

        fs_result = self.runner.run(
            ["fsstat", "-o", "0", str(resolved)],
            timeout=self.runner.timeout,
            evidence_id=evidence_id,
        )
        fs_info = parse_fsstat(fs_result.stdout) if fs_result.ok else {}
        if not fs_result.ok or not fs_info.get("filesystem"):
            raise EvidenceAccessError(
                "fsstat could not identify a filesystem on the raw exposure",
                code="exposure_fsstat_failed",
                details={
                    "path": str(resolved),
                    "exit_code": fs_result.exit_code,
                    "timed_out": fs_result.timed_out,
                },
            )
        details["fsstat"] = fs_info

        if shutil.which("img_stat"):
            img_result = self.runner.run(
                ["img_stat", str(resolved)],
                timeout=self.runner.timeout,
                evidence_id=evidence_id,
            )
            if img_result.ok:
                img_info = parse_img_stat(img_result.stdout)
                details["img_stat"] = img_info
                img_size = img_info.get("size_bytes")
                if img_size is not None and img_size != media_size:
                    raise EvidenceAccessError(
                        "img_stat size does not match EWF media size",
                        code="exposure_size_mismatch",
                        details={
                            "path": str(resolved),
                            "img_stat_size": img_size,
                            "media_size": media_size,
                        },
                    )
            else:
                warnings.append(
                    f"img_stat failed: {_stderr_excerpt(img_result)}"
                )

        return warnings, details

    def resolve_explicit(
        self,
        source: Path,
        media_size: int,
        evidence_id: str,
        source_sha256: str,
        mapping: EwfMapping,
    ) -> ExposureResolution:
        if mapping.source_sha256 and mapping.source_sha256 != source_sha256:
            raise EvidenceAccessError(
                "explicit EWF mapping source SHA-256 does not match evidence",
                code="ewf_mapping_source_mismatch",
                details={
                    "source": str(source),
                    "expected": mapping.source_sha256,
                    "actual": source_sha256,
                },
            )
        if mapping.media_size is not None and mapping.media_size != media_size:
            raise EvidenceAccessError(
                "explicit EWF mapping media size does not match ewfinfo",
                code="ewf_mapping_media_mismatch",
                details={
                    "source": str(source),
                    "expected": mapping.media_size,
                    "actual": media_size,
                },
            )

        warnings, details = self.verify_exposure(
            mapping.exposure, media_size, evidence_id
        )
        warnings.insert(
            0,
            f"using explicit read-only EWF exposure {details['path']} "
            "(source-path mapping, not media-size discovery)",
        )
        return ExposureResolution(
            path=Path(details["path"]),
            mode="explicit",
            verified_at=utc_now_iso(),
            warnings=warnings,
            details=details,
        )

    def _write_marker(self, mount_dir: Path, payload: dict[str, Any]) -> None:
        marker = mount_dir / ".dfir-managed.json"
        descriptor, temporary = tempfile.mkstemp(
            prefix=".dfir-managed.", suffix=".tmp", dir=str(mount_dir)
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, marker)
            os.chmod(marker, 0o600)
        finally:
            if os.path.exists(temporary):
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def resolve_managed(
        self,
        source: Path,
        media_size: int,
        evidence_id: str,
        source_sha256: str,
    ) -> ExposureResolution:
        self.mounts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        mounts_root = self.mounts_dir.resolve()
        mount_dir = self.mounts_dir / evidence_id
        resolved_mount = mount_dir.resolve(strict=False)
        if not resolved_mount.is_relative_to(mounts_root):
            raise EvidenceAccessError(
                "managed mount directory escapes the mounts root",
                code="managed_mount_invalid",
                details={"mount_dir": str(mount_dir)},
            )

        marker = mount_dir / ".dfir-managed.json"
        if mount_dir.exists():
            if mount_dir.is_symlink() or not mount_dir.is_dir():
                raise EvidenceAccessError(
                    "managed mount path is not a safe directory",
                    code="managed_mount_invalid",
                    details={"mount_dir": str(mount_dir)},
                )
            if not marker.is_file():
                raise EvidenceAccessError(
                    "mount directory exists but was not created by this application",
                    code="managed_mount_unowned",
                    details={"mount_dir": str(mount_dir)},
                )
            try:
                marker_data = json.loads(marker.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise EvidenceAccessError(
                    "managed mount marker is unreadable",
                    code="managed_mount_invalid_marker",
                    details={"mount_dir": str(mount_dir), "error": str(exc)},
                ) from exc
            if (
                marker_data.get("evidence_id") != evidence_id
                or marker_data.get("source_path") != str(source.resolve())
                or marker_data.get("source_sha256") != source_sha256
            ):
                raise EvidenceAccessError(
                    "managed mount belongs to different evidence",
                    code="managed_mount_conflict",
                    details={"mount_dir": str(mount_dir)},
                )
            exposure = mount_dir / "ewf1"
            if not exposure.is_file():
                raise EvidenceAccessError(
                    "managed mount marker exists but ewf1 is missing",
                    code="managed_mount_missing_exposure",
                    details={"mount_dir": str(mount_dir)},
                )
            warnings, details = self.verify_exposure(
                exposure, media_size, evidence_id
            )
            warnings.insert(
                0, f"reusing existing managed EWF exposure {details['path']}"
            )
            return ExposureResolution(
                path=Path(details["path"]),
                mode="managed",
                verified_at=utc_now_iso(),
                warnings=warnings,
                details=details,
            )

        mount_dir.mkdir(parents=True, mode=0o700)
        if mount_dir.is_symlink():
            raise EvidenceAccessError(
                "refusing to mount into a symlinked directory",
                code="managed_mount_invalid",
                details={"mount_dir": str(mount_dir)},
            )

        result = self.runner.run(
            ["ewfmount", str(source), str(mount_dir)],
            timeout=self.runner.timeout,
            evidence_id=evidence_id,
        )
        if not result.ok:
            self._remove_empty_dir(mount_dir)
            raise EvidenceAccessError(
                "ewfmount failed",
                code="ewfmount_failed",
                details={
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stderr": _stderr_excerpt(result),
                    "mount_dir": str(mount_dir),
                },
            )

        exposure = mount_dir / "ewf1"
        if not exposure.is_file():
            self._unmount_dir(mount_dir, evidence_id)
            self._remove_empty_dir(mount_dir)
            raise EvidenceAccessError(
                "ewfmount succeeded but ewf1 was not created",
                code="ewfmount_no_image",
                details={"mount_dir": str(mount_dir)},
            )

        self._created_mounts.add(resolved_mount)
        try:
            warnings, details = self.verify_exposure(
                exposure, media_size, evidence_id
            )
            self._write_marker(
                mount_dir,
                {
                    "version": 1,
                    "evidence_id": evidence_id,
                    "source_path": str(source.resolve()),
                    "source_sha256": source_sha256,
                    "media_size": media_size,
                    "created_at": utc_now_iso(),
                    "pid": os.getpid(),
                },
            )
        except Exception:
            self._unmount_dir(mount_dir, evidence_id)
            self._created_mounts.discard(resolved_mount)
            self._remove_empty_dir(mount_dir)
            raise

        warnings.insert(
            0, f"created managed read-only EWF exposure {details['path']} with ewfmount"
        )
        self._logger.info("mounted EWF evidence %s at %s", source, mount_dir)
        return ExposureResolution(
            path=Path(details["path"]),
            mode="managed",
            verified_at=utc_now_iso(),
            warnings=warnings,
            details=details,
        )

    def resolve(
        self,
        source: Path,
        media_size: int,
        evidence_id: str,
        source_sha256: str,
    ) -> ExposureResolution:
        source = source.resolve()
        if source.suffix.lower() != ".e01":
            st = source.stat()
            return ExposureResolution(
                path=source,
                mode="direct",
                verified_at=utc_now_iso(),
                warnings=[],
                details={
                    "path": str(source),
                    "size": st.st_size,
                    "mode": oct(stat_module.S_IMODE(st.st_mode)),
                    "read_only": not _has_write_bits(st.st_mode),
                    "source": "direct",
                },
            )

        mapping = self.mappings.get(str(source))
        if mapping is not None:
            return self.resolve_explicit(
                source, media_size, evidence_id, source_sha256, mapping
            )
        if self.automount:
            return self.resolve_managed(
                source, media_size, evidence_id, source_sha256
            )
        raise EvidenceAccessError(
            "no explicit EWF mapping is configured for this evidence and "
            "managed automount is disabled",
            code="ewf_mapping_missing",
            details={
                "source": str(source),
                "automount": False,
                "configured_sources": sorted(self.mappings),
                "hint": (
                    "configure DFIR_EWF_MAPPINGS, DFIR_EWF_MAPPING_FILE or "
                    "var/ewf_mappings.json, or set DFIR_EWF_AUTOMOUNT=1"
                ),
            },
        )

    def _unmount_dir(self, mount_dir: Path, evidence_id: str | None) -> bool:
        for argv in (
            ["fusermount", "-u", str(mount_dir)],
            ["umount", str(mount_dir)],
        ):
            result = self.runner.run(
                argv, timeout=30.0, evidence_id=evidence_id
            )
            if result.ok:
                self._logger.info("unmounted managed exposure %s", mount_dir)
                return True
        self._logger.warning("could not unmount managed exposure %s", mount_dir)
        return False

    @staticmethod
    def _remove_empty_dir(path: Path) -> None:
        try:
            path.rmdir()
        except OSError:
            pass

    def cleanup_managed(self) -> None:
        """Unmount only managed exposures created by this process."""
        for mount_dir in sorted(self._created_mounts, reverse=True):
            try:
                if not mount_dir.exists():
                    continue
                marker = mount_dir / ".dfir-managed.json"
                if not marker.is_file():
                    self._logger.warning(
                        "not unmounting %s: managed marker missing", mount_dir
                    )
                    continue
                if self._unmount_dir(mount_dir, evidence_id=None):
                    try:
                        marker.unlink()
                    except OSError:
                        pass
                    self._remove_empty_dir(mount_dir)
            finally:
                self._created_mounts.discard(mount_dir)


class EvidenceService:
    def __init__(
        self,
        policy: SecurityPolicy,
        runner: CommandRunner,
        registry: Registry,
        provider: ImageProvider,
        filesystem: FilesystemService,
        settings: Settings,
        logger: logging.Logger | None = None,
    ) -> None:
        self.policy = policy
        self.runner = runner
        self.registry = registry
        self.provider = provider
        self.filesystem = filesystem
        self.settings = settings
        self._logger = logger or logging.getLogger("dfir_browser.evidence")

    def _tool_version(self, tool: str) -> str | None:
        getter = getattr(self.runner, "version", None)
        if getter is None:
            return None
        try:
            return getter(tool)
        except Exception:
            return None

    def _source_sha256(self, source: Path) -> str:
        try:
            digest, hashed_size = sha256_file(
                source, self.settings.hash_timeout
            )
        except HashTimeout as exc:
            raise EvidenceError(
                "source hashing exceeded the configured limit",
                code="source_hash_timeout",
                details={"path": str(source)},
            ) from exc
        except OSError as exc:
            raise EvidenceError(
                f"cannot hash source evidence: {exc}",
                code="source_hash_failed",
                details={"path": str(source)},
            ) from exc
        try:
            current_size = source.stat().st_size
        except OSError as exc:
            raise EvidenceError(
                f"cannot stat source evidence: {exc}",
                code="source_stat_failed",
            ) from exc
        if hashed_size != current_size:
            raise EvidenceError(
                "source evidence changed while it was being hashed",
                code="source_changed",
                details={"hashed_size": hashed_size, "current_size": current_size},
            )
        return digest

    def register(self, path: str) -> EvidenceRecord:
        source = self.policy.validate_evidence_path(path)
        evidence_id = make_evidence_id(source)
        try:
            source_stat = source.stat()
        except OSError as exc:
            raise EvidenceError(
                f"cannot stat source evidence: {exc}",
                code="source_stat_failed",
            ) from exc
        source_size = source_stat.st_size
        source_mtime_ns = source_stat.st_mtime_ns
        source_sha256 = self._source_sha256(source)
        extension = source.suffix.lower()
        warnings: list[str] = []

        if extension == ".ad1":
            from .backends import AD1EvidenceBackend, ad1_open, ad1_segments, segment_manifest

            segments = ad1_segments(source, self.policy.allowed_roots)
            manifest = segment_manifest(segments)
            if len(manifest) > AD1EvidenceBackend.max_segments:
                raise EvidenceError("AD1 segment count exceeds the configured limit", code="ad1_segment_limit")
            aggregate = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            fs, handles = ad1_open(str(source), manifest)
            try:
                logical_version = int(fs.logical_image.version)
                if logical_version != 4:
                    raise EvidenceError("only AD1 logical image version 4 is supported", code="ad1_version_unsupported")
            finally:
                for handle in handles:
                    handle.close()
            for item in manifest:
                current = Path(str(item["path"])).stat()
                if current.st_size != int(item["size"]) or current.st_mtime_ns != int(item["mtime_ns"]):
                    raise EvidenceError("AD1 segment changed during registration", code="source_changed", details={"path": item["path"]})
            source_sha256 = aggregate
            media_size = sum(int(item["size"]) for item in manifest)
            sector_size = 0
            raw_exposure_path = None
            exposure_mode = "ad1"
            exposure_verified_at = utc_now_iso()
            exposure_details = {"segments": manifest, "logical_version": logical_version, "segment_count": len(manifest)}
            record_format = "AD1"
            md5 = sha1 = None
            ewfinfo_version = None
            ewfinfo_duration_ms = 0.0
            ewfinfo_command = {}
            layout = Layout(scope="logical", filesystem=None, offset_sectors=0, method="dissect.evidence", details={"logical_version": logical_version}, warnings=[])
            status = "ready"
        elif extension == ".e01":
            result = self.runner.run(
                ["ewfinfo", str(source)],
                timeout=self.settings.command_timeout,
                evidence_id=evidence_id,
            )
            if not result.ok:
                raise EvidenceError(
                    f"ewfinfo failed: {_stderr_excerpt(result)}",
                    code="ewfinfo_failed",
                    details={
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                    },
                )
            info = parse_ewfinfo(result.stdout)
            media_size = info.get("media_size")
            if not media_size:
                raise EvidenceError(
                    "ewfinfo did not report a usable media size",
                    code="ewfinfo_no_media_size",
                    details={"path": str(source)},
                )
            media_size = int(media_size)
            sector_size = int(info.get("sector_size") or 512)
            resolution = self.provider.resolve(
                source, media_size, evidence_id, source_sha256
            )
            warnings.extend(resolution.warnings)
            record_format = str(info.get("format") or "EWF")
            md5 = info.get("md5")
            sha1 = info.get("sha1")
            ewfinfo_version = info.get("tool_version") or self._tool_version(
                "ewfinfo"
            )
            ewfinfo_duration_ms = result.duration_ms
            ewfinfo_command = result.to_dict(include_output=True)
            raw_exposure_path = str(resolution.path)
            exposure_mode = resolution.mode
            exposure_verified_at = resolution.verified_at
            exposure_details = resolution.details
        else:
            media_size = source_size
            sector_size = 512
            if not os.access(source, os.R_OK):
                raise EvidenceError(
                    "raw evidence is not readable",
                    code="source_not_readable",
                    details={"path": str(source)},
                )
            raw_exposure_path = str(source)
            exposure_mode = "direct"
            exposure_verified_at = utc_now_iso()
            exposure_details = {
                "path": str(source),
                "size": source_size,
                "mode": oct(stat_module.S_IMODE(source_stat.st_mode)),
                "read_only": not _has_write_bits(source_stat.st_mode),
                "source": "direct",
            }
            record_format = "raw"
            md5 = None
            sha1 = None
            ewfinfo_version = None
            ewfinfo_duration_ms = 0.0
            ewfinfo_command = {}
            warnings.append(
                "raw/img evidence is read directly; no EWF exposure is used"
            )
            if _has_write_bits(source_stat.st_mode):
                warnings.append(
                    "raw/img evidence has write permission bits; the application "
                    "only reads it"
                )

        if extension != ".ad1":
            try:
                layout = detect_layout(
                    self.runner, Path(raw_exposure_path), evidence_id=evidence_id
                )
                warnings.extend(layout.warnings)
                if layout.details.get("sector_size"):
                    sector_size = int(layout.details["sector_size"])
                status = "ready"
            except FilesystemError as exc:
                layout = Layout(
                    scope="unknown",
                    filesystem=None,
                    offset_sectors=0,
                    method="failed",
                    details={},
                    warnings=[str(exc)],
                )
                status = "layout_error"
                warnings.append(f"filesystem detection failed: {exc}")

        try:
            final_stat = source.stat()
        except OSError as exc:
            raise EvidenceError(
                f"cannot re-stat source evidence: {exc}",
                code="source_stat_failed",
            ) from exc
        if (
            final_stat.st_size != source_size
            or final_stat.st_mtime_ns != source_mtime_ns
        ):
            raise EvidenceError(
                "source evidence changed during registration",
                code="source_changed",
                details={
                    "expected_size": source_size,
                    "actual_size": final_stat.st_size,
                    "expected_mtime_ns": source_mtime_ns,
                    "actual_mtime_ns": final_stat.st_mtime_ns,
                },
            )

        record = EvidenceRecord(
            evidence_id=evidence_id,
            resolved_source_path=str(source),
            filename=source.name,
            extension=extension,
            source_sha256=source_sha256,
            source_size=source_size,
            source_mtime_ns=source_mtime_ns,
            format=record_format,
            media_size=media_size,
            sector_size=sector_size,
            md5=md5,
            sha1=sha1,
            ewfinfo_version=ewfinfo_version,
            ewfinfo_duration_ms=ewfinfo_duration_ms,
            ewfinfo_command=ewfinfo_command,
            raw_exposure_path=raw_exposure_path,
            exposure_mode=exposure_mode,
            exposure_verified_at=exposure_verified_at,
            exposure_details=exposure_details,
            layout=layout,
            registered_at=utc_now_iso(),
            status=status,
            warnings=list(dict.fromkeys(warnings)),
        )
        self.registry.upsert(record.to_dict())
        self._logger.info(
            "registered evidence id=%s source=%s exposure_mode=%s exposure=%s "
            "status=%s layout=%s offset=%s",
            evidence_id,
            source,
            exposure_mode,
            raw_exposure_path,
            status,
            layout.filesystem,
            layout.offset_sectors,
        )
        return record

    def get(self, evidence_id: str) -> EvidenceRecord:
        self.policy.validate_evidence_id(evidence_id)
        record = self.registry.get(evidence_id)
        if record is None:
            raise EvidenceNotFound(f"unknown evidence id: {evidence_id}")
        return EvidenceRecord.from_dict(record)

    def list(self) -> list[EvidenceRecord]:
        return [EvidenceRecord.from_dict(item) for item in self.registry.list_all()]

    def ensure_image(self, record: EvidenceRecord) -> Path:
        if record.exposure_mode == "legacy" or not record.source_sha256:
            raise EvidenceAccessError(
                "evidence record uses a legacy schema; re-register the evidence",
                code="legacy_registry_record",
                details={"evidence_id": record.evidence_id},
            )

        source = self.policy.validate_evidence_path(record.resolved_source_path)
        try:
            source_stat = source.stat()
        except OSError as exc:
            raise EvidenceAccessError(
                f"cannot stat source evidence: {exc}",
                code="source_stat_failed",
            ) from exc
        if (
            source_stat.st_size != record.source_size
            or source_stat.st_mtime_ns != record.source_mtime_ns
        ):
            raise EvidenceAccessError(
                "source evidence size or mtime changed since registration",
                code="source_changed",
                details={
                    "expected_size": record.source_size,
                    "actual_size": source_stat.st_size,
                    "expected_mtime_ns": record.source_mtime_ns,
                    "actual_mtime_ns": source_stat.st_mtime_ns,
                },
            )

        if record.extension == ".ad1":
            from .backends import ad1_segments

            try:
                paths = ad1_segments(source, self.policy.allowed_roots)
                expected = record.exposure_details.get("segments") or []
                if len(paths) != len(expected):
                    raise EvidenceAccessError("AD1 segment set changed since registration", code="source_changed")
                for path, pinned in zip(paths, expected):
                    current = path.stat()
                    if str(path) != str(pinned.get("path")) or current.st_size != int(pinned.get("size", -1)) or current.st_mtime_ns != int(pinned.get("mtime_ns", -1)):
                        raise EvidenceAccessError("AD1 segment changed since registration", code="source_changed", details={"path": str(path)})
            except EvidenceAccessError:
                raise
            except Exception as exc:
                raise EvidenceAccessError(f"AD1 segments are unavailable: {exc}", code="ad1_segment_missing") from exc
            return source

        if record.exposure_mode == "direct":
            if record.media_size != record.source_size:
                raise EvidenceAccessError(
                    "direct evidence size does not match registered media size",
                    code="exposure_size_mismatch",
                    details={
                        "media_size": record.media_size,
                        "source_size": record.source_size,
                    },
                )
            return source

        if record.exposure_mode not in {"explicit", "managed"}:
            raise EvidenceAccessError(
                f"unknown exposure mode: {record.exposure_mode}",
                code="exposure_mode_invalid",
                details={"mode": record.exposure_mode},
            )
        if not record.raw_exposure_path:
            raise EvidenceAccessError(
                "evidence record has no raw exposure path",
                code="exposure_missing",
                details={"evidence_id": record.evidence_id},
            )
        try:
            exposure = Path(record.raw_exposure_path).resolve(strict=True)
        except FileNotFoundError as exc:
            raise EvidenceAccessError(
                "recorded raw exposure no longer exists",
                code="exposure_missing",
                details={"path": record.raw_exposure_path},
            ) from exc
        except OSError as exc:
            raise EvidenceAccessError(
                f"cannot resolve raw exposure: {exc}",
                code="exposure_unavailable",
            ) from exc
        if not exposure.is_file():
            raise EvidenceAccessError(
                "recorded raw exposure is not a regular file",
                code="exposure_not_file",
                details={"path": str(exposure)},
            )
        if not os.access(exposure, os.R_OK):
            raise EvidenceAccessError(
                "recorded raw exposure is not readable",
                code="exposure_not_readable",
                details={"path": str(exposure)},
            )
        exposure_stat = exposure.stat()
        if _has_write_bits(exposure_stat.st_mode):
            raise EvidenceAccessError(
                "recorded raw exposure is writable",
                code="exposure_writable",
                details={"path": str(exposure)},
            )
        if exposure_stat.st_size != record.media_size:
            raise EvidenceAccessError(
                "recorded raw exposure size no longer matches media size",
                code="exposure_size_mismatch",
                details={
                    "path": str(exposure),
                    "exposure_size": exposure_stat.st_size,
                    "media_size": record.media_size,
                },
            )
        return exposure

    def inspect(self, evidence_id: str) -> dict[str, Any]:
        record = self.get(evidence_id)
        exposure_info: dict[str, Any] = {
            "path": record.raw_exposure_path,
            "mode": record.exposure_mode,
            "verified_at": record.exposure_verified_at,
            "readable": False,
            "read_only": None,
            "size": None,
            "error": None,
        }
        try:
            exposure = self.ensure_image(record)
            exposure_stat = exposure.stat()
            exposure_info["path"] = str(exposure)
            exposure_info["readable"] = True
            exposure_info["read_only"] = not _has_write_bits(exposure_stat.st_mode)
            exposure_info["size"] = exposure_stat.st_size
        except (DFIRError, OSError) as exc:
            exposure_info["error"] = (
                exc.to_dict() if isinstance(exc, DFIRError) else str(exc)
            )
        return {
            "trust": TRUST_LABEL,
            "evidence": record.to_dict(),
            "layout": record.layout.to_dict(),
            "source": {
                "path": record.resolved_source_path,
                "sha256": record.source_sha256,
                "size": record.source_size,
                "mtime_ns": record.source_mtime_ns,
            },
            "exposure": exposure_info,
        }
