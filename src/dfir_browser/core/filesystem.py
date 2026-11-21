from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .command import CommandResult, CommandRunner
from .audit import get_correlation_id
from .config import Settings
from .errors import DFIRError
from .hashing import HashTimeout, sha256_file
from .models import (
    DirectoryListing,
    ExtractionResult,
    Layout,
    MetadataResult,
    utc_now_iso,
)
from .parsers import parse_fls, parse_fsstat, parse_istat, parse_mmls
from .policy import SecurityPolicy


class FilesystemError(DFIRError):
    """Raised when Sleuth Kit cannot inspect or read the filesystem."""

    default_code = "filesystem_error"


class ExtractionError(FilesystemError):
    """Raised when a file cannot be safely extracted."""

    default_code = "extraction_error"


def _tsk_argv(
    tool: str,
    image_path: Path,
    offset_sectors: int,
    options: list[str] | None = None,
    inode: int | None = None,
) -> list[str]:
    argv = [tool]
    if offset_sectors > 0:
        argv.extend(["-o", str(offset_sectors)])
    if options:
        argv.extend(options)
    argv.append(str(image_path))
    if inode is not None:
        argv.append(str(inode))
    return argv


def _stderr_excerpt(result: CommandResult, limit: int = 500) -> str:
    text = (result.stderr or "").strip()
    if not text:
        return "no stderr output"
    return text[:limit].replace("\n", " ")


def detect_layout(
    runner: CommandRunner,
    image_path: Path,
    evidence_id: str | None = None,
) -> Layout:
    """Detect whether the image is a whole volume or a partitioned disk.

    ``mmls`` is attempted first. Its failure is *not* treated as evidence
    corruption: the volume is then probed with ``fsstat`` at sector 0.
    """
    image_path = Path(image_path)
    if not image_path.is_file():
        raise FilesystemError(
            f"view image is not a regular file: {image_path}",
            code="exposure_not_file",
        )
    if not os.access(image_path, os.R_OK):
        raise FilesystemError(
            f"view image is not readable: {image_path}",
            code="exposure_not_readable",
        )

    timeout = getattr(runner, "timeout", 60.0)
    warnings: list[str] = []

    mmls_result = runner.run(
        ["mmls", str(image_path)], timeout=timeout, evidence_id=evidence_id
    )
    mmls_parsed: dict[str, Any] = {"slots": [], "data_slots": []}
    if not mmls_result.ok:
        warnings.append(
            "mmls did not produce a partition table "
            f"(exit={mmls_result.exit_code}, {_stderr_excerpt(mmls_result)}); "
            "falling back to fsstat at sector 0"
        )
    elif not (mmls_result.stdout or "").strip():
        warnings.append("mmls returned empty output; falling back to fsstat at sector 0")
    else:
        mmls_parsed = parse_mmls(mmls_result.stdout)

    if mmls_parsed.get("data_slots"):
        first = mmls_parsed["data_slots"][0]
        unit_bytes = int(mmls_parsed.get("unit_bytes") or 512)
        offset = int(first["start_sectors"]) * unit_bytes // 512
        fs_result = runner.run(
            ["fsstat", "-o", str(offset), str(image_path)],
            timeout=timeout,
            evidence_id=evidence_id,
        )
        fs_info = parse_fsstat(fs_result.stdout) if fs_result.ok else {}
        if fs_result.ok and fs_info.get("filesystem"):
            return Layout(
                scope="partition",
                filesystem=fs_info["filesystem"],
                offset_sectors=offset,
                method="mmls+fsstat",
                details={
                    **fs_info,
                    "partition_slot": first["slot"],
                    "partition_description": first["description"],
                    "partition_start_sectors": offset,
                },
                warnings=warnings,
            )
        warnings.append(
            f"fsstat failed at mmls partition offset {offset}; "
            "falling back to fsstat at sector 0"
        )
    elif mmls_result.ok and (mmls_result.stdout or "").strip():
        warnings.append(
            "mmls found no data partitions; falling back to fsstat at sector 0"
        )

    fs_result = runner.run(
        ["fsstat", "-o", "0", str(image_path)],
        timeout=timeout,
        evidence_id=evidence_id,
    )
    fs_info = parse_fsstat(fs_result.stdout)
    if not fs_result.ok or not fs_info.get("filesystem"):
        raise FilesystemError(
            "unable to identify a filesystem with fsstat at sector 0: "
            f"{_stderr_excerpt(fs_result)}",
            code="layout_detection_failed",
            details={
                "exit_code": fs_result.exit_code,
                "timed_out": fs_result.timed_out,
            },
        )

    return Layout(
        scope="volume",
        filesystem=fs_info["filesystem"],
        offset_sectors=0,
        method="fsstat",
        details=fs_info,
        warnings=warnings,
    )


class FilesystemService:
    def __init__(
        self,
        policy: SecurityPolicy,
        runner: CommandRunner,
        settings: Settings,
        logger: logging.Logger | None = None,
    ) -> None:
        self.policy = policy
        self.runner = runner
        self.settings = settings
        self._logger = logger or logging.getLogger("dfir_browser.filesystem")

    def _validate_image(self, image_path: Path) -> Path:
        image_path = Path(image_path)
        if not image_path.is_file():
            raise FilesystemError(
                f"view image is not a regular file: {image_path}",
                code="exposure_not_file",
            )
        if not os.access(image_path, os.R_OK):
            raise FilesystemError(
                f"view image is not readable: {image_path}",
                code="exposure_not_readable",
            )
        return image_path

    @staticmethod
    def _validate_offset(offset_sectors: int) -> int:
        if isinstance(offset_sectors, bool) or not isinstance(offset_sectors, int):
            raise FilesystemError(
                "offset_sectors must be an integer", code="invalid_offset"
            )
        if offset_sectors < 0 or offset_sectors > (1 << 63) - 1:
            raise FilesystemError(
                "offset_sectors is out of range", code="invalid_offset"
            )
        return offset_sectors

    def _command_metadata(self, result: CommandResult) -> dict[str, Any]:
        return result.to_dict()

    def _tool_version(self, tool: str) -> str | None:
        getter = getattr(self.runner, "version", None)
        if getter is None:
            return None
        try:
            return getter(tool)
        except Exception:  # version capture must never break analysis
            return None

    def _write_debug(self, name: str, text: str) -> None:
        if not self.settings.debug_raw:
            return
        debug_dir = self.settings.var_dir / "debug"
        try:
            debug_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = debug_dir / re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.chmod(path, 0o600)
        except OSError as exc:
            self._logger.warning("could not write debug output: %s", exc)

    def list_directory(
        self,
        image_path: Path,
        evidence_id: str,
        inode: int = 5,
        offset_sectors: int = 0,
    ) -> DirectoryListing:
        image_path = self._validate_image(image_path)
        inode = self.policy.validate_inode(inode)
        offset_sectors = self._validate_offset(offset_sectors)

        argv = _tsk_argv("fls", image_path, offset_sectors, ["-l"], inode)
        result = self.runner.run(
            argv, timeout=self.settings.command_timeout, evidence_id=evidence_id
        )
        if not result.ok:
            raise FilesystemError(
                f"fls failed for inode {inode}: {_stderr_excerpt(result)}",
                code="fls_failed",
                details={
                    "inode": inode,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                },
            )

        self._write_debug(f"fls_{evidence_id}_{inode}.txt", result.stdout)

        warnings: list[str] = []
        truncated = bool(result.stdout_truncated)
        warning: str | None = None
        parse_text = result.stdout
        if truncated:
            warning = (
                "fls output was truncated at "
                f"{result.stdout_bytes_seen} bytes; this directory listing is "
                "INCOMPLETE and must not be treated as the full contents."
            )
            warnings.append(warning)
            if result.stdout and not result.stdout.endswith("\n"):
                cut = result.stdout.rfind("\n")
                parse_text = result.stdout[: cut + 1] if cut >= 0 else ""
                warnings.append(
                    "Dropped the final partial line because fls output was truncated."
                )

        parsed = parse_fls(parse_text)
        entries = [
            entry for entry in parsed.entries if entry.name not in {".", ".."}
        ]
        if result.stderr.strip():
            warnings.append(f"fls: {_stderr_excerpt(result)}")
        if parsed.unparsed:
            warnings.append(
                f"{len(parsed.unparsed)} fls output line(s) could not be parsed"
            )

        return DirectoryListing(
            evidence_id=evidence_id,
            inode=inode,
            offset_sectors=offset_sectors,
            breadcrumb=self.breadcrumb(
                image_path, inode, offset_sectors, evidence_id=evidence_id
            ),
            entries=entries,
            warnings=warnings,
            tool_version=self._tool_version("fls"),
            command=self._command_metadata(result),
            complete=not truncated,
            truncated=truncated,
            warning=warning,
            cursor=None,
            next_cursor=None,
            source="live",
            path="",
            index_status=None,
            total=None,
            page=1,
            page_size=0,
        )

    def _istat(
        self,
        image_path: Path,
        inode: int,
        offset_sectors: int,
        evidence_id: str | None = None,
    ) -> tuple[dict[str, Any], CommandResult]:
        argv = _tsk_argv("istat", image_path, offset_sectors, None, inode)
        result = self.runner.run(
            argv, timeout=self.settings.command_timeout, evidence_id=evidence_id
        )
        if not result.ok:
            raise FilesystemError(
                f"istat failed for inode {inode}: {_stderr_excerpt(result)}",
                code="istat_failed",
                details={
                    "inode": inode,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                },
            )
        summary = parse_istat(result.stdout)
        if summary.get("inode") is None:
            raise FilesystemError(
                f"istat returned no MFT entry header for inode {inode}",
                code="istat_no_header",
                details={"inode": inode},
            )
        return summary, result

    def stat(
        self,
        image_path: Path,
        evidence_id: str,
        inode: int,
        offset_sectors: int = 0,
    ) -> MetadataResult:
        image_path = self._validate_image(image_path)
        inode = self.policy.validate_inode(inode)
        offset_sectors = self._validate_offset(offset_sectors)

        summary, result = self._istat(
            image_path, inode, offset_sectors, evidence_id=evidence_id
        )
        self._write_debug(f"istat_{evidence_id}_{inode}.txt", result.stdout)
        warnings: list[str] = []
        if summary.get("inode") != inode:
            warnings.append(
                f"istat returned MFT entry {summary.get('inode')} "
                f"for requested inode {inode}"
            )
        if result.stderr.strip():
            warnings.append(f"istat: {_stderr_excerpt(result)}")

        raw = result.stdout[: self.settings.max_metadata_bytes]
        raw_truncated = (
            len(result.stdout) > self.settings.max_metadata_bytes
            or result.stdout_truncated
        )

        return MetadataResult(
            evidence_id=evidence_id,
            inode=inode,
            summary=summary,
            raw=raw,
            raw_truncated=raw_truncated,
            warnings=warnings,
            tool_version=self._tool_version("istat"),
            command=self._command_metadata(result),
        )

    def breadcrumb(
        self,
        image_path: Path,
        inode: int,
        offset_sectors: int = 0,
        evidence_id: str | None = None,
    ) -> list[dict[str, Any]]:
        inode = self.policy.validate_inode(inode)
        if inode == 5:
            return [{"inode": 5, "name": "/"}]

        chain: list[dict[str, Any]] = []
        visited: set[int] = set()
        current = inode
        for _ in range(64):
            if current in visited or current == 5:
                break
            visited.add(current)
            try:
                summary, _result = self._istat(
                    image_path, current, offset_sectors, evidence_id=evidence_id
                )
            except FilesystemError:
                chain.append({"inode": current, "name": f"inode {current}"})
                break
            name = summary.get("name") or f"inode {current}"
            chain.append({"inode": current, "name": name})
            parent = summary.get("parent_inode")
            if parent is None or parent == current:
                break
            current = int(parent)
        else:
            self._logger.warning("breadcrumb depth limit reached for inode %s", inode)

        return [{"inode": 5, "name": "/"}] + list(reversed(chain))

    @staticmethod
    def _claim_output(exports_dir: Path, filename: str) -> Path:
        stem = Path(filename).stem
        suffix = Path(filename).suffix
        for attempt in range(1000):
            candidate = exports_dir / (
                filename if attempt == 0 else f"{stem}_{attempt}{suffix}"
            )
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                continue
            else:
                os.close(descriptor)
                return candidate
        raise ExtractionError(
            "could not allocate a unique export filename",
            code="export_name_exhausted",
        )

    def _sha256_file(self, path: Path) -> tuple[str, int]:
        try:
            return sha256_file(path, self.settings.hash_timeout)
        except HashTimeout as exc:
            raise ExtractionError(str(exc), code="hash_timeout") from exc
        except OSError as exc:
            raise ExtractionError(
                f"cannot hash extracted file: {exc}", code="hash_failed"
            ) from exc

    def extract(
        self,
        image_path: Path,
        evidence_id: str,
        inode: int,
        case_id: str,
        offset_sectors: int = 0,
        assume_file: bool = False,
    ) -> ExtractionResult:
        image_path = self._validate_image(image_path)
        inode = self.policy.validate_inode(inode)
        case_id = self.policy.validate_case_id(case_id)
        offset_sectors = self._validate_offset(offset_sectors)

        metadata = self.stat(image_path, evidence_id, inode, offset_sectors)
        summary = metadata.summary
        if summary.get("is_directory") is True:
            raise ExtractionError(
                "refusing to extract a directory as a file",
                code="directory_extraction",
                details={"inode": inode},
            )
        if summary.get("is_directory") is None and not assume_file:
            raise ExtractionError(
                "refusing to extract an entry whose type could not be determined",
                code="entry_type_unknown",
                details={"inode": inode},
            )

        original_name = summary.get("name")
        exports_dir = self.policy.case_exports_dir(case_id)
        filename = self.policy.build_export_filename(inode, original_name)
        output_path = self._claim_output(exports_dir, filename)

        argv = _tsk_argv("icat", image_path, offset_sectors, None, inode)
        result = self.runner.run(
            argv,
            timeout=self.settings.extract_timeout,
            stdout_path=output_path,
            evidence_id=evidence_id,
        )
        if not result.ok:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise ExtractionError(
                f"icat failed for inode {inode}: {_stderr_excerpt(result)}",
                code="icat_failed",
                details={
                    "inode": inode,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                },
            )

        sha256, size = self._sha256_file(output_path)
        warnings: list[str] = []
        expected_size = summary.get("data_size")
        if expected_size is not None and expected_size != size:
            warnings.append(
                f"extracted size {size} differs from istat data size {expected_size}"
            )
        if size == 0:
            warnings.append("extracted file is empty")
        if result.stderr.strip():
            warnings.append(f"icat: {_stderr_excerpt(result)}")

        try:
            relative_path = str(
                output_path.resolve().relative_to(self.settings.var_dir)
            )
        except ValueError:
            relative_path = str(output_path)

        extraction = ExtractionResult(
            evidence_id=evidence_id,
            case_id=case_id,
            inode=inode,
            name=original_name,
            output_path=str(output_path.resolve()),
            relative_path=relative_path,
            size=size,
            sha256=sha256,
            source_size=expected_size,
            tool_version=self._tool_version("icat"),
            extracted_at=utc_now_iso(),
            untrusted=True,
            warnings=warnings,
            command=self._command_metadata(result),
        )

        sidecar = output_path.with_name(output_path.name + ".provenance.json")
        payload = extraction.to_dict()
        payload["raw_exposure_path"] = str(image_path)
        payload["case_id"] = case_id
        try:
            with open(sidecar, "x", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.chmod(sidecar, 0o600)
        except FileExistsError:
            self._logger.warning("provenance sidecar already exists: %s", sidecar)
        except OSError as exc:
            extraction.warnings.append(
                f"could not write provenance sidecar: {exc}"
            )

        try:
            audit_logger = getattr(self.runner, "audit_logger", None)
            if audit_logger is not None:
                audit_logger.event(
                    "extract_file",
                    evidence_id=evidence_id,
                    request_id=get_correlation_id(),
                    details={
                        "inode": inode,
                        "case_id": case_id,
                        "size": size,
                        "sha256": sha256,
                    },
                )
        except Exception:
            self._logger.exception("could not write extraction audit event")

        return extraction
