from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .errors import DFIRError

EVIDENCE_EXTENSIONS = {".e01", ".raw", ".img", ".ad1"}
EVIDENCE_ID_RE = re.compile(r"^ev_[0-9a-f]{12}$")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
INODE_RE = re.compile(r"^(?:0|[1-9][0-9]{0,14})$")
MAX_INODE = (1 << 48) - 1


class PolicyError(DFIRError):
    """Raised when a caller-supplied path or identifier is not allowed."""

    default_code = "policy_error"


class SecurityPolicy:
    """Allowlist and identifier validation for evidence and exports.

    Evidence paths are canonicalised with ``Path.resolve(strict=True)`` so a
    symlink inside an allowed root that points outside is rejected. Case IDs
    and inodes are restricted to conservative character sets before they are
    ever placed on a command line or used as a path component.
    """

    def __init__(
        self,
        allowed_roots: Sequence[Path | str],
        var_dir: Path | str,
    ) -> None:
        if not allowed_roots:
            raise ValueError("at least one allowed evidence root is required")
        self.allowed_roots: tuple[Path, ...] = tuple(
            Path(root).expanduser().resolve() for root in allowed_roots
        )
        self.var_dir = Path(var_dir).expanduser().resolve()

    def _within_allowed_roots(self, resolved: Path) -> bool:
        return any(resolved.is_relative_to(root) for root in self.allowed_roots)

    def browse_directory(
        self, raw_path: str | None, *, limit: int = 2000, evidence_only: bool = True
    ) -> dict[str, Any]:
        """List one directory for the evidence picker, bounded to the allowlist.

        ``raw_path`` is a directory inside an allowed root, or empty for the
        roots themselves. Symlinks are never followed for listing; a symlinked
        directory is only navigable when it resolves inside an allowed root.
        """
        entries: list[dict[str, Any]] = []
        warnings: list[str] = []
        truncated = False
        if not raw_path or not str(raw_path).strip():
            for root in self.allowed_roots:
                entries.append(
                    {
                        "name": root.name or str(root),
                        "path": str(root),
                        "kind": "directory",
                        "size": None,
                    }
                )
            return {
                "path": "",
                "parent": None,
                "roots": [str(root) for root in self.allowed_roots],
                "entries": entries,
                "truncated": False,
                "warnings": warnings,
            }

        text = str(raw_path)
        if "\x00" in text:
            raise PolicyError("path contains a NUL byte")
        candidate = Path(text)
        if not candidate.is_absolute():
            raise PolicyError("path must be absolute")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise PolicyError(f"path does not exist: {text}") from exc
        except OSError as exc:
            raise PolicyError(f"cannot resolve path: {exc}") from exc
        if not resolved.is_dir():
            raise PolicyError("path is not a directory")
        if not self._within_allowed_roots(resolved):
            roots = ", ".join(str(root) for root in self.allowed_roots)
            raise PolicyError(f"path is outside the allowed roots: {roots}")

        parent = None
        if resolved not in self.allowed_roots:
            parent = str(resolved.parent)
            if not self._within_allowed_roots(resolved.parent.resolve()):
                raise PolicyError("parent directory is outside the allowed roots")

        try:
            iterator = os.scandir(resolved)
        except OSError as exc:
            raise PolicyError(f"cannot read directory: {exc}") from exc
        with iterator:
            for entry in iterator:
                if len(entries) >= limit:
                    truncated = True
                    break
                try:
                    is_symlink = entry.is_symlink()
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError:
                    continue
                if entry.name.startswith("."):
                    # Hidden entries are noise in an evidence picker.
                    continue
                if is_symlink:
                    # A symlink is listed only as a hint, never navigable unless
                    # it resolves inside the allowlist.
                    try:
                        target = Path(entry.path).resolve(strict=True)
                    except OSError:
                        warnings.append(f"skipped broken symlink {entry.name}")
                        continue
                    if not self._within_allowed_roots(target) or not target.is_dir():
                        warnings.append(
                            f"skipped symlink outside the allowed roots: {entry.name}"
                        )
                        continue
                    is_dir = True
                if is_dir:
                    entries.append(
                        {
                            "name": entry.name,
                            "path": str(Path(entry.path)),
                            "kind": "directory",
                            "size": None,
                        }
                    )
                    continue
                if not is_file:
                    continue
                suffix = Path(entry.name).suffix.lower()
                if evidence_only and suffix not in EVIDENCE_EXTENSIONS:
                    continue
                try:
                    size = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    size = None
                entries.append(
                    {
                        "name": entry.name,
                        "path": str(Path(entry.path)),
                        "kind": "file",
                        "size": size,
                        "extension": suffix,
                    }
                )
        entries.sort(
            key=lambda item: (
                0 if item["kind"] == "directory" else 1,
                item["name"].lower(),
            )
        )
        return {
            "path": str(resolved),
            "parent": parent,
            "roots": [str(root) for root in self.allowed_roots],
            "entries": entries,
            "truncated": truncated,
            "warnings": warnings,
            "limit": limit,
        }

    def validate_evidence_path(self, raw_path: str) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise PolicyError("evidence path must be a non-empty string")
        if "\x00" in raw_path:
            raise PolicyError("evidence path contains a NUL byte")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            raise PolicyError("evidence path must be absolute")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise PolicyError(f"evidence path does not exist: {raw_path}") from exc
        except OSError as exc:
            raise PolicyError(f"cannot resolve evidence path: {exc}") from exc

        if not resolved.is_file():
            raise PolicyError("evidence path must point to a regular file")
        if resolved.suffix.lower() == ".ad2" or resolved.suffix.lower() in {".ad3", ".ad4"}:
            raise PolicyError("register the primary .ad1 segment, not a continuation segment")
        if resolved.suffix.lower() not in EVIDENCE_EXTENSIONS:
            raise PolicyError(
                "unsupported evidence extension; expected .E01, .raw, .img or .ad1"
            )
        if not self._within_allowed_roots(resolved):
            roots = ", ".join(str(root) for root in self.allowed_roots)
            raise PolicyError(f"evidence path is outside the allowed roots: {roots}")
        if not os.access(resolved, os.R_OK):
            raise PolicyError("evidence path is not readable")
        return resolved

    @staticmethod
    def validate_evidence_id(evidence_id: str) -> str:
        if not isinstance(evidence_id, str) or not EVIDENCE_ID_RE.fullmatch(evidence_id):
            raise PolicyError("invalid evidence id")
        return evidence_id

    @staticmethod
    def validate_case_id(case_id: str) -> str:
        if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
            raise PolicyError(
                "invalid case id; use 1-64 characters from A-Z, a-z, 0-9, _ and -"
            )
        return case_id

    @staticmethod
    def validate_inode(value: int | str) -> int:
        if isinstance(value, bool):
            raise PolicyError("invalid inode")
        if isinstance(value, int):
            inode = value
        elif isinstance(value, str):
            if not INODE_RE.fullmatch(value):
                raise PolicyError(
                    "invalid inode; expected a decimal MFT entry number only"
                )
            inode = int(value)
        else:
            raise PolicyError("invalid inode type")
        if inode < 0 or inode > MAX_INODE:
            raise PolicyError("inode is outside the supported 48-bit MFT range")
        return inode

    def case_exports_dir(self, case_id: str) -> Path:
        self.validate_case_id(case_id)
        cases_root = self.var_dir / "cases"
        cases_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        cases_root_resolved = cases_root.resolve()
        case_dir = cases_root / case_id
        if case_dir.is_symlink():
            raise PolicyError("case directory must not be a symlink")
        try:
            resolved_case = case_dir.resolve(strict=False)
        except OSError as exc:
            raise PolicyError(f"cannot resolve case directory: {exc}") from exc
        if not resolved_case.is_relative_to(cases_root_resolved):
            raise PolicyError("case directory escapes the cases root")
        exports = resolved_case / "exports"
        try:
            exports.mkdir(parents=True, exist_ok=True, mode=0o700)
        except FileExistsError as exc:
            raise PolicyError("case exports path is not a directory") from exc
        resolved_exports = exports.resolve()
        if not resolved_exports.is_relative_to(cases_root_resolved):
            raise PolicyError("exports directory escapes the cases root")
        return resolved_exports

    @staticmethod
    def build_export_filename(inode: int, original_name: str | None) -> str:
        base = (original_name or "").replace("\\", "/").rsplit("/", 1)[-1]
        base = base.replace("\x00", "")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._-")
        if not safe:
            safe = "file.bin"
        if len(safe) > 80:
            safe = safe[:80].rstrip("._-") or "file.bin"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"inode_{inode}_{stamp}_{safe}"
        if Path(filename).name != filename or "/" in filename or "\\" in filename:
            raise PolicyError("generated export filename is not a basename")
        return filename
