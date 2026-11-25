from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .errors import DFIRError
from .models import utc_now_iso


class CaseError(DFIRError):
    default_code = "case_error"


@dataclass(slots=True)
class CaseRecord:
    case_id: str
    name: str
    description: str
    status: str
    created_at: str
    updated_at: str
    archived_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CaseRecord":
        now = utc_now_iso()
        return cls(str(value["case_id"]), str(value.get("name") or value["case_id"]), str(value.get("description") or ""), str(value.get("status") or "active"), str(value.get("created_at") or now), str(value.get("updated_at") or now), value.get("archived_at"))


class CaseManager:
    """Atomic single-user case registry; evidence remains read-only."""

    def __init__(self, path: Path, policy, evidence_registry) -> None:
        self.path = Path(path)
        self.policy = policy
        self.evidence_registry = evidence_registry
        self._lock = threading.RLock()
        self._ensure_default()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "active_case_id": "case01", "cases": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseError(f"cannot read case registry: {exc}", code="case_registry_corrupt") from exc
        if not isinstance(value, dict) or not isinstance(value.get("cases"), dict):
            raise CaseError("case registry is malformed", code="case_registry_corrupt")
        return value

    def _write(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".cases.", suffix=".tmp", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _ensure_default(self) -> None:
        with self._lock:
            value = self._read()
            if "case01" not in value.setdefault("cases", {}):
                now = utc_now_iso()
                value["cases"]["case01"] = CaseRecord("case01", "Default case", "Migrated legacy workspace", "active", now, now).to_dict()
            value.setdefault("active_case_id", "case01")
            self._write(value)

    def list(self) -> list[CaseRecord]:
        with self._lock:
            records = [CaseRecord.from_dict(item) for item in self._read()["cases"].values()]
        return sorted(records, key=lambda item: item.updated_at, reverse=True)

    def get(self, case_id: str) -> CaseRecord:
        case_id = self.policy.validate_case_id(case_id)
        with self._lock:
            item = self._read()["cases"].get(case_id)
        if item is None:
            raise CaseError("case not found", code="case_not_found")
        return CaseRecord.from_dict(item)

    def active(self) -> CaseRecord:
        with self._lock:
            value = self._read()
            case_id = value.get("active_case_id", "case01")
        return self.get(case_id)

    def create(self, case_id: str, name: str, description: str = "") -> CaseRecord:
        case_id = self.policy.validate_case_id(case_id)
        name, description = str(name).strip(), str(description).strip()
        if not name or len(name) > 120 or len(description) > 1000:
            raise CaseError("case name or description is invalid", code="case_invalid")
        with self._lock:
            value = self._read()
            if case_id in value["cases"]:
                raise CaseError("case id already exists", code="case_exists")
            now = utc_now_iso()
            record = CaseRecord(case_id, name, description, "active", now, now)
            value["cases"][case_id] = record.to_dict()
            value["active_case_id"] = case_id
            self._write(value)
        self.policy.case_exports_dir(case_id)
        return record

    def open(self, case_id: str) -> CaseRecord:
        record = self.get(case_id)
        if record.status == "archived":
            raise CaseError("restore this archived case before opening it", code="case_archived")
        with self._lock:
            value = self._read()
            value["active_case_id"] = case_id
            value["cases"][case_id]["updated_at"] = utc_now_iso()
            self._write(value)
        return self.get(case_id)

    def set_archived(self, case_id: str, archived: bool) -> CaseRecord:
        self.get(case_id)
        with self._lock:
            value = self._read()
            if archived and value.get("active_case_id") == case_id:
                replacement = next((key for key, item in value["cases"].items() if key != case_id and item.get("status") == "active"), None)
                if replacement is None:
                    raise CaseError("create another active case first", code="case_last_active")
                value["active_case_id"] = replacement
            now = utc_now_iso()
            value["cases"][case_id].update(status="archived" if archived else "active", archived_at=now if archived else None, updated_at=now)
            self._write(value)
        return self.get(case_id)

    def evidence_count(self, case_id: str) -> int:
        return sum(str(item.get("case_id") or "case01") == case_id for item in self.evidence_registry.list_all())

    def usage(self, case_id: str) -> dict[str, int]:
        root = self.policy.var_dir / "cases" / case_id
        total = files = 0
        if root.exists():
            for path in root.rglob("*"):
                try:
                    if path.is_file() and not path.is_symlink():
                        total += path.stat().st_size
                        files += 1
                except OSError:
                    continue
        return {"bytes": total, "files": files, "evidence_count": self.evidence_count(case_id)}

    def delete(self, case_id: str) -> None:
        if self.evidence_count(case_id):
            raise CaseError("only empty cases can be deleted; archive this case instead", code="case_not_empty")
        with self._lock:
            value = self._read()
            if value.get("active_case_id") == case_id:
                raise CaseError("open another case before deleting this one", code="case_is_active")
            if case_id not in value["cases"]:
                raise CaseError("case not found", code="case_not_found")
            del value["cases"][case_id]
            self._write(value)
        root = (self.policy.var_dir / "cases" / case_id).resolve()
        cases_root = (self.policy.var_dir / "cases").resolve()
        if root.exists() and root.is_relative_to(cases_root) and not root.is_symlink():
            shutil.rmtree(root)
