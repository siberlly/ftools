from __future__ import annotations

from pathlib import Path

import pytest

from dfir_browser.core.cases import CaseError, CaseManager
from dfir_browser.core.evidence import Registry
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.policy import SecurityPolicy


def manager(tmp_path: Path) -> tuple[CaseManager, Registry]:
    allowed = tmp_path / "evidence"
    allowed.mkdir()
    policy = SecurityPolicy((allowed,), tmp_path / "var")
    registry = Registry(tmp_path / "var" / "registry.json")
    return CaseManager(tmp_path / "var" / "cases.json", policy, registry), registry


def test_case_lifecycle_and_usage(tmp_path: Path) -> None:
    cases, registry = manager(tmp_path)
    assert cases.active().case_id == "case01"
    created = cases.create("lab-01", "Lab 01", "Synthetic exercise")
    assert created.case_id == "lab-01"
    assert cases.active().case_id == "lab-01"

    export = cases.policy.case_exports_dir("lab-01") / "sample.bin"
    export.write_bytes(b"fixture")
    assert cases.usage("lab-01") == {"bytes": 7, "files": 1, "evidence_count": 0}

    cases.open("case01")
    archived = cases.set_archived("lab-01", True)
    assert archived.status == "archived"
    assert cases.set_archived("lab-01", False).status == "active"
    cases.delete("lab-01")
    with pytest.raises(CaseError):
        cases.get("lab-01")


def test_nonempty_case_cannot_be_deleted(tmp_path: Path) -> None:
    cases, registry = manager(tmp_path)
    cases.create("lab-02", "Lab 02")
    registry.upsert({"evidence_id": "ev_000000000001", "case_id": "lab-02"})
    cases.open("case01")
    with pytest.raises(CaseError, match="only empty cases"):
        cases.delete("lab-02")


def test_legacy_evidence_defaults_to_default_case() -> None:
    record = EvidenceRecord.from_dict(
        {
            "evidence_id": "ev_000000000001",
            "resolved_source_path": "/evidence/sample.raw",
            "layout": Layout("volume", "NTFS", 0, "test").to_dict(),
        }
    )
    assert record.case_id == "case01"
