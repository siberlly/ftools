from __future__ import annotations

import json
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from dfir_browser.core.evidence import (
    REGISTRY_SCHEMA_VERSION,
    Registry,
    RegistryError,
)


def record(index: int) -> dict:
    return {
        "evidence_id": f"ev_{index:012x}",
        "registered_at": f"2026-01-01T00:00:{index:02d}Z",
        "status": "ready",
    }


def test_missing_registry_lists_empty(tmp_path: Path) -> None:
    registry = Registry(tmp_path / "registry.json")
    assert registry.list_all() == []


def test_atomic_write_permissions_and_no_temp_files(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    registry = Registry(path)
    for index in range(5):
        registry.upsert(record(index))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == REGISTRY_SCHEMA_VERSION
    assert len(data["evidences"]) == 5
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "registry.lock").stat().st_mode) == 0o600
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".registry.json.*.tmp")) == []


def test_malformed_json_is_kept_and_reported(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text("{this is not json", encoding="utf-8")
    registry = Registry(path)
    with pytest.raises(RegistryError) as excinfo:
        registry.list_all()
    assert excinfo.value.code == "registry_corrupt"
    assert path.read_text(encoding="utf-8") == "{this is not json"


def test_malformed_registry_does_not_get_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text("{bad", encoding="utf-8")
    registry = Registry(path)
    with pytest.raises(RegistryError):
        registry.upsert(record(1))
    assert path.read_text(encoding="utf-8") == "{bad"


def test_invalid_registry_shapes_rejected(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    registry = Registry(path)
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(RegistryError, match="root must be an object"):
        registry.list_all()
    path.write_text('{"version": 2, "evidences": []}', encoding="utf-8")
    with pytest.raises(RegistryError, match="must be an object"):
        registry.list_all()


def test_newer_registry_schema_rejected(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"version": REGISTRY_SCHEMA_VERSION + 1, "evidences": {}}),
        encoding="utf-8",
    )
    with pytest.raises(RegistryError) as excinfo:
        Registry(path).list_all()
    assert excinfo.value.code == "registry_schema_newer"


def test_old_schema_is_readable(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"version": 1, "evidences": {}}), encoding="utf-8"
    )
    assert Registry(path).list_all() == []


def test_concurrent_writers_do_not_lose_records(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    registries = [Registry(path) for _ in range(4)]

    def worker(index: int) -> None:
        registries[index % len(registries)].upsert(record(index))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(20)))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["evidences"]) == 20
    assert set(data["evidences"]) == {
        f"ev_{index:012x}" for index in range(20)
    }
    assert list(tmp_path.glob(".registry.json.*.tmp")) == []
