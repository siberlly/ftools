from __future__ import annotations

import json
from pathlib import Path

import pytest

from dfir_browser.core.config import (
    ConfigurationError,
    EwfMapping,
    Settings,
    load_ewf_mappings,
    normalize_mappings,
)


def test_mapping_from_env_json(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "disk.E01"
    exposure = tmp_path / "ewf1"
    source.write_bytes(b"x")
    exposure.write_bytes(b"y")
    payload = {
        "version": 1,
        "mappings": {
            str(source): {
                "exposure": str(exposure),
                "source_sha256": "a" * 64,
                "media_size": 1234,
            }
        },
    }
    monkeypatch.setenv("DFIR_EWF_MAPPINGS", json.dumps(payload))
    settings = Settings.from_env(
        var_dir=tmp_path / "var", allowed_roots=(tmp_path,)
    )
    mapping = settings.ewf_mappings[str(source.resolve())]
    assert mapping.exposure == str(exposure.resolve())
    assert mapping.source_sha256 == "a" * 64
    assert mapping.media_size == 1234


def test_mapping_from_default_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DFIR_EWF_MAPPINGS", raising=False)
    var = tmp_path / "var"
    var.mkdir()
    source = tmp_path / "disk.E01"
    exposure = tmp_path / "ewf1"
    source.write_bytes(b"x")
    exposure.write_bytes(b"y")
    (var / "ewf_mappings.json").write_text(
        json.dumps(
            {
                "version": 1,
                "mappings": {str(source): str(exposure)},
            }
        ),
        encoding="utf-8",
    )
    settings = Settings.from_env(var_dir=var, allowed_roots=(tmp_path,))
    assert settings.ewf_mappings[str(source.resolve())].exposure == str(
        exposure.resolve()
    )


def test_mapping_file_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DFIR_EWF_MAPPINGS", raising=False)
    mapping_file = tmp_path / "mapping.json"
    source = tmp_path / "disk.E01"
    exposure = tmp_path / "ewf1"
    source.write_bytes(b"x")
    exposure.write_bytes(b"y")
    mapping_file.write_text(
        json.dumps({str(source): {"exposure": str(exposure)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("DFIR_EWF_MAPPING_FILE", str(mapping_file))
    settings = Settings.from_env(
        var_dir=tmp_path / "var", allowed_roots=(tmp_path,)
    )
    assert str(source.resolve()) in settings.ewf_mappings


def test_missing_mapping_file_env_is_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DFIR_EWF_MAPPINGS", raising=False)
    monkeypatch.setenv(
        "DFIR_EWF_MAPPING_FILE", str(tmp_path / "does-not-exist.json")
    )
    with pytest.raises(ConfigurationError, match="does not exist"):
        Settings.from_env(var_dir=tmp_path / "var", allowed_roots=(tmp_path,))


def test_invalid_env_json_is_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DFIR_EWF_MAPPINGS", "{not json")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        Settings.from_env(var_dir=tmp_path / "var", allowed_roots=(tmp_path,))


def test_duplicate_resolved_sources_rejected(tmp_path: Path) -> None:
    data = {
        str(tmp_path / "a" / ".." / "disk.E01"): "/tmp/one",
        str(tmp_path / "disk.E01"): "/tmp/two",
    }
    with pytest.raises(ConfigurationError, match="duplicate mapping"):
        normalize_mappings(data)


def test_invalid_sha256_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="source_sha256"):
        normalize_mappings(
            {str(tmp_path / "disk.E01"): {"exposure": "/tmp/ewf1", "source_sha256": "abc"}}
        )


def test_invalid_media_size_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="media_size"):
        normalize_mappings(
            {str(tmp_path / "disk.E01"): {"exposure": "/tmp/ewf1", "media_size": 0}}
        )


def test_unknown_mapping_keys_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="unsupported keys"):
        normalize_mappings(
            {str(tmp_path / "disk.E01"): {"exposure": "/tmp/ewf1", "wat": 1}}
        )


def test_relative_mapping_paths_rejected() -> None:
    with pytest.raises(ConfigurationError, match="absolute"):
        normalize_mappings({"relative.E01": "/tmp/ewf1"})
    with pytest.raises(ConfigurationError, match="absolute"):
        normalize_mappings({"/tmp/disk.E01": "relative/ewf1"})


def test_direct_mapping_schema_and_ewf_mapping_override(tmp_path: Path) -> None:
    source = str(tmp_path / "disk.E01")
    mapping = EwfMapping(exposure=str(tmp_path / "ewf1"), media_size=4096)
    normalized = normalize_mappings({source: mapping})
    assert normalized[str(Path(source).resolve())].media_size == 4096


def test_env_mapping_overrides_file(monkeypatch, tmp_path: Path) -> None:
    var = tmp_path / "var"
    var.mkdir()
    source = tmp_path / "disk.E01"
    file_exposure = tmp_path / "file-ewf1"
    env_exposure = tmp_path / "env-ewf1"
    for path in (source, file_exposure, env_exposure):
        path.write_bytes(b"x")
    (var / "ewf_mappings.json").write_text(
        json.dumps({str(source): str(file_exposure)}), encoding="utf-8"
    )
    monkeypatch.setenv(
        "DFIR_EWF_MAPPINGS",
        json.dumps({str(source): str(env_exposure)}),
    )
    mappings = load_ewf_mappings(var)
    assert mappings[str(source.resolve())].exposure == str(
        env_exposure.resolve()
    )
