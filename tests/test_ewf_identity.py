from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from dfir_browser.core.command import CommandResult
from dfir_browser.core.config import EwfMapping, Settings
from dfir_browser.core.evidence import (
    EvidenceAccessError,
    EvidenceService,
    ImageProvider,
    Registry,
    make_evidence_id,
)
from dfir_browser.core.filesystem import FilesystemService
from dfir_browser.core.policy import SecurityPolicy

MEDIA_SIZE = 4096

EWFINFO = """ewfinfo 20140814

EWF information
\tFile format:\t\tFTK Imager

Media information
\tBytes per sector:\t512
\tNumber of sectors:\t8
\tMedia size:\t\t4 KiB (4096 bytes)

Digest hash information
\tMD5:\t\t\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
\tSHA1:\t\t\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""

FSSTAT = """FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Sector Size: 512
Cluster Size: 4096
Root Directory: 5
"""

IMG_STAT = """IMAGE FILE INFORMATION
--------------------------------------------
Image Type: raw

Size in bytes: 4096
Sector size:\t512
"""


def command_result(argv, stdout="", stderr="", exit_code=0) -> CommandResult:
    return CommandResult(
        argv=list(argv),
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=1.0,
    )


class FakeRunner:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[tuple[list[str], dict]] = []
        self.timeout = 5.0

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        return self.handler(list(argv), kwargs)

    def version(self, binary: str) -> str:
        return "fake-tool 1.0"

    def tools_called(self) -> list[str]:
        return [argv[0] for argv, _ in self.calls]


def default_handler(argv, _kwargs):
    tool = argv[0]
    if tool == "ewfinfo":
        return command_result(argv, stdout=EWFINFO)
    if tool == "mmls":
        return command_result(
            argv, stderr="Cannot determine partition type", exit_code=1
        )
    if tool == "fsstat":
        return command_result(argv, stdout=FSSTAT)
    if tool == "img_stat":
        return command_result(argv, stdout=IMG_STAT)
    if tool == "ewfmount":
        mount_dir = Path(argv[2])
        mount_dir.mkdir(parents=True, exist_ok=True)
        exposure = mount_dir / "ewf1"
        exposure.write_bytes(b"\x00" * MEDIA_SIZE)
        os.chmod(exposure, 0o444)
        return command_result(argv)
    if tool in {"fusermount", "umount"}:
        mount_dir = Path(argv[2])
        exposure = mount_dir / "ewf1"
        if exposure.exists():
            exposure.unlink()
        return command_result(argv)
    raise AssertionError(f"unexpected tool: {argv}")


def make_source(allowed: Path, name: str, content: bytes) -> Path:
    path = allowed / name
    path.write_bytes(content)
    return path


def make_exposure(path: Path, *, mode: int = 0o444) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00" * MEDIA_SIZE)
    os.chmod(path, mode)
    return path


def make_env(
    tmp_path: Path,
    *,
    mappings: dict | None = None,
    automount: bool = False,
    handler=default_handler,
):
    allowed = tmp_path / "allowed"
    allowed.mkdir(exist_ok=True)
    settings = Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(allowed,),
        ewf_mappings=mappings or {},
        ewf_automount=automount,
        command_timeout=5.0,
        extract_timeout=5.0,
        hash_timeout=10.0,
    )
    policy = SecurityPolicy(settings.allowed_roots, settings.var_dir)
    runner = FakeRunner(handler)
    registry = Registry(settings.var_dir / "registry.json")
    filesystem = FilesystemService(policy, runner, settings)
    provider = ImageProvider(
        mappings=settings.ewf_mappings,
        automount=settings.ewf_automount,
        runner=runner,
        mounts_dir=settings.var_dir / "mounts",
    )
    service = EvidenceService(
        policy=policy,
        runner=runner,
        registry=registry,
        provider=provider,
        filesystem=filesystem,
        settings=settings,
    )
    return settings, service, provider, registry, allowed, runner


def test_two_evidence_same_media_size_are_not_cross_matched(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source_a = make_source(allowed, "A.E01", b"A" * 100)
    source_b = make_source(allowed, "B.E01", b"B" * 100)
    exposure_a = make_exposure(tmp_path / "exposures" / "a" / "ewf1")
    exposure_b = make_exposure(tmp_path / "exposures" / "b" / "ewf1")
    mappings = {
        str(source_a.resolve()): EwfMapping(
            exposure=str(exposure_a.resolve()),
            source_sha256=hashlib.sha256(b"A" * 100).hexdigest(),
        ),
        str(source_b.resolve()): EwfMapping(
            exposure=str(exposure_b.resolve()),
            source_sha256=hashlib.sha256(b"B" * 100).hexdigest(),
        ),
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    record_a = service.register(str(source_a))
    record_b = service.register(str(source_b))

    assert record_a.raw_exposure_path == str(exposure_a.resolve())
    assert record_b.raw_exposure_path == str(exposure_b.resolve())
    assert record_a.raw_exposure_path != record_b.raw_exposure_path
    assert record_a.exposure_mode == "explicit"
    assert record_b.exposure_mode == "explicit"
    assert record_a.source_sha256 == hashlib.sha256(b"A" * 100).hexdigest()
    assert record_b.source_sha256 == hashlib.sha256(b"B" * 100).hexdigest()


def test_no_explicit_mapping_never_scans_or_reuses_raw_exposure(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    # A same-size exposure exists, but there is no mapping. It must not be used.
    make_exposure(tmp_path / "unrelated" / "ewf1")
    _settings, service, _provider, registry, _allowed, runner = make_env(
        tmp_path, mappings={}, automount=False
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "ewf_mapping_missing"
    assert registry.get(make_evidence_id(source.resolve())) is None
    assert "fsstat" not in runner.tools_called()
    assert "img_stat" not in runner.tools_called()
    assert "ewfmount" not in runner.tools_called()


def test_explicit_mapping_for_different_source_is_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source_a = make_source(allowed, "A.E01", b"A" * 100)
    source_b = make_source(allowed, "B.E01", b"B" * 100)
    exposure = make_exposure(tmp_path / "ewf1")
    mappings = {
        str(source_b.resolve()): EwfMapping(exposure=str(exposure.resolve()))
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source_a))
    assert excinfo.value.code == "ewf_mapping_missing"


def test_explicit_mapping_source_hash_pin_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    exposure = make_exposure(tmp_path / "ewf1")
    mappings = {
        str(source.resolve()): EwfMapping(
            exposure=str(exposure.resolve()),
            source_sha256=hashlib.sha256(b"wrong").hexdigest(),
        )
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "ewf_mapping_source_mismatch"


def test_explicit_mapping_media_size_pin_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    exposure = make_exposure(tmp_path / "ewf1")
    mappings = {
        str(source.resolve()): EwfMapping(
            exposure=str(exposure.resolve()), media_size=8192
        )
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "ewf_mapping_media_mismatch"


def test_writable_explicit_exposure_rejected(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    exposure = make_exposure(tmp_path / "ewf1", mode=0o644)
    mappings = {
        str(source.resolve()): EwfMapping(exposure=str(exposure.resolve()))
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "exposure_writable"


def test_managed_mount_per_evidence_and_cleanup_only_managed(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source_a = make_source(allowed, "A.E01", b"A" * 100)
    source_b = make_source(allowed, "B.E01", b"B" * 100)
    source_c = make_source(allowed, "C.E01", b"C" * 100)
    explicit_exposure = make_exposure(tmp_path / "explicit" / "ewf1")
    mappings = {
        str(source_a.resolve()): EwfMapping(
            exposure=str(explicit_exposure.resolve())
        )
    }
    settings, service, provider, _registry, _allowed, runner = make_env(
        tmp_path, mappings=mappings, automount=True
    )

    record_a = service.register(str(source_a))
    record_b = service.register(str(source_b))
    record_c = service.register(str(source_c))

    assert record_a.exposure_mode == "explicit"
    assert record_a.raw_exposure_path == str(explicit_exposure.resolve())
    assert record_b.exposure_mode == "managed"
    assert record_c.exposure_mode == "managed"
    assert Path(record_b.raw_exposure_path).parent.name == record_b.evidence_id
    assert Path(record_c.raw_exposure_path).parent.name == record_c.evidence_id
    assert Path(record_b.raw_exposure_path) != Path(record_c.raw_exposure_path)
    assert (
        settings.var_dir
        / "mounts"
        / record_b.evidence_id
        / ".dfir-managed.json"
    ).is_file()
    assert provider.managed_mounts

    provider.cleanup_managed()

    unmount_calls = [
        argv
        for argv, _kwargs in runner.calls
        if argv[0] in {"fusermount", "umount"}
    ]
    assert unmount_calls
    assert not any(
        str(explicit_exposure.resolve()) in " ".join(argv)
        for argv in unmount_calls
    )
    assert not (
        settings.var_dir / "mounts" / record_b.evidence_id
    ).exists()
    assert not (
        settings.var_dir / "mounts" / record_c.evidence_id
    ).exists()
    assert explicit_exposure.exists()


def test_managed_mount_of_other_evidence_not_reused(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings={}, automount=True
    )
    evidence_id = make_evidence_id(source.resolve())
    mount_dir = settings.var_dir / "mounts" / evidence_id
    mount_dir.mkdir(parents=True)
    exposure = mount_dir / "ewf1"
    exposure.write_bytes(b"\x00" * MEDIA_SIZE)
    os.chmod(exposure, 0o444)
    (mount_dir / ".dfir-managed.json").write_text(
        json.dumps(
            {
                "evidence_id": evidence_id,
                "source_path": "/some/other/evidence.E01",
                "source_sha256": "c" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "managed_mount_conflict"


def test_managed_mount_directory_without_marker_not_reused(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings={}, automount=True
    )
    evidence_id = make_evidence_id(source.resolve())
    mount_dir = settings.var_dir / "mounts" / evidence_id
    mount_dir.mkdir(parents=True)
    (mount_dir / "ewf1").write_bytes(b"\x00" * MEDIA_SIZE)
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "managed_mount_unowned"


def test_managed_ewfmount_failure_has_no_fallback(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)

    def handler(argv, _kwargs):
        if argv[0] == "ewfmount":
            return command_result(
                argv, stderr="fuse: permission denied", exit_code=1
            )
        return default_handler(argv, _kwargs)

    settings, service, _provider, registry, _allowed, runner = make_env(
        tmp_path, mappings={}, automount=True, handler=handler
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.register(str(source))
    assert excinfo.value.code == "ewfmount_failed"
    assert registry.get(make_evidence_id(source.resolve())) is None
    assert not (settings.var_dir / "mounts" / make_evidence_id(source.resolve())).exists()
    assert "fsstat" not in runner.tools_called()


def test_source_mtime_change_after_registration_is_rejected(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    source = make_source(allowed, "disk.E01", b"A" * 100)
    exposure = make_exposure(tmp_path / "ewf1")
    mappings = {
        str(source.resolve()): EwfMapping(exposure=str(exposure.resolve()))
    }
    _settings, service, _provider, _registry, _allowed, _runner = make_env(
        tmp_path, mappings=mappings
    )
    record = service.register(str(source))
    source_stat = source.stat()
    os.utime(
        source,
        ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 1_000_000_000),
    )
    with pytest.raises(EvidenceAccessError) as excinfo:
        service.ensure_image(record)
    assert excinfo.value.code == "source_changed"
