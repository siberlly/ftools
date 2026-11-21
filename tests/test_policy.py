from __future__ import annotations

from pathlib import Path

import pytest

from dfir_browser.core.policy import PolicyError, SecurityPolicy


@pytest.fixture()
def policy_env(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    policy = SecurityPolicy([allowed], tmp_path / "var")
    return policy, allowed, outside


def test_valid_evidence_path_is_canonicalised(policy_env) -> None:
    policy, allowed, _ = policy_env
    evidence = allowed / "disk.E01"
    evidence.write_bytes(b"not really an image")
    resolved = policy.validate_evidence_path(str(evidence))
    assert resolved == evidence.resolve()
    assert resolved.is_absolute()


def test_all_supported_extensions(policy_env) -> None:
    policy, allowed, _ = policy_env
    for name in ("a.E01", "b.e01", "c.raw", "d.img"):
        path = allowed / name
        path.write_bytes(b"x")
        assert policy.validate_evidence_path(str(path)) == path.resolve()


def test_unsupported_extension_rejected(policy_env) -> None:
    policy, allowed, _ = policy_env
    path = allowed / "notes.txt"
    path.write_text("x")
    with pytest.raises(PolicyError, match="unsupported"):
        policy.validate_evidence_path(str(path))


def test_relative_path_rejected(policy_env) -> None:
    policy, _, _ = policy_env
    with pytest.raises(PolicyError, match="absolute"):
        policy.validate_evidence_path("disk.E01")


def test_missing_path_rejected(policy_env) -> None:
    policy, allowed, _ = policy_env
    with pytest.raises(PolicyError, match="does not exist"):
        policy.validate_evidence_path(str(allowed / "missing.E01"))


def test_directory_is_not_evidence(policy_env) -> None:
    policy, allowed, _ = policy_env
    directory = allowed / "folder.E01"
    directory.mkdir()
    with pytest.raises(PolicyError, match="regular file"):
        policy.validate_evidence_path(str(directory))


def test_outside_allowlist_rejected(policy_env) -> None:
    policy, _, outside = policy_env
    path = outside / "disk.raw"
    path.write_bytes(b"x")
    with pytest.raises(PolicyError, match="outside the allowed roots"):
        policy.validate_evidence_path(str(path))


def test_dotdot_traversal_rejected(policy_env) -> None:
    policy, allowed, outside = policy_env
    path = outside / "disk.raw"
    path.write_bytes(b"x")
    traversal = allowed / ".." / "outside" / "disk.raw"
    with pytest.raises(PolicyError, match="outside the allowed roots"):
        policy.validate_evidence_path(str(traversal))


def test_symlink_escape_rejected(policy_env) -> None:
    policy, allowed, outside = policy_env
    target = outside / "real.E01"
    target.write_bytes(b"x")
    link = allowed / "link.E01"
    link.symlink_to(target)
    with pytest.raises(PolicyError, match="outside the allowed roots"):
        policy.validate_evidence_path(str(link))


def test_nul_byte_rejected(policy_env) -> None:
    policy, allowed, _ = policy_env
    with pytest.raises(PolicyError, match="NUL"):
        policy.validate_evidence_path(str(allowed / "x\x00.E01"))


def test_case_id_validation(policy_env) -> None:
    policy, _, _ = policy_env
    for valid in ("case01", "CASE_1", "a-b_c", "A" * 64):
        assert policy.validate_case_id(valid) == valid
    for invalid in ("", ".", "..", "../evil", "a/b", "a\\b", "a b", "a" * 65, "é"):
        with pytest.raises(PolicyError):
            policy.validate_case_id(invalid)


def test_case_exports_directory_created_under_var(policy_env, tmp_path: Path) -> None:
    policy, _, _ = policy_env
    exports = policy.case_exports_dir("case-01")
    assert exports.is_dir()
    assert exports == (tmp_path / "var" / "cases" / "case-01" / "exports").resolve()


def test_case_exports_rejects_symlinked_case_dir(policy_env, tmp_path: Path) -> None:
    policy, _, outside = policy_env
    cases = tmp_path / "var" / "cases"
    cases.mkdir(parents=True)
    (cases / "evil").symlink_to(outside)
    with pytest.raises(PolicyError, match="symlink"):
        policy.case_exports_dir("evil")


def test_inode_validation() -> None:
    for valid, expected in (("0", 0), ("5", 5), ("1746", 1746), (83437, 83437)):
        assert SecurityPolicy.validate_inode(valid) == expected
    for invalid in (
        "",
        "-1",
        "+5",
        " 5",
        "5 ",
        "5-128-1",
        "1e3",
        "5; rm -rf /",
        "../../etc/passwd",
        1 << 48,
        -1,
        True,
        1.5,
        None,
    ):
        with pytest.raises(PolicyError):
            SecurityPolicy.validate_inode(invalid)


def test_export_filename_is_server_generated(policy_env) -> None:
    policy, _, _ = policy_env
    name = policy.build_export_filename(60734, "../../etc/passwd")
    assert name.startswith("inode_60734_")
    assert "/" not in name and "\\" not in name
    assert ".." not in name
    assert Path(name).name == name


def test_export_filename_handles_spaces_and_unicode(policy_env) -> None:
    policy, _, _ = policy_env
    name = policy.build_export_filename(1, "My Report – final.docx")
    assert name.endswith(".docx")
    assert " " not in name
    assert len(name) <= 120
    empty = policy.build_export_filename(2, "")
    assert empty.endswith("file.bin")
