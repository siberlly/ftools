from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from dfir_browser.core.vt_secrets import (
    REDACTED,
    SecretStore,
    SecretStoreError,
    redact_headers,
    redact_text,
)

KEY = "b" * 64
OTHER_KEY = "c" * 64
HASH = "d3c3bc26a836ab7d70b8384d13b237cccc45ce883eb74e98429dcaec31b09a0b"


def test_save_read_status_and_permissions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    store = SecretStore(tmp_path / "secrets")
    assert store.status()["configured"] is False
    store.save(KEY)
    assert store.stored_key() == KEY
    status = store.status()
    assert status["configured"] is True
    assert status["source"] == "ui"
    assert status["masked"] == "****" + KEY[-4:]
    assert status["ui_fallback_present"] is True
    directory_mode = stat.S_IMODE(os.stat(tmp_path / "secrets").st_mode)
    file_mode = stat.S_IMODE(os.stat(tmp_path / "secrets" / "virustotal.key").st_mode)
    assert directory_mode == 0o700
    assert file_mode == 0o600
    store.remove()
    assert store.status()["configured"] is False


def test_replace_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    store = SecretStore(tmp_path / "secrets")
    store.save(KEY)
    store.save(OTHER_KEY)
    assert store.stored_key() == OTHER_KEY
    assert store.path.read_text().strip() == OTHER_KEY


def test_invalid_key_format_rejected(tmp_path: Path) -> None:
    store = SecretStore(tmp_path / "secrets")
    for bad in ("", "short", "g" * 64, "a" * 63, "../" + "a" * 64):
        with pytest.raises(SecretStoreError) as excinfo:
            store.save(bad)
        assert excinfo.value.code == "virustotal_key_invalid_format"


def test_environment_precedence(tmp_path: Path, monkeypatch) -> None:
    store = SecretStore(tmp_path / "secrets")
    store.save(KEY)
    monkeypatch.setenv("VT_API_KEY", OTHER_KEY)
    status = store.status()
    assert status["source"] == "environment"
    assert status["environment_managed"] is True
    assert status["ui_fallback_present"] is True
    key, source = store.resolve_key()
    assert key == OTHER_KEY and source == "environment"
    store.remove()
    assert store.status()["configured"] is True
    assert store.status()["source"] == "environment"


def test_secret_file_symlink_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    outside = tmp_path / "outside.key"
    outside.write_text(KEY)
    os.symlink(outside, secrets / "virustotal.key")
    store = SecretStore(secrets)
    from dfir_browser.core.vt_secrets import SecretStoreError as Error

    with pytest.raises(Error) as excinfo:
        store.stored_key()
    assert excinfo.value.code == "secret_symlink_rejected"
    with pytest.raises(Error):
        store.save(OTHER_KEY)


def test_secret_directory_symlink_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "secrets"
    os.symlink(real, link)
    store = SecretStore(link)
    with pytest.raises(SecretStoreError):
        store.save(KEY)


def test_redaction_keeps_allowed_hash() -> None:
    text = f"key={KEY} hash={HASH}"
    redacted = redact_text(text, keep=(HASH,))
    assert KEY not in redacted
    assert HASH in redacted
    assert REDACTED in redacted


def test_redact_headers_hides_apikey() -> None:
    headers = {
        "x-apikey": KEY,
        "authorization": "Bearer secret",
        "accept": "application/json",
    }
    cleaned = redact_headers(headers)
    assert cleaned["x-apikey"] == REDACTED
    assert cleaned["authorization"] == REDACTED
    assert cleaned["accept"] == "application/json"
    assert KEY not in str(cleaned)


def test_exception_message_redaction() -> None:
    from dfir_browser.core.virustotal import VirusTotalError

    error = VirusTotalError(f"upstream echoed {KEY}")
    redacted = redact_text(str(error), keep=(HASH,))
    assert KEY not in redacted
