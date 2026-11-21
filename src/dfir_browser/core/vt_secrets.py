from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path

from .errors import DFIRError

VT_KEY_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
# A VirusTotal API key is a 64-character hex token, which is also the shape of
# a SHA-256 digest. Redaction therefore takes an optional allow-list of hashes
# that must stay visible in audit/log output.
_HEX64_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
REDACTED = "[REDACTED]"
SECRET_NAME = "virustotal.key"
ENV_VAR = "VT_API_KEY"


class SecretStoreError(DFIRError):
    default_code = "secret_store_error"


class SecretStore:
    """Server-side API key store protected by Unix permissions.

    There is no encryption here: the key is a plain file under a 0700 directory
    with 0600 permissions. README says so explicitly.
    """

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)

    @property
    def path(self) -> Path:
        return self.directory / SECRET_NAME

    def _ensure_directory(self) -> Path:
        directory = self.directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise SecretStoreError(
                "secret directory must not be a symlink",
                code="secret_directory_symlink",
            )
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        try:
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise SecretStoreError(
                f"cannot resolve secret directory: {exc}",
                code="secret_directory_unresolvable",
            ) from exc
        if not resolved.is_dir():
            raise SecretStoreError(
                "secret path is not a directory",
                code="secret_directory_invalid",
            )
        return resolved

    def _validated_target(self) -> Path:
        directory = self._ensure_directory()
        candidate = directory / SECRET_NAME
        if candidate.is_symlink():
            raise SecretStoreError(
                "secret file must not be a symlink",
                code="secret_symlink_rejected",
            )
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(directory):
            raise SecretStoreError(
                "secret file escapes the secret directory",
                code="secret_path_escape",
            )
        return resolved

    def environment_key(self) -> str | None:
        value = os.environ.get(ENV_VAR, "").strip()
        return value or None

    def stored_key(self) -> str | None:
        target = self._validated_target()
        try:
            info = os.lstat(target)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SecretStoreError(
                f"cannot stat secret file: {exc}", code="secret_stat_failed"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise SecretStoreError(
                "secret file must not be a symlink",
                code="secret_symlink_rejected",
            )
        if not stat.S_ISREG(info.st_mode):
            raise SecretStoreError(
                "secret path is not a regular file",
                code="secret_not_regular",
            )
        try:
            value = target.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecretStoreError(
                f"cannot read secret file: {exc}", code="secret_read_failed"
            ) from exc
        return value or None

    def save(self, key: str) -> None:
        key = (key or "").strip()
        if not VT_KEY_RE.fullmatch(key):
            raise SecretStoreError(
                "VirusTotal API key must be 64 hexadecimal characters",
                code="virustotal_key_invalid_format",
            )
        target = self._validated_target()
        descriptor, temporary = tempfile.mkstemp(
            prefix=".virustotal.", dir=str(target.parent)
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(key)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass

    def remove(self) -> bool:
        target = self._validated_target()
        try:
            os.unlink(target)
            return True
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise SecretStoreError(
                f"cannot remove secret file: {exc}", code="secret_remove_failed"
            ) from exc

    def resolve_key(self) -> tuple[str | None, str]:
        """Return (key, source) with source in environment|ui|none."""
        env_key = self.environment_key()
        if env_key:
            return env_key, "environment"
        stored = self.stored_key()
        if stored:
            return stored, "ui"
        return None, "none"

    def status(self) -> dict[str, object]:
        key, source = self.resolve_key()
        return {
            "configured": bool(key),
            "source": source,
            "environment_managed": source == "environment",
            "masked": f"****{key[-4:]}" if key else None,
            "ui_fallback_present": bool(self.stored_key()),
        }


def redact_text(value: str, *, keep: tuple[str, ...] = ()) -> str:
    """Redact 64-hex secrets unless they are explicitly allowed hashes."""

    keep_lower = {item.lower() for item in keep if item}

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.lower() in keep_lower:
            return token
        return REDACTED

    return _HEX64_RE.sub(replace, value)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for name, value in headers.items():
        if str(name).lower() in {"x-apikey", "authorization", "cookie"}:
            cleaned[str(name)] = REDACTED
        else:
            cleaned[str(name)] = redact_text(str(value))
    return cleaned
