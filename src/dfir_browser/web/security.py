from __future__ import annotations

import hmac
import os
import re
import secrets
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Request

from ..core.config import ConfigurationError
from ..core.errors import DFIRError

SESSION_COOKIE = "dfir_session"
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class CsrfRejected(DFIRError):
    default_code = "csrf_rejected"


@dataclass(frozen=True, slots=True)
class CsrfSession:
    session_id: str
    cookie_value: str
    token: str


def load_or_create_secret(path: Path | str) -> bytes:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        data = path.read_bytes().strip()
        if len(data) < 32:
            raise ConfigurationError(
                f"web secret file is too short or corrupt: {path}"
            )
        return data

    secret = secrets.token_bytes(32)
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        data = path.read_bytes().strip()
        if len(data) < 32:
            raise ConfigurationError(
                f"web secret file is too short or corrupt: {path}"
            )
        return data
    try:
        remaining = secret
        while remaining:
            written = os.write(descriptor, remaining)
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)
    return secret


def _canonical_origin(value: str, error_type: type[DFIRError]) -> str:
    if not isinstance(value, str) or not value.strip():
        raise error_type("empty origin")
    if value.strip().lower() == "null":
        raise error_type("null origin is not allowed")
    parsed = urlsplit(value.strip())
    if not parsed.scheme or not parsed.netloc:
        raise error_type(f"invalid origin: {value!r}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class CSRFProtection:
    """Double-submit CSRF protection bound to a signed session cookie.

    The token is an HMAC over a random session id. Both the cookie and the
    token are signed with a server-side secret stored under ``var/``.
    """

    def __init__(self, secret: bytes, allowed_origins: tuple[str, ...]) -> None:
        if len(secret) < 32:
            raise ConfigurationError("CSRF secret must be at least 32 bytes")
        if not allowed_origins:
            raise ConfigurationError("at least one allowed origin is required")
        self._secret = secret
        self.allowed_origins = frozenset(
            _canonical_origin(origin, ConfigurationError)
            for origin in allowed_origins
        )

    def _sign(self, value: str) -> str:
        return hmac.new(self._secret, value.encode("utf-8"), sha256).hexdigest()

    def _cookie_value(self, session_id: str) -> str:
        return f"{session_id}.{self._sign('session:' + session_id)}"

    def _token_value(self, session_id: str) -> str:
        return f"{session_id}.{self._sign('csrf:' + session_id)}"

    def _verify_cookie(self, value: str | None) -> str | None:
        if not value:
            return None
        session_id, separator, signature = value.rpartition(".")
        if not separator or not _SESSION_ID_RE.fullmatch(session_id):
            return None
        expected = self._sign("session:" + session_id)
        if not hmac.compare_digest(signature, expected):
            return None
        return session_id

    def ensure_session(self, request: Request) -> CsrfSession:
        session_id = self._verify_cookie(request.cookies.get(SESSION_COOKIE))
        if session_id is None:
            session_id = secrets.token_urlsafe(32)
        return CsrfSession(
            session_id=session_id,
            cookie_value=self._cookie_value(session_id),
            token=self._token_value(session_id),
        )

    def _check_origin(self, request: Request) -> None:
        origin = request.headers.get("origin")
        if origin is not None:
            canonical = _canonical_origin(origin, CsrfRejected)
            if canonical not in self.allowed_origins:
                raise CsrfRejected(
                    "request origin is not allowed",
                    details={"origin": canonical},
                )
            return
        referer = request.headers.get("referer")
        if referer is not None:
            canonical = _canonical_origin(referer, CsrfRejected)
            if canonical not in self.allowed_origins:
                raise CsrfRejected(
                    "request referer origin is not allowed",
                    details={"referer_origin": canonical},
                )

    def validate(self, request: Request, token: str | None) -> CsrfSession:
        self._check_origin(request)
        session_id = self._verify_cookie(request.cookies.get(SESSION_COOKIE))
        if session_id is None:
            raise CsrfRejected("missing or invalid session cookie")
        if not token:
            raise CsrfRejected("missing CSRF token")
        token_session, separator, signature = token.rpartition(".")
        if (
            not separator
            or not _SESSION_ID_RE.fullmatch(token_session)
            or not hmac.compare_digest(token_session, session_id)
        ):
            raise CsrfRejected("CSRF token is not bound to this session")
        expected = self._sign("csrf:" + session_id)
        if not hmac.compare_digest(signature, expected):
            raise CsrfRejected("invalid CSRF token")
        return CsrfSession(
            session_id=session_id,
            cookie_value=self._cookie_value(session_id),
            token=self._token_value(session_id),
        )
