from __future__ import annotations

import contextlib
import contextvars
import fcntl
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("dfir_browser.audit")

_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "dfir_correlation_id", default=None
)


def new_correlation_id(prefix: str = "req") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


@contextlib.contextmanager
def correlation_scope(prefix: str = "req") -> Iterator[str]:
    token = _correlation_id.set(new_correlation_id(prefix))
    try:
        yield _correlation_id.get() or ""
    finally:
        _correlation_id.reset(token)


def get_correlation_id() -> str:
    current = _correlation_id.get()
    if current is None:
        current = new_correlation_id("cmd")
        _correlation_id.set(current)
    return current


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class AuditLogger:
    """Append-only JSONL command audit log safe for concurrent writers.

    Only command metadata is written. stdout/stderr content, file data,
    passwords, CSRF tokens and session secrets are never included.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._thread_lock = threading.Lock()

    def record(
        self,
        *,
        command: str,
        argv: list[str],
        exit_code: int | None,
        duration_ms: float,
        timed_out: bool,
        stdout_truncated: bool,
        stderr_truncated: bool,
        bytes_seen: dict[str, int | None],
        success: bool,
        evidence_id: str | None,
        request_id: str | None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": _utc_timestamp(),
            "request_id": request_id or get_correlation_id(),
            "evidence_id": evidence_id,
            "tool": command,
            "argv": argv,
            "exit_code": exit_code,
            "duration_ms": round(float(duration_ms), 3),
            "timeout": bool(timed_out),
            "truncated": {
                "stdout": bool(stdout_truncated),
                "stderr": bool(stderr_truncated),
            },
            "bytes_seen": bytes_seen,
            "success": bool(success),
        }
        if extra:
            record["extra"] = extra
        self._append(record)

    def event(
        self,
        event: str,
        *,
        evidence_id: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._append(
            {
                "timestamp": _utc_timestamp(),
                "request_id": request_id or get_correlation_id(),
                "evidence_id": evidence_id,
                "event": event,
                "details": details or {},
            }
        )

    def _append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
        try:
            with self._thread_lock:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor = os.open(
                    self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600
                )
                try:
                    os.chmod(self.path, 0o600)
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                    remaining = line.encode("utf-8")
                    while remaining:
                        written = os.write(descriptor, remaining)
                        remaining = remaining[written:]
                finally:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)
        except OSError as exc:
            # Auditing must not break the forensic operation, but the failure
            # is surfaced to the service log.
            logger.warning("could not append audit record to %s: %s", self.path, exc)
