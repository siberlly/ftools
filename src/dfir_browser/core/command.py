from __future__ import annotations

import logging
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .audit import AuditLogger, get_correlation_id
from .errors import DFIRError


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    stdout: str
    stderr: str
    exit_code: int | None
    duration_ms: float
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_bytes_seen: int | None = None
    stderr_bytes_seen: int | None = None
    output_bytes: int | None = None
    request_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def command_name(self) -> str:
        return Path(self.argv[0]).name if self.argv else ""

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        data = {
            "command": self.command_name,
            "argv": sanitize_argv(self.argv),
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 3),
            "timed_out": self.timed_out,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "bytes_seen": {
                "stdout": self.stdout_bytes_seen,
                "stderr": self.stderr_bytes_seen,
            },
            "output_bytes": self.output_bytes,
            "request_id": self.request_id,
        }
        if include_output:
            data["stdout"] = self.stdout
            data["stderr"] = self.stderr
        if self.extra:
            data["extra"] = self.extra
        return data


class CommandError(DFIRError):
    default_code = "command_error"

    def __init__(
        self,
        message: str,
        result: CommandResult | None = None,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
        self.result = result


_SENSITIVE_WORDS = re.compile(r"password|passwd|secret|token", re.IGNORECASE)


def sanitize_argv(argv: Sequence[str]) -> list[str]:
    """Return an argv safe for logs: no credentials, bounded argument length."""
    sanitized: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            sanitized.append("<redacted>")
            redact_next = False
            continue
        lowered = arg.lower()
        if lowered in {"-p", "--password", "--passwd", "--token"}:
            sanitized.append(arg)
            redact_next = True
        elif _SENSITIVE_WORDS.search(arg):
            sanitized.append("<redacted>")
        elif len(arg) > 200:
            sanitized.append(arg[:197] + "...")
        else:
            sanitized.append(arg)
    return sanitized


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_process_group(
    process: subprocess.Popen,
    logger: logging.Logger | None = None,
    grace_seconds: float = 2.0,
) -> None:
    """Terminate a process and every process in its process group."""
    log = logger or logging.getLogger("dfir_browser.command")
    if os.name != "posix":
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            pass
        return

    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        log.warning("could not SIGTERM process group %s: %s", pgid, exc)

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None and not _group_alive(pgid):
            break
        time.sleep(0.05)

    if _group_alive(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            log.warning("could not SIGKILL process group %s: %s", pgid, exc)

    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        log.warning(
            "process %s did not exit after process-group kill", process.pid
        )


class CommandRunner:
    """Run external tools with list arguments only (``shell=False``).

    stdout/stderr returned to callers are bounded. For large binary output
    (``icat``) use ``stdout_path`` so data is streamed to a file instead of
    being buffered in memory.

    On timeout the whole process group is terminated (SIGTERM then SIGKILL)
    and the direct child is reaped.
    """

    def __init__(
        self,
        timeout: float = 60.0,
        max_output_bytes: int = 256 * 1024,
        logger: logging.Logger | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self.timeout = float(timeout)
        self.max_output_bytes = int(max_output_bytes)
        self._logger = logger or logging.getLogger("dfir_browser.command")
        self.audit_logger = audit_logger
        self._version_cache: dict[str, str | None] = {}

    @staticmethod
    def _validate_argv(argv: Sequence[str]) -> list[str]:
        if not argv:
            raise ValueError("argv must not be empty")
        validated: list[str] = []
        for item in argv:
            if not isinstance(item, str):
                raise TypeError("argv items must be strings")
            if "\x00" in item:
                raise ValueError("argv item contains a NUL byte")
            validated.append(item)
        return validated

    def _decode(
        self, raw: bytes | None, limit: int | None = None
    ) -> tuple[str, bool, int]:
        data = raw or b""
        cap = self.max_output_bytes if limit is None else int(limit)
        total = len(data)
        truncated = total > cap
        text = data[:cap].decode("utf-8", "replace")
        return text, truncated, total

    def _terminate_process_group(
        self, process: subprocess.Popen, grace_seconds: float = 2.0
    ) -> None:
        terminate_process_group(process, self._logger, grace_seconds)

    def _popen_kwargs(
        self,
        cwd: Path | str | None,
        env: dict[str, str],
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "shell": False,
            "cwd": str(cwd) if cwd is not None else None,
            "env": env,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        return kwargs

    def _log(self, result: CommandResult, evidence_id: str | None) -> None:
        self._logger.info(
            "request_id=%s command=%s evidence_id=%s args=%s exit=%s "
            "duration_ms=%.1f timed_out=%s stdout_truncated=%s "
            "stdout_bytes_seen=%s",
            result.request_id,
            result.command_name,
            evidence_id,
            sanitize_argv(result.argv[1:]),
            result.exit_code,
            result.duration_ms,
            result.timed_out,
            result.stdout_truncated,
            result.stdout_bytes_seen,
        )

    def _audit(self, result: CommandResult, evidence_id: str | None) -> None:
        if self.audit_logger is None:
            return
        self.audit_logger.record(
            command=result.command_name,
            argv=sanitize_argv(result.argv),
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            bytes_seen={
                "stdout": result.stdout_bytes_seen,
                "stderr": result.stderr_bytes_seen,
            },
            success=result.ok,
            evidence_id=evidence_id,
            request_id=result.request_id,
        )

    def _run_captured(
        self,
        argv: list[str],
        timeout: float,
        cwd: Path | str | None,
        env: dict[str, str],
        max_output_bytes: int | None = None,
    ) -> CommandResult:
        start = time.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **self._popen_kwargs(cwd, env),
            )
        except OSError as exc:
            return CommandResult(
                argv=list(argv),
                stdout="",
                stderr=f"failed to execute {argv[0]}: {exc}",
                exit_code=None,
                duration_ms=(time.monotonic() - start) * 1000.0,
                stdout_bytes_seen=0,
                stderr_bytes_seen=0,
                output_bytes=0,
            )

        timed_out = False
        try:
            stdout_raw, stderr_raw = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            self._terminate_process_group(process)
            try:
                stdout_raw, stderr_raw = process.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    stdout_raw, stderr_raw = process.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    stdout_raw = exc.stdout or b""
                    stderr_raw = exc.stderr or b""

        duration_ms = (time.monotonic() - start) * 1000.0
        stdout, out_truncated, out_total = self._decode(
            stdout_raw, max_output_bytes
        )
        stderr, err_truncated, err_total = self._decode(
            stderr_raw, max_output_bytes
        )
        if timed_out:
            message = f"command timed out after {timeout:g}s"
            stderr = f"{message}\n{stderr}".strip() if stderr else message
        return CommandResult(
            argv=list(argv),
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            duration_ms=duration_ms,
            timed_out=timed_out,
            stdout_truncated=out_truncated,
            stderr_truncated=err_truncated,
            stdout_bytes_seen=out_total,
            stderr_bytes_seen=err_total,
            output_bytes=out_total,
        )

    def _run_streaming(
        self,
        argv: list[str],
        timeout: float,
        cwd: Path | str | None,
        env: dict[str, str],
        stdout_path: Path,
    ) -> CommandResult:
        start = time.monotonic()
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        timed_out = False
        exit_code: int | None = None
        stderr_text = ""
        err_total = 0
        err_truncated = False

        with open(stdout_path, "wb") as out_file, tempfile.TemporaryFile() as err_file:
            try:
                process = subprocess.Popen(
                    argv,
                    stdout=out_file,
                    stderr=err_file,
                    **self._popen_kwargs(cwd, env),
                )
            except OSError as exc:
                stderr_text = f"failed to execute {argv[0]}: {exc}"
                process = None

            if process is not None:
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._terminate_process_group(process)
                    exit_code = process.returncode
                    stderr_text = f"command timed out after {timeout:g}s"

                err_file.seek(0, os.SEEK_END)
                err_total = err_file.tell()
                err_file.seek(0)
                err_raw = err_file.read(self.max_output_bytes + 1)
                decoded, err_truncated, _ = self._decode(err_raw)
                if decoded:
                    stderr_text = (
                        f"{stderr_text}\n{decoded}".strip()
                        if stderr_text
                        else decoded
                    )

        try:
            output_bytes: int | None = stdout_path.stat().st_size
        except OSError:
            output_bytes = None

        duration_ms = (time.monotonic() - start) * 1000.0
        return CommandResult(
            argv=list(argv),
            stdout="",
            stderr=stderr_text,
            exit_code=exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
            stdout_truncated=False,
            stderr_truncated=err_truncated,
            stdout_bytes_seen=output_bytes,
            stderr_bytes_seen=err_total,
            output_bytes=output_bytes,
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        check: bool = False,
        stdout_path: Path | str | None = None,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
        evidence_id: str | None = None,
        audit: bool = True,
        max_output_bytes: int | None = None,
    ) -> CommandResult:
        validated = self._validate_argv(argv)
        effective_timeout = self.timeout if timeout is None else float(timeout)
        if effective_timeout <= 0:
            raise ValueError("timeout must be positive")

        child_env = dict(os.environ)
        child_env["LC_ALL"] = "C.UTF-8"
        child_env["TZ"] = "UTC"
        if env:
            child_env.update({str(k): str(v) for k, v in env.items()})

        if stdout_path is None:
            result = self._run_captured(
                validated,
                effective_timeout,
                cwd,
                child_env,
                max_output_bytes=max_output_bytes,
            )
        else:
            result = self._run_streaming(
                validated,
                effective_timeout,
                cwd,
                child_env,
                Path(stdout_path),
            )

        result.request_id = get_correlation_id()
        self._log(result, evidence_id)
        if audit:
            self._audit(result, evidence_id)
        if check and not result.ok:
            raise CommandError(
                f"{result.command_name} failed with exit code {result.exit_code}",
                result,
                details={
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "stderr": (result.stderr or "")[:500],
                },
            )
        return result

    def version(self, binary: str) -> str | None:
        """Return the first version line from ``<binary> -V`` (cached)."""
        if binary in self._version_cache:
            return self._version_cache[binary]

        version: str | None = None
        for flag in ("-V", "--version"):
            try:
                result = self.run(
                    [binary, flag],
                    timeout=min(self.timeout, 10.0),
                    check=False,
                    audit=False,
                )
            except (OSError, ValueError):
                continue
            text = (result.stdout or result.stderr or "").strip()
            if result.ok and text:
                version = text.splitlines()[0].strip() or None
                break
        self._version_cache[binary] = version
        return version

    def command_metadata(self, result: CommandResult) -> dict[str, Any]:
        return result.to_dict()
