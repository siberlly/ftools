from __future__ import annotations

import sys

import pytest

from dfir_browser.core.command import (
    CommandError,
    CommandRunner,
    sanitize_argv,
)


def test_command_capture_and_exit_code() -> None:
    runner = CommandRunner(timeout=5.0, max_output_bytes=1024)
    result = runner.run(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)",
        ]
    )
    assert result.exit_code == 3
    assert result.ok is False
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"
    assert result.duration_ms >= 0


def test_command_timeout_is_bounded() -> None:
    runner = CommandRunner(timeout=5.0)
    result = runner.run(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2
    )
    assert result.timed_out is True
    assert result.exit_code in (None, -9, -15)
    assert result.ok is False
    assert "timed out" in result.stderr


def test_command_output_truncation() -> None:
    runner = CommandRunner(timeout=5.0, max_output_bytes=100)
    result = runner.run([sys.executable, "-c", "print('x' * 5000)"])
    assert result.stdout_truncated is True
    assert len(result.stdout) == 100


def test_command_streams_stdout_to_file(tmp_path) -> None:
    target = tmp_path / "out.bin"
    runner = CommandRunner(timeout=5.0)
    result = runner.run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'abc' * 1000)"],
        stdout_path=target,
    )
    assert result.ok is True
    assert result.stdout == ""
    assert result.output_bytes == 3000
    assert target.read_bytes() == b"abc" * 1000


def test_command_streaming_timeout(tmp_path) -> None:
    target = tmp_path / "partial.bin"
    runner = CommandRunner(timeout=5.0)
    result = runner.run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.2,
        stdout_path=target,
    )
    assert result.timed_out is True
    assert result.ok is False
    assert "timed out" in result.stderr


def test_command_missing_binary() -> None:
    runner = CommandRunner(timeout=5.0)
    result = runner.run(["/definitely/not/a/binary"])
    assert result.exit_code is None
    assert result.ok is False
    assert "failed to execute" in result.stderr


def test_command_check_raises() -> None:
    runner = CommandRunner(timeout=5.0)
    with pytest.raises(CommandError) as excinfo:
        runner.run([sys.executable, "-c", "import sys; sys.exit(9)"], check=True)
    assert excinfo.value.result is not None
    assert excinfo.value.result.exit_code == 9


def test_shell_metacharacters_are_literal() -> None:
    runner = CommandRunner(timeout=5.0)
    argument = "x; echo hacked"
    result = runner.run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", argument]
    )
    assert result.ok is True
    assert result.stdout.strip() == argument


def test_sanitize_argv_redacts_credentials() -> None:
    sanitized = sanitize_argv(
        ["tool", "--password", "hunter2", "password=abc", "x" * 300]
    )
    assert sanitized[2] == "<redacted>"
    assert sanitized[3] == "<redacted>"
    assert sanitized[4].endswith("...")


def test_version_capture() -> None:
    runner = CommandRunner(timeout=5.0)
    version = runner.version(sys.executable)
    assert version is not None
    assert version.startswith("Python")
