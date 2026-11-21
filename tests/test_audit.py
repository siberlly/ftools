from __future__ import annotations

import json
import os
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dfir_browser.core.audit import AuditLogger, correlation_scope
from dfir_browser.core.command import CommandRunner


def test_command_audit_fields_and_redaction(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "commands.jsonl"
    audit = AuditLogger(audit_path)
    runner = CommandRunner(timeout=5.0, audit_logger=audit)
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("TOP_SECRET_CONTENT", encoding="utf-8")
    code = "import sys; print(open(sys.argv[1]).read())"

    with correlation_scope("test") as correlation_id:
        result = runner.run(
            [
                sys.executable,
                "-c",
                code,
                str(secret_file),
                "--password",
                "hunter2",
            ],
            evidence_id="ev_0123456789ab",
        )

    assert result.ok is True
    assert result.stdout == "TOP_SECRET_CONTENT\n"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["request_id"] == correlation_id
    assert record["evidence_id"] == "ev_0123456789ab"
    assert record["tool"] == Path(sys.executable).name
    assert record["exit_code"] == 0
    assert record["timeout"] is False
    assert record["truncated"] == {"stdout": False, "stderr": False}
    assert record["bytes_seen"]["stdout"] > 0
    assert record["success"] is True
    assert "<redacted>" in record["argv"]
    serialized = json.dumps(record)
    assert "TOP_SECRET_CONTENT" not in serialized
    assert "hunter2" not in serialized
    assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(audit_path.parent.stat().st_mode) == 0o700


def test_timeout_kills_whole_process_group(tmp_path: Path) -> None:
    runner = CommandRunner(timeout=5.0)
    pid_file = tmp_path / "grandchild.pid"
    grandchild_code = (
        "import signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(30)"
    )
    parent_code = (
        "import subprocess, sys, time; "
        "p = subprocess.Popen([sys.executable, '-c', sys.argv[2]]); "
        "open(sys.argv[1], 'w').write(str(p.pid)); "
        "time.sleep(30)"
    )
    result = runner.run(
        [
            sys.executable,
            "-c",
            parent_code,
            str(pid_file),
            grandchild_code,
        ],
        timeout=1.0,
    )
    assert result.timed_out is True
    assert result.exit_code in (None, -9, -15)
    assert pid_file.is_file()
    grandchild_pid = int(pid_file.read_text(encoding="utf-8"))

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not Path(f"/proc/{grandchild_pid}").exists():
            break
        time.sleep(0.05)
    assert not Path(f"/proc/{grandchild_pid}").exists(), (
        "grandchild process survived process-group termination"
    )


def test_audit_concurrent_writes_are_valid_jsonl(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "commands.jsonl"
    loggers = [AuditLogger(audit_path) for _ in range(4)]

    def worker(index: int) -> None:
        loggers[index % len(loggers)].record(
            command="tool",
            argv=["tool", str(index)],
            exit_code=0,
            duration_ms=1.0,
            timed_out=False,
            stdout_truncated=False,
            stderr_truncated=False,
            bytes_seen={"stdout": 0, "stderr": 0},
            success=True,
            evidence_id=None,
            request_id=f"req-{index}",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(20)))

    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 20
    records = [json.loads(line) for line in lines]
    assert {record["request_id"] for record in records} == {
        f"req-{index}" for index in range(20)
    }
    assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600


def test_command_result_reports_bytes_seen(tmp_path: Path) -> None:
    runner = CommandRunner(timeout=5.0, max_output_bytes=10)
    result = runner.run([sys.executable, "-c", "print('abcdefghijklmnop')"])
    assert result.stdout_truncated is True
    assert result.stdout_bytes_seen == len("abcdefghijklmnop\n")
    assert len(result.stdout) == 10
    metadata = result.to_dict()
    assert metadata["bytes_seen"]["stdout"] == len("abcdefghijklmnop\n")
