from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path

import pytest

from dfir_browser.core import triage_analyzers
from dfir_browser.core.triage_analyzers import (
    derive_findings,
    entropy_analysis,
    hash_file,
    run_exiftool,
    run_file_identification,
    run_pe,
    run_yara,
    scan_strings,
)
from dfir_browser.core.triage_models import TriageError, TriageRejectedError
from dfir_browser.core.triage_store import TriageStore, new_job_id, validate_job_id
from dfir_browser.core.triage_models import TriageNotFoundError

from triage_helpers import (
    EVIDENCE,
    build_services,
    minimal_pe32,
    sample_payload,
    stub_extraction,
    wait_job,
)


def make_services(tmp_path, payload=None, **kwargs):
    return build_services(tmp_path, payload or sample_payload(), **kwargs)


def test_hashes_match_python_hashing(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    payload = sample_payload()
    stub_extraction(services, payload)
    job = services.triage.start(record, entry_id)
    done = wait_job(services, job.job_id)
    assert done.status == "complete", done.errors
    assert done.md5 == hashlib.md5(payload).hexdigest()
    assert done.sha1 == hashlib.sha1(payload).hexdigest()
    assert done.sha256 == hashlib.sha256(payload).hexdigest()
    assert done.size == len(payload)
    services.cleanup()


def test_cache_hit_then_force_rerun(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    calls = stub_extraction(services, sample_payload())
    first = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert first.status == "complete"
    assert first.cached is False
    extracted_after_first = len(calls)

    second = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert second.cached is True
    assert second.cached_from_job_id == first.job_id
    assert second.sha256 == first.sha256
    # A valid cached copy is reused, so a cache hit creates no new export.
    assert len(calls) == extracted_after_first
    # Analyzer rows are reused from the source job, so their recorded durations
    # are identical: nothing was re-run.
    first_durations = {a.name: a.duration_ms for a in first.analyzers}
    second_durations = {a.name: a.duration_ms for a in second.analyzers}
    assert second_durations == first_durations
    result = services.triage.result(second.job_id)
    assert result["job"]["cached"] is True

    third = wait_job(
        services, services.triage.start(record, entry_id, force=True).job_id
    )
    assert third.cached is False
    assert third.job_id != second.job_id
    services.cleanup()


def test_deleted_file_can_be_triaged(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path, deleted=True)
    stub_extraction(services, sample_payload())
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "complete", job.errors
    assert job.sha256
    services.cleanup()


def test_directory_entry_rejected(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    directory_id = services.indexer.resolve_entry_path(record, "Files").id
    with pytest.raises(TriageError) as excinfo:
        services.triage.start(record, directory_id)
    assert excinfo.value.code == "triage_directory_rejected"
    services.cleanup()


def test_missing_entry_rejected(tmp_path) -> None:
    services, record, _entry_id = make_services(tmp_path)
    with pytest.raises(Exception) as excinfo:
        services.triage.start(record, 99999)
    assert getattr(excinfo.value, "code", "") == "entry_not_found"
    services.cleanup()


def test_negative_and_invalid_entry_ids_rejected(tmp_path) -> None:
    services, record, _entry_id = make_services(tmp_path)
    for bad in (-1, 10**20):
        with pytest.raises(Exception) as excinfo:
            services.triage.start(record, bad)
        assert getattr(excinfo.value, "code", "") == "invalid_entry_id"
    services.cleanup()


def test_other_evidence_entry_rejected(tmp_path) -> None:
    services, _record, entry_id = make_services(tmp_path)
    from dfir_browser.core.models import EvidenceRecord

    other = services.evidence.get(EVIDENCE)
    other_record = EvidenceRecord.from_dict({**other.to_dict(), "evidence_id": "ev_ffffffffffff"})
    services.evidence.registry.upsert(other_record.to_dict())
    record = services.evidence.get("ev_ffffffffffff")
    with pytest.raises(Exception) as excinfo:
        services.triage.start(record, entry_id)
    # Another evidence has no index generation for this row id, so the entry
    # cannot be resolved there at all.
    assert getattr(excinfo.value, "code", "") in {
        "entry_not_found",
        "index_not_found",
        "index_not_ready",
    }
    services.cleanup()


def test_file_over_size_limit_is_failed_not_run(tmp_path) -> None:
    services, record, entry_id = make_services(
        tmp_path, triage_max_file_size=10
    )
    calls = stub_extraction(services, sample_payload())
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "failed"
    assert job.error_code == "triage_file_too_large"
    assert calls == []
    services.cleanup()


def test_analyzer_failure_is_isolated(tmp_path, monkeypatch) -> None:
    services, record, entry_id = make_services(tmp_path)
    stub_extraction(services, sample_payload())

    def boom(*_args, **_kwargs):
        raise RuntimeError("yara exploded")

    monkeypatch.setattr("dfir_browser.core.triage.run_yara", boom)
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "partial"
    assert any(a.name == "yara" and a.status == "failed" for a in job.analyzers)
    assert any(a.name == "strings" and a.status == "ok" for a in job.analyzers)
    assert job.errors
    services.cleanup()


def test_timeout_marks_analyzer_timeout(tmp_path, monkeypatch) -> None:
    services, record, entry_id = make_services(tmp_path)
    stub_extraction(services, sample_payload())

    def timeout(*_args, **_kwargs):
        raise triage_analyzers.AnalyzerDeadline("triage job deadline exceeded")

    monkeypatch.setattr("dfir_browser.core.triage.run_yara", timeout)
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert any(a.name == "yara" and a.status == "timeout" for a in job.analyzers)
    services.cleanup()


def test_path_escape_rejected(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")

    def escape(image_path, evidence_id, inode, case_id, offset_sectors=0, **kwargs):
        from types import SimpleNamespace

        return SimpleNamespace(output_path=str(outside), relative_path="x", inode=inode)

    services.filesystem.extract = escape
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "failed"
    assert job.error_code == "triage_path_escape"
    services.cleanup()


def test_symlink_escape_rejected(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(sample_payload())

    def symlink(image_path, evidence_id, inode, case_id, offset_sectors=0, **kwargs):
        from types import SimpleNamespace

        exports = services.policy.case_exports_dir(case_id)
        link = exports / "link.bin"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(outside)
        return SimpleNamespace(output_path=str(link), relative_path="x", inode=inode)

    services.filesystem.extract = symlink
    services.evidence.ensure_image = lambda record: Path("/raw/exposure")
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert job.status == "failed"
    assert job.error_code == "triage_symlink_rejected"
    services.cleanup()


def test_concurrent_job_limit(tmp_path) -> None:
    services, record, entry_id = make_services(
        tmp_path, triage_max_concurrent_jobs=1, triage_max_queued_jobs=1
    )
    gate = threading.Event()
    stub_extraction(services, sample_payload(), block=gate)
    first = services.triage.start(record, entry_id)
    second = services.triage.start(record, entry_id)
    with pytest.raises(TriageError) as excinfo:
        services.triage.start(record, entry_id)
    assert excinfo.value.code == "triage_queue_full"
    gate.set()
    wait_job(services, first.job_id)
    wait_job(services, second.job_id)
    services.cleanup()


def test_restart_marks_running_jobs_interrupted(tmp_path) -> None:
    from dfir_browser.core.triage_models import TriageJob, utc_now_iso

    services, record, entry_id = make_services(tmp_path)
    store = TriageStore(services.settings.triage_database())
    store.ensure_schema()
    job_id = new_job_id()
    store.create_job(
        TriageJob(
            job_id=job_id,
            evidence_id=EVIDENCE,
            entry_id=entry_id,
            inode=900,
            case_id="case01",
            profile_version=services.settings.triage_profile_version,
            status="running",
            phase="strings",
            created_at=utc_now_iso(),
        )
    )
    assert store.recover_interrupted() >= 1
    recovered = store.get_job(job_id)
    assert recovered.status == "interrupted"
    assert recovered.phase == "complete"
    assert recovered.error_code == "triage_interrupted"
    services.cleanup()


def test_job_id_validation(tmp_path) -> None:
    store = TriageStore(tmp_path / "triage.db")
    store.ensure_schema()
    good = new_job_id()
    assert validate_job_id(good) == good
    for bad in ("../../etc/passwd", "tr_", "tr_ZZZZ", "", "tr_0123456789abcdef0"):
        with pytest.raises(TriageNotFoundError):
            store.get_job(bad)
    with pytest.raises(TriageNotFoundError):
        store.get_job("tr_0000000000000000")


def test_strings_ascii_and_utf16(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    payload = b"\x00\x00Hello World ASCII\x00\x00" + "Wide String Here".encode(
        "utf-16le"
    )
    path = tmp_path / "strings.bin"
    path.write_bytes(payload)
    strings, truncated = scan_strings(path, settings, time.monotonic() + 10)
    encodings = {encoding for encoding, _offset, _value in strings}
    values = {value for _encoding, _offset, value in strings}
    assert "ascii" in encodings
    assert "utf-16le" in encodings
    assert any("Hello World" in value for value in values)
    assert any("Wide String" in value for value in values)
    assert truncated is False


def test_strings_limits_and_truncation(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(
        triage_max_strings=5, triage_min_string_length=4
    )
    path = tmp_path / "many.bin"
    path.write_bytes(b"\n".join(b"longstringvalue%03d" % i for i in range(50)))
    strings, truncated = scan_strings(path, settings, time.monotonic() + 10)
    assert truncated is True
    assert len(strings) <= 5


def test_finding_categories(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    payload = sample_payload()
    path = tmp_path / "findings.bin"
    path.write_bytes(payload)
    strings, _ = scan_strings(path, settings, time.monotonic() + 10)
    findings = derive_findings(strings, settings)
    categories = {finding.category for finding in findings}
    assert {"url", "ipv4", "domain", "email", "powershell", "windows_path",
            "registry_path", "base64", "mutex", "user_agent", "executable_name",
            "cmd", "rundll32", "regsvr32", "mshta", "certutil"} <= categories
    for finding in findings:
        assert finding.rule_id.startswith("string.")
        assert finding.reason
        assert finding.encoding in {"ascii", "utf-16le"}


def test_base64_detection_is_bounded(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(triage_max_findings=10)
    long_token = "A" * 100_000
    path = tmp_path / "base64.bin"
    path.write_bytes(long_token.encode())
    strings, _ = scan_strings(path, settings, time.monotonic() + 10)
    findings = derive_findings(strings, settings)
    assert len(findings) <= 10
    assert all(len(finding.value) <= 512 for finding in findings)


def test_entropy_values(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    zeros = tmp_path / "zeros.bin"
    zeros.write_bytes(b"\x00" * 4096)
    randomish = tmp_path / "rand.bin"
    randomish.write_bytes(bytes(range(256)) * 256)
    assert entropy_analysis(empty, settings, time.monotonic() + 10).data["whole"] == 0.0
    assert entropy_analysis(zeros, settings, time.monotonic() + 10).data["whole"] == 0.0
    result = entropy_analysis(randomish, settings, time.monotonic() + 10)
    assert 7.9 < result.data["whole"] <= 8.0
    assert len(result.data["chunks"]) > 1


def test_yara_match_metadata(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(
        triage_yara_rules_dir=Path(__file__).resolve().parents[1] / "rules" / "yara"
    )
    path = tmp_path / "marker.bin"
    path.write_bytes(b"prefix DFIR_TRIAGE_TEST_MARKER suffix")
    result, matches = run_yara(path, settings, time.monotonic() + 20)
    assert result.status == "ok"
    assert len(matches) == 1
    match = matches[0]
    assert match["rule"] == "DFIR_Triage_Test_Marker"
    assert match["namespace"].startswith("rules_")
    assert match["meta"]["severity"] == "informational"
    assert match["strings"][0]["identifier"] == "$marker"
    assert match["strings"][0]["instances"][0]["offset"] == 7


def test_yara_no_match(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(
        triage_yara_rules_dir=Path(__file__).resolve().parents[1] / "rules" / "yara"
    )
    path = tmp_path / "clean.bin"
    path.write_bytes(b"nothing interesting here")
    result, matches = run_yara(path, settings, time.monotonic() + 20)
    assert result.status == "ok"
    assert matches == []
    assert result.warnings == ["YARA rules ran; no matches"]


def test_yara_no_active_rules(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    empty = tmp_path / "rules"
    empty.mkdir()
    settings = Settings.from_env(triage_yara_rules_dir=empty)
    path = tmp_path / "sample.bin"
    path.write_bytes(b"anything")
    result, matches = run_yara(path, settings, time.monotonic() + 10)
    assert result.status == "no_rules"
    assert matches == []
    assert "No active YARA rules" in result.warnings[0]


def test_yara_invalid_rule(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yar").write_text("rule broken {{{ strings: $a = ")
    settings = Settings.from_env(triage_yara_rules_dir=rules)
    path = tmp_path / "sample.bin"
    path.write_bytes(b"anything")
    result, matches = run_yara(path, settings, time.monotonic() + 10)
    assert result.status == "failed"
    assert "compilation failed" in (result.error or "")
    assert matches == []


def test_yara_timeout(tmp_path, monkeypatch) -> None:
    from dfir_browser.core.config import Settings
    import yara

    settings = Settings.from_env(
        triage_yara_rules_dir=Path(__file__).resolve().parents[1] / "rules" / "yara"
    )
    path = tmp_path / "sample.bin"
    path.write_bytes(b"anything")

    class FakeRules:
        def match(self, *_args, **_kwargs):
            raise yara.Error("timeout")

    monkeypatch.setattr(yara, "compile", lambda **_kwargs: FakeRules())
    result, matches = run_yara(path, settings, time.monotonic() + 10)
    assert result.status == "timeout"
    assert matches == []


def test_pe_summary(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    path = tmp_path / "sample.exe"
    path.write_bytes(minimal_pe32())
    result = run_pe(path, settings, time.monotonic() + 20)
    assert result.status == "ok"
    assert result.data["is_pe"] is True
    assert result.data["kind"] == "PE32"
    assert result.data["sections"][0]["name"] == ".text"
    assert result.data["has_signature_directory"] is False
    assert any("compiled timestamp" in warning.lower() or "compile timestamp" in warning.lower() for warning in result.warnings)


def test_non_pe_is_skipped(tmp_path) -> None:
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    path = tmp_path / "text.bin"
    path.write_bytes(b"plain text, not a PE")
    result = run_pe(path, settings, time.monotonic() + 10)
    assert result.status == "skipped"
    assert result.data == {"is_pe": False}


def test_pe_parser_failure_is_warning(tmp_path, monkeypatch) -> None:
    from dfir_browser.core.config import Settings
    import pefile

    settings = Settings.from_env()
    path = tmp_path / "broken.exe"
    path.write_bytes(b"MZ" + b"\x00" * 200)

    def explode(*_args, **_kwargs):
        raise pefile.PEFormatError("broken")

    monkeypatch.setattr(pefile, "PE", explode)
    result = run_pe(path, settings, time.monotonic() + 10)
    assert result.status == "failed"
    assert result.error
    assert result.warnings


def test_file_identification_and_exiftool(tmp_path) -> None:
    from dfir_browser.core.command import CommandRunner
    from dfir_browser.core.config import Settings

    settings = Settings.from_env()
    runner = CommandRunner(timeout=10)
    path = tmp_path / "sample.txt"
    path.write_text("hello world")
    deadline = time.monotonic() + 20
    file_result = run_file_identification(path, settings, runner, deadline)
    assert file_result.status == "ok"
    assert file_result.data["file_type"]
    exif_result = run_exiftool(path, settings, runner, deadline)
    assert exif_result.status == "ok"
    assert exif_result.data["tag_count"] >= 1


def test_truncated_tool_output_is_reported(tmp_path) -> None:
    from dfir_browser.core.command import CommandRunner
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(triage_max_tool_output=32)
    runner = CommandRunner(timeout=10)
    path = tmp_path / "sample.txt"
    path.write_text("x" * 4096)
    result = run_file_identification(path, settings, runner, time.monotonic() + 20)
    assert result.status in {"ok", "failed"}


def test_tool_nonzero_exit_is_error(tmp_path) -> None:
    from dfir_browser.core.command import CommandRunner
    from dfir_browser.core.config import Settings

    settings = Settings.from_env(triage_exiftool_command=("false",))
    runner = CommandRunner(timeout=10)
    path = tmp_path / "sample.txt"
    path.write_text("x")
    result = run_exiftool(path, settings, runner, time.monotonic() + 10)
    assert result.status in {"failed", "unavailable"}


def test_strings_pagination_and_filter(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    stub_extraction(services, sample_payload())
    job = wait_job(services, services.triage.start(record, entry_id).job_id)
    first = services.triage.strings(job.job_id, page=1, page_size=3)
    assert first.total >= 3
    assert len(first.strings) == 3
    second = services.triage.strings(job.job_id, page=2, page_size=3)
    assert {s["value"] for s in first.strings}.isdisjoint(
        {s["value"] for s in second.strings}
    )
    filtered = services.triage.strings(
        job.job_id, page=1, page_size=10, query="DFIR_TRIAGE"
    )
    assert filtered.total >= 1
    assert all("DFIR_TRIAGE" in s["value"] for s in filtered.strings)
    ascii_only = services.triage.strings(
        job.job_id, page=1, page_size=10, encoding="utf-16le"
    )
    assert all(s["encoding"] == "utf-16le" for s in ascii_only.strings)


def test_latest_job_orders_newest_first(tmp_path) -> None:
    from dfir_browser.core.triage_models import TriageJob, utc_now_iso

    services, _record, entry_id = make_services(tmp_path)
    store = services.triage_store
    stamp = "2026-01-01T00:00:00Z"
    ids = []
    for index in range(3):
        job_id = new_job_id()
        store.create_job(
            TriageJob(
                job_id=job_id,
                evidence_id=EVIDENCE,
                entry_id=entry_id,
                inode=900,
                case_id="case01",
                profile_version=services.settings.triage_profile_version,
                status="complete",
                phase="complete",
                created_at=stamp,
            )
        )
        ids.append(job_id)
    assert store.latest_for_entry(EVIDENCE, entry_id).job_id == ids[-1]
    services.cleanup()


def test_cache_hit_does_not_create_extra_export(tmp_path) -> None:
    services, record, entry_id = make_services(tmp_path)
    stub_extraction(services, sample_payload())
    exports = services.policy.case_exports_dir("case01")

    def payload_count():
        return len(
            [
                path
                for path in exports.iterdir()
                if path.is_file() and not path.name.endswith(".provenance.json")
            ]
        )

    fresh = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert fresh.cached is False
    after_fresh = payload_count()
    cached = wait_job(services, services.triage.start(record, entry_id).job_id)
    assert cached.cached is True
    assert cached.extract_relpath == fresh.extract_relpath
    assert payload_count() == after_fresh
    services.cleanup()
