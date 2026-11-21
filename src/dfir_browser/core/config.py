from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

from .errors import DFIRError

DEFAULT_ALLOWED_ROOTS = ("/home/ubuntu/test", "/home/ubuntu/evidence")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ConfigurationError(DFIRError):
    default_code = "configuration_error"


@dataclass(frozen=True, slots=True)
class EwfMapping:
    """Explicit, administrator-supplied E01 -> raw exposure mapping."""

    exposure: str
    source_sha256: str | None = None
    media_size: int | None = None


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive, got {value}")
    return value


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive, got {value}")
    return value


def _resolve_absolute(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{label} must be a non-empty string")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path: {value!r}")
    return str(path.resolve(strict=False))


def _normalize_mapping(value: Any, label: str) -> EwfMapping:
    if isinstance(value, EwfMapping):
        source_sha256 = value.source_sha256
        media_size = value.media_size
        exposure = value.exposure
    elif isinstance(value, str):
        return EwfMapping(exposure=_resolve_absolute(value, label))
    elif isinstance(value, Mapping):
        unknown = set(value) - {"exposure", "source_sha256", "media_size"}
        if unknown:
            raise ConfigurationError(
                f"{label} has unsupported keys: {', '.join(sorted(unknown))}"
            )
        if "exposure" not in value:
            raise ConfigurationError(f"{label} requires an 'exposure' path")
        exposure = value["exposure"]
        source_sha256 = value.get("source_sha256")
        media_size = value.get("media_size")
    else:
        raise ConfigurationError(
            f"{label} must be a path string or an object with 'exposure'"
        )

    exposure = _resolve_absolute(str(exposure), f"{label}.exposure")

    if source_sha256 is not None:
        source_sha256 = str(source_sha256).strip().lower()
        if not SHA256_RE.fullmatch(source_sha256):
            raise ConfigurationError(
                f"{label}.source_sha256 must be a 64-character hex SHA-256"
            )

    if media_size is not None:
        try:
            media_size = int(media_size)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"{label}.media_size must be an integer"
            ) from exc
        if media_size <= 0:
            raise ConfigurationError(f"{label}.media_size must be positive")

    return EwfMapping(
        exposure=exposure, source_sha256=source_sha256, media_size=media_size
    )


def _parse_mapping_object(data: Any, origin: str) -> dict[str, EwfMapping]:
    if not isinstance(data, dict):
        raise ConfigurationError(f"{origin}: mapping document must be a JSON object")

    if "mappings" in data:
        version = data.get("version", 1)
        if version != 1:
            raise ConfigurationError(
                f"{origin}: unsupported EWF mapping version {version!r}"
            )
        unknown = set(data) - {"version", "mappings"}
        if unknown:
            raise ConfigurationError(
                f"{origin}: unsupported top-level keys: {', '.join(sorted(unknown))}"
            )
        mappings = data["mappings"]
    else:
        mappings = data

    if not isinstance(mappings, dict):
        raise ConfigurationError(f"{origin}: 'mappings' must be an object")

    normalized: dict[str, EwfMapping] = {}
    for source, value in mappings.items():
        if not isinstance(source, str):
            raise ConfigurationError(f"{origin}: mapping source keys must be strings")
        resolved_source = _resolve_absolute(source, f"{origin} source")
        if resolved_source in normalized:
            raise ConfigurationError(
                f"{origin}: duplicate mapping after path resolution: {resolved_source}"
            )
        normalized[resolved_source] = _normalize_mapping(
            value, f"{origin} mapping for {resolved_source}"
        )
    return normalized


def normalize_mappings(
    mappings: Mapping[str, Any] | None,
) -> dict[str, EwfMapping]:
    if mappings is None:
        return {}
    if not isinstance(mappings, Mapping):
        raise ConfigurationError("ewf_mappings must be a mapping")
    return _parse_mapping_object(dict(mappings), "ewf_mappings")


def _load_mapping_document(path: Path) -> dict[str, EwfMapping]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read EWF mapping file {path}: {exc}"
        ) from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"invalid JSON in EWF mapping file {path}: {exc}"
        ) from exc
    return _parse_mapping_object(data, str(path))


def load_ewf_mappings(
    var_dir: Path,
    mapping_file: Path | None = None,
) -> dict[str, EwfMapping]:
    """Load explicit mappings from file and ``DFIR_EWF_MAPPINGS`` JSON.

    There is intentionally no filesystem scan or media-size based discovery.
    Environment JSON entries override file entries for the same resolved
    source path.
    """
    merged: dict[str, EwfMapping] = {}

    default_file = Path(var_dir) / "ewf_mappings.json"
    selected_file = mapping_file if mapping_file is not None else default_file
    if mapping_file is not None and not selected_file.is_file():
        raise ConfigurationError(
            f"DFIR_EWF_MAPPING_FILE does not exist: {selected_file}"
        )
    if selected_file.is_file():
        merged.update(_load_mapping_document(selected_file))

    env_json = os.environ.get("DFIR_EWF_MAPPINGS")
    if env_json and env_json.strip():
        try:
            data = json.loads(env_json)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"DFIR_EWF_MAPPINGS is not valid JSON: {exc}"
            ) from exc
        merged.update(_parse_mapping_object(data, "DFIR_EWF_MAPPINGS"))

    return merged


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime configuration.

    Evidence paths in user input are validated against ``allowed_roots`` by
    :class:`dfir_browser.core.policy.SecurityPolicy`. EWF exposures are never
    discovered by scanning; only explicit mappings or managed mounts are used.
    """

    var_dir: Path
    allowed_roots: tuple[Path, ...]
    ewf_mappings: dict[str, EwfMapping] = field(default_factory=dict)
    ewf_automount: bool = False
    command_timeout: float = 60.0
    extract_timeout: float = 600.0
    hash_timeout: float = 900.0
    max_output_bytes: int = 256 * 1024
    max_metadata_bytes: int = 64 * 1024
    auto_index: bool = True
    index_db_path: Path | None = None
    index_timeout: float = 1800.0
    index_max_entries: int = 2_000_000
    index_batch_size: int = 1000
    index_max_line_bytes: int = 64 * 1024
    index_max_raw_error_bytes: int = 4 * 1024
    index_page_size_default: int = 100
    index_page_size_max: int = 500
    index_fls_command: tuple[str, ...] = ("fls",)
    index_scanner_version: str = "fls-r-p-l-v1"
    triage_db_path: Path | None = None
    triage_profile_version: str = "static-triage-v1"
    triage_max_file_size: int = 256 * 1024 * 1024
    triage_max_strings: int = 10_000
    triage_max_string_length: int = 4_096
    triage_min_string_length: int = 6
    triage_analyzer_timeout: float = 30.0
    triage_job_timeout: float = 120.0
    triage_yara_timeout: float = 30.0
    triage_max_concurrent_jobs: int = 2
    triage_max_queued_jobs: int = 8
    triage_entropy_chunk_size: int = 4_096
    triage_entropy_max_bytes: int = 16 * 1024 * 1024
    triage_max_findings: int = 2_000
    triage_max_yara_matches: int = 200
    triage_max_tool_output: int = 1024 * 1024
    triage_max_exiftool_items: int = 300
    triage_file_command: tuple[str, ...] = ("file",)
    triage_exiftool_command: tuple[str, ...] = ("exiftool",)
    triage_yara_rules_dir: Path | None = None
    virustotal_db_path: Path | None = None
    virustotal_secret_dir: Path | None = None
    virustotal_cache_ttl: int = 86_400
    virustotal_notfound_ttl: int = 3_600
    virustotal_rate_limit: int = 4
    virustotal_timeout: float = 15.0
    virustotal_max_response_bytes: int = 2_000_000
    registry_db_path: Path | None = None
    registry_parser_version: str = "python-registry-1.3.1-v1"
    registry_max_hive_size: int = 512 * 1024 * 1024
    registry_max_keys: int = 300_000
    registry_max_depth: int = 64
    registry_max_value_bytes: int = 8 * 1024 * 1024
    registry_max_text_length: int = 64 * 1024
    registry_binary_preview_bytes: int = 64
    registry_build_timeout: float = 180.0
    registry_max_amcache_records: int = 100_000
    registry_page_size_default: int = 100
    registry_page_size_max: int = 500
    registry_max_concurrent_jobs: int = 1
    registry_max_queued_jobs: int = 4
    evtx_db_path: Path | None = None
    evtx_parser_version: str = "evtx-0.15.0-v1"
    evtx_max_file_size: int = 2 * 1024 * 1024 * 1024
    evtx_max_records: int = 500_000
    evtx_max_event_xml_bytes: int = 512 * 1024
    evtx_max_field_length: int = 8 * 1024
    evtx_max_query_length: int = 256
    evtx_max_raw_xml_bytes: int = 64 * 1024
    evtx_parser_timeout: float = 300.0
    evtx_index_timeout: float = 300.0
    evtx_max_concurrent_jobs: int = 1
    evtx_max_queued_jobs: int = 4
    evtx_page_size_default: int = 100
    evtx_page_size_max: int = 500
    evtx_context_before: int = 5
    evtx_context_after: int = 5
    evtx_context_max: int = 50
    evtx_batch_size: int = 500
    browser_db_path: Path | None = None
    browser_parser_version: str = "browser-artifacts-v1"
    browser_webcache_engine: str = "dissect.esedb-3.18"
    browser_max_artifact_size: int = 2 * 1024 * 1024 * 1024
    browser_max_records: int = 500_000
    browser_max_url_length: int = 4 * 1024
    browser_max_title_length: int = 2 * 1024
    browser_max_path_length: int = 2 * 1024
    browser_max_metadata_bytes: int = 0
    browser_parser_timeout: float = 300.0
    browser_index_timeout: float = 300.0
    browser_max_concurrent_jobs: int = 1
    browser_max_queued_jobs: int = 4
    browser_page_size_default: int = 100
    browser_page_size_max: int = 500
    browser_max_query_length: int = 256
    browser_batch_size: int = 500
    preview_default_limit: int = 64 * 1024
    preview_max_bytes: int = 1024 * 1024
    preview_text_max_lines: int = 10_000
    preview_binary_sample: int = 8192
    preview_registry_hex_bytes: int = 4096
    preview_verify_hash_bytes: int = 8 * 1024 * 1024
    preview_cache_entries: int = 32
    preview_hex_max_bytes: int = 64 * 1024
    host: str = "127.0.0.1"
    port: int = 8080
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "testserver")
    allowed_origins: tuple[str, ...] = ()
    secret_key_path: Path | None = None
    audit_log_path: Path | None = None
    debug_raw: bool = False

    def secret_key_file(self) -> Path:
        return self.secret_key_path or (self.var_dir / "secret.key")

    def audit_file(self) -> Path:
        return self.audit_log_path or (self.var_dir / "audit" / "commands.jsonl")

    def index_database(self) -> Path:
        return self.index_db_path or (self.var_dir / "index" / "filesystem.db")

    def triage_database(self) -> Path:
        return self.triage_db_path or (self.var_dir / "cases" / "triage.db")

    def browser_database(self) -> Path:
        return self.browser_db_path or (
            self.var_dir / "cases" / "browser_artifacts.db"
        )

    def evtx_database(self) -> Path:
        return self.evtx_db_path or (self.var_dir / "cases" / "evtx.db")

    def registry_database(self) -> Path:
        return self.registry_db_path or (self.var_dir / "cases" / "registry.db")

    def virustotal_database(self) -> Path:
        return self.virustotal_db_path or (
            self.var_dir / "cases" / "virustotal.db"
        )

    def virustotal_secret_directory(self) -> Path:
        return self.virustotal_secret_dir or (self.var_dir / "secrets")

    def triage_rules_directory(self) -> Path:
        if self.triage_yara_rules_dir is not None:
            return self.triage_yara_rules_dir
        project_rules = Path.cwd() / "rules" / "yara"
        if project_rules.is_dir():
            return project_rules
        bundled = Path(__file__).resolve().parent.parent / "rules" / "yara"
        return bundled

    @classmethod
    def from_env(cls, **overrides: Any) -> "Settings":
        var_dir = Path(
            os.environ.get("DFIR_VAR_DIR", str(Path.cwd() / "var"))
        ).expanduser().resolve()

        allowlist_env = os.environ.get("DFIR_EVIDENCE_ALLOWLIST")
        if allowlist_env is not None:
            raw_roots = [item for item in allowlist_env.split(":") if item.strip()]
        else:
            raw_roots = list(DEFAULT_ALLOWED_ROOTS)
        if not raw_roots:
            raise ConfigurationError("DFIR_EVIDENCE_ALLOWLIST contains no roots")
        allowed_roots = tuple(Path(item).expanduser().resolve() for item in raw_roots)

        mapping_file_env = os.environ.get("DFIR_EWF_MAPPING_FILE")
        mapping_file = (
            Path(mapping_file_env).expanduser().resolve()
            if mapping_file_env
            else None
        )
        ewf_mappings = load_ewf_mappings(var_dir, mapping_file)

        port = _int_env("DFIR_PORT", 8080)
        hosts_env = os.environ.get("DFIR_ALLOWED_HOSTS")
        if hosts_env is not None:
            allowed_hosts = tuple(
                item.strip() for item in hosts_env.split(",") if item.strip()
            )
        else:
            allowed_hosts = ("127.0.0.1", "localhost", "testserver")

        origins_env = os.environ.get("DFIR_ALLOWED_ORIGINS")
        if origins_env is not None:
            allowed_origins = tuple(
                item.strip() for item in origins_env.split(",") if item.strip()
            )
        else:
            allowed_origins = (
                f"http://127.0.0.1:{port}",
                f"http://localhost:{port}",
                "http://testserver",
            )

        secret_key_path = Path(
            os.environ.get(
                "DFIR_SECRET_KEY_FILE", str(var_dir / "secret.key")
            )
        ).expanduser().resolve()
        audit_log_path = Path(
            os.environ.get(
                "DFIR_AUDIT_LOG", str(var_dir / "audit" / "commands.jsonl")
            )
        ).expanduser().resolve()
        index_db_path = Path(
            os.environ.get(
                "DFIR_INDEX_DB", str(var_dir / "index" / "filesystem.db")
            )
        ).expanduser().resolve()
        triage_db_path = Path(
            os.environ.get(
                "DFIR_TRIAGE_DB", str(var_dir / "cases" / "triage.db")
            )
        ).expanduser().resolve()
        triage_rules_env = os.environ.get("DFIR_TRIAGE_YARA_RULES")
        triage_rules_dir = (
            Path(triage_rules_env).expanduser().resolve()
            if triage_rules_env
            else None
        )
        virustotal_db_path = Path(
            os.environ.get(
                "DFIR_VIRUSTOTAL_DB", str(var_dir / "cases" / "virustotal.db")
            )
        ).expanduser().resolve()
        virustotal_secret_dir = Path(
            os.environ.get(
                "DFIR_VIRUSTOTAL_SECRET_DIR", str(var_dir / "secrets")
            )
        ).expanduser().resolve()
        registry_db_path = Path(
            os.environ.get(
                "DFIR_REGISTRY_DB", str(var_dir / "cases" / "registry.db")
            )
        ).expanduser().resolve()
        evtx_db_path = Path(
            os.environ.get("DFIR_EVTX_DB", str(var_dir / "cases" / "evtx.db"))
        ).expanduser().resolve()
        browser_db_path = Path(
            os.environ.get(
                "DFIR_BROWSER_DB", str(var_dir / "cases" / "browser_artifacts.db")
            )
        ).expanduser().resolve()
        index_page_size_default = _int_env("DFIR_INDEX_PAGE_SIZE_DEFAULT", 100)
        index_page_size_max = _int_env("DFIR_INDEX_MAX_PAGE_SIZE", 500)
        if index_page_size_default > index_page_size_max:
            raise ConfigurationError(
                "DFIR_INDEX_PAGE_SIZE_DEFAULT must not exceed DFIR_INDEX_MAX_PAGE_SIZE"
            )

        settings = cls(
            var_dir=var_dir,
            allowed_roots=allowed_roots,
            ewf_mappings=ewf_mappings,
            ewf_automount=_bool_env("DFIR_EWF_AUTOMOUNT", False),
            command_timeout=_float_env("DFIR_CMD_TIMEOUT", 60.0),
            extract_timeout=_float_env("DFIR_EXTRACT_TIMEOUT", 600.0),
            hash_timeout=_float_env("DFIR_HASH_TIMEOUT", 900.0),
            max_output_bytes=_int_env("DFIR_MAX_OUTPUT_BYTES", 256 * 1024),
            max_metadata_bytes=_int_env("DFIR_MAX_METADATA_BYTES", 64 * 1024),
            auto_index=_bool_env("DFIR_AUTO_INDEX", True),
            index_db_path=index_db_path,
            index_timeout=_float_env("DFIR_INDEX_TIMEOUT", 1800.0),
            index_max_entries=_int_env("DFIR_INDEX_MAX_ENTRIES", 2_000_000),
            index_batch_size=_int_env("DFIR_INDEX_BATCH_SIZE", 1000),
            index_max_line_bytes=_int_env("DFIR_INDEX_MAX_LINE_BYTES", 64 * 1024),
            index_max_raw_error_bytes=_int_env(
                "DFIR_INDEX_MAX_RAW_ERROR_BYTES", 4 * 1024
            ),
            index_page_size_default=index_page_size_default,
            index_page_size_max=index_page_size_max,
            index_scanner_version=os.environ.get(
                "DFIR_INDEX_SCANNER_VERSION", "fls-r-p-l-v1"
            ),
            triage_db_path=triage_db_path,
            triage_profile_version=os.environ.get(
                "DFIR_TRIAGE_PROFILE", "static-triage-v1"
            ),
            triage_max_file_size=_int_env(
                "DFIR_TRIAGE_MAX_FILE_SIZE", 256 * 1024 * 1024
            ),
            triage_max_strings=_int_env("DFIR_TRIAGE_MAX_STRINGS", 10_000),
            triage_max_string_length=_int_env(
                "DFIR_TRIAGE_MAX_STRING_LENGTH", 4_096
            ),
            triage_min_string_length=_int_env(
                "DFIR_TRIAGE_MIN_STRING_LENGTH", 6
            ),
            triage_analyzer_timeout=_float_env(
                "DFIR_TRIAGE_ANALYZER_TIMEOUT", 30.0
            ),
            triage_job_timeout=_float_env("DFIR_TRIAGE_JOB_TIMEOUT", 120.0),
            triage_yara_timeout=_float_env("DFIR_TRIAGE_YARA_TIMEOUT", 30.0),
            triage_max_concurrent_jobs=_int_env(
                "DFIR_TRIAGE_MAX_CONCURRENT_JOBS", 2
            ),
            triage_max_queued_jobs=_int_env("DFIR_TRIAGE_MAX_QUEUED_JOBS", 8),
            triage_entropy_chunk_size=_int_env(
                "DFIR_TRIAGE_ENTROPY_CHUNK_SIZE", 4_096
            ),
            triage_entropy_max_bytes=_int_env(
                "DFIR_TRIAGE_ENTROPY_MAX_BYTES", 16 * 1024 * 1024
            ),
            triage_max_findings=_int_env("DFIR_TRIAGE_MAX_FINDINGS", 2_000),
            triage_max_yara_matches=_int_env(
                "DFIR_TRIAGE_MAX_YARA_MATCHES", 200
            ),
            triage_max_tool_output=_int_env(
                "DFIR_TRIAGE_MAX_TOOL_OUTPUT", 1024 * 1024
            ),
            triage_max_exiftool_items=_int_env(
                "DFIR_TRIAGE_MAX_EXIFTOOL_ITEMS", 300
            ),
            triage_yara_rules_dir=triage_rules_dir,
            virustotal_db_path=virustotal_db_path,
            virustotal_secret_dir=virustotal_secret_dir,
            virustotal_cache_ttl=_int_env(
                "DFIR_VIRUSTOTAL_CACHE_TTL", 86_400
            ),
            virustotal_notfound_ttl=_int_env(
                "DFIR_VIRUSTOTAL_NOTFOUND_TTL", 3_600
            ),
            virustotal_rate_limit=_int_env("DFIR_VIRUSTOTAL_RATE_LIMIT", 4),
            virustotal_timeout=_float_env("DFIR_VIRUSTOTAL_TIMEOUT", 15.0),
            virustotal_max_response_bytes=_int_env(
                "DFIR_VIRUSTOTAL_MAX_RESPONSE_BYTES", 2_000_000
            ),
            registry_db_path=registry_db_path,
            registry_max_hive_size=_int_env(
                "DFIR_REGISTRY_MAX_HIVE_SIZE", 512 * 1024 * 1024
            ),
            registry_max_keys=_int_env("DFIR_REGISTRY_MAX_KEYS", 300_000),
            registry_max_depth=_int_env("DFIR_REGISTRY_MAX_DEPTH", 64),
            registry_max_value_bytes=_int_env(
                "DFIR_REGISTRY_MAX_VALUE_BYTES", 8 * 1024 * 1024
            ),
            registry_max_text_length=_int_env(
                "DFIR_REGISTRY_MAX_TEXT_LENGTH", 64 * 1024
            ),
            registry_binary_preview_bytes=_int_env(
                "DFIR_REGISTRY_BINARY_PREVIEW_BYTES", 64
            ),
            registry_build_timeout=_float_env(
                "DFIR_REGISTRY_BUILD_TIMEOUT", 180.0
            ),
            registry_max_amcache_records=_int_env(
                "DFIR_REGISTRY_MAX_AMCACHE_RECORDS", 100_000
            ),
            registry_page_size_default=_int_env(
                "DFIR_REGISTRY_PAGE_SIZE_DEFAULT", 100
            ),
            registry_page_size_max=_int_env(
                "DFIR_REGISTRY_PAGE_SIZE_MAX", 500
            ),
            registry_max_concurrent_jobs=_int_env(
                "DFIR_REGISTRY_MAX_CONCURRENT_JOBS", 1
            ),
            registry_max_queued_jobs=_int_env(
                "DFIR_REGISTRY_MAX_QUEUED_JOBS", 4
            ),
            evtx_db_path=evtx_db_path,
            evtx_max_file_size=_int_env(
                "DFIR_EVTX_MAX_FILE_SIZE", 2 * 1024 * 1024 * 1024
            ),
            evtx_max_records=_int_env("DFIR_EVTX_MAX_RECORDS", 500_000),
            evtx_max_event_xml_bytes=_int_env(
                "DFIR_EVTX_MAX_EVENT_XML_BYTES", 512 * 1024
            ),
            evtx_max_field_length=_int_env(
                "DFIR_EVTX_MAX_FIELD_LENGTH", 8 * 1024
            ),
            evtx_max_raw_xml_bytes=_int_env(
                "DFIR_EVTX_MAX_RAW_XML_BYTES", 64 * 1024
            ),
            evtx_parser_timeout=_float_env("DFIR_EVTX_PARSER_TIMEOUT", 300.0),
            evtx_index_timeout=_float_env("DFIR_EVTX_INDEX_TIMEOUT", 300.0),
            evtx_max_concurrent_jobs=_int_env(
                "DFIR_EVTX_MAX_CONCURRENT_JOBS", 1
            ),
            evtx_max_queued_jobs=_int_env("DFIR_EVTX_MAX_QUEUED_JOBS", 4),
            evtx_page_size_default=_int_env("DFIR_EVTX_PAGE_SIZE_DEFAULT", 100),
            evtx_page_size_max=_int_env("DFIR_EVTX_PAGE_SIZE_MAX", 500),
            evtx_context_before=_int_env("DFIR_EVTX_CONTEXT_BEFORE", 5),
            evtx_context_after=_int_env("DFIR_EVTX_CONTEXT_AFTER", 5),
            evtx_context_max=_int_env("DFIR_EVTX_CONTEXT_MAX", 50),
            evtx_batch_size=_int_env("DFIR_EVTX_BATCH_SIZE", 500),
            browser_db_path=browser_db_path,
            browser_max_artifact_size=_int_env(
                "DFIR_BROWSER_MAX_ARTIFACT_SIZE", 2 * 1024 * 1024 * 1024
            ),
            browser_max_records=_int_env("DFIR_BROWSER_MAX_RECORDS", 500_000),
            browser_max_url_length=_int_env(
                "DFIR_BROWSER_MAX_URL_LENGTH", 4 * 1024
            ),
            browser_max_title_length=_int_env(
                "DFIR_BROWSER_MAX_TITLE_LENGTH", 2 * 1024
            ),
            browser_max_path_length=_int_env(
                "DFIR_BROWSER_MAX_PATH_LENGTH", 2 * 1024
            ),
            browser_parser_timeout=_float_env(
                "DFIR_BROWSER_PARSER_TIMEOUT", 300.0
            ),
            browser_index_timeout=_float_env(
                "DFIR_BROWSER_INDEX_TIMEOUT", 300.0
            ),
            browser_max_concurrent_jobs=_int_env(
                "DFIR_BROWSER_MAX_CONCURRENT_JOBS", 1
            ),
            browser_max_queued_jobs=_int_env(
                "DFIR_BROWSER_MAX_QUEUED_JOBS", 4
            ),
            browser_page_size_default=_int_env(
                "DFIR_BROWSER_PAGE_SIZE_DEFAULT", 100
            ),
            browser_page_size_max=_int_env(
                "DFIR_BROWSER_PAGE_SIZE_MAX", 500
            ),
            browser_max_query_length=_int_env(
                "DFIR_BROWSER_MAX_QUERY_LENGTH", 256
            ),
            browser_batch_size=_int_env("DFIR_BROWSER_BATCH_SIZE", 500),
            preview_default_limit=_int_env(
                "DFIR_PREVIEW_DEFAULT_LIMIT", 64 * 1024
            ),
            preview_max_bytes=_int_env(
                "DFIR_PREVIEW_MAX_BYTES", 1024 * 1024
            ),
            preview_text_max_lines=_int_env(
                "DFIR_PREVIEW_TEXT_MAX_LINES", 10_000
            ),
            preview_binary_sample=_int_env(
                "DFIR_PREVIEW_BINARY_SAMPLE", 8192
            ),
            preview_registry_hex_bytes=_int_env(
                "DFIR_PREVIEW_REGISTRY_HEX_BYTES", 4096
            ),
            preview_verify_hash_bytes=_int_env(
                "DFIR_PREVIEW_VERIFY_HASH_BYTES", 8 * 1024 * 1024
            ),
            preview_cache_entries=_int_env("DFIR_PREVIEW_CACHE_ENTRIES", 32),
            preview_hex_max_bytes=_int_env(
                "DFIR_PREVIEW_HEX_MAX_BYTES", 64 * 1024
            ),
            host=os.environ.get("DFIR_HOST", "127.0.0.1"),
            port=port,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            secret_key_path=secret_key_path,
            audit_log_path=audit_log_path,
            debug_raw=_bool_env("DFIR_DEBUG_RAW", False),
        )
        if overrides:
            overrides = dict(overrides)

            if "var_dir" in overrides:
                new_var_dir = Path(overrides["var_dir"]).expanduser().resolve()
                overrides["var_dir"] = new_var_dir
                overrides.setdefault(
                    "secret_key_path", new_var_dir / "secret.key"
                )
                overrides.setdefault(
                    "audit_log_path", new_var_dir / "audit" / "commands.jsonl"
                )
                overrides.setdefault(
                    "index_db_path", new_var_dir / "index" / "filesystem.db"
                )
                overrides.setdefault(
                    "triage_db_path", new_var_dir / "cases" / "triage.db"
                )
                overrides.setdefault(
                    "virustotal_db_path",
                    new_var_dir / "cases" / "virustotal.db",
                )
                overrides.setdefault(
                    "virustotal_secret_dir", new_var_dir / "secrets"
                )
                overrides.setdefault(
                    "registry_db_path", new_var_dir / "cases" / "registry.db"
                )
                overrides.setdefault(
                    "evtx_db_path", new_var_dir / "cases" / "evtx.db"
                )
                overrides.setdefault(
                    "browser_db_path",
                    new_var_dir / "cases" / "browser_artifacts.db",
                )
                if "ewf_mappings" not in overrides:
                    overrides["ewf_mappings"] = load_ewf_mappings(
                        new_var_dir, mapping_file
                    )

            if "allowed_roots" in overrides:
                overrides["allowed_roots"] = tuple(
                    Path(item).expanduser().resolve()
                    for item in overrides["allowed_roots"]
                )

            if "port" in overrides and "allowed_origins" not in overrides:
                new_port = int(overrides["port"])
                overrides["allowed_origins"] = (
                    f"http://127.0.0.1:{new_port}",
                    f"http://localhost:{new_port}",
                    "http://testserver",
                )

            if "ewf_mappings" in overrides:
                overrides["ewf_mappings"] = normalize_mappings(
                    overrides["ewf_mappings"]
                )
            if "allowed_hosts" in overrides:
                overrides["allowed_hosts"] = tuple(overrides["allowed_hosts"])
            if "allowed_origins" in overrides:
                overrides["allowed_origins"] = tuple(overrides["allowed_origins"])
            if "secret_key_path" in overrides:
                overrides["secret_key_path"] = Path(
                    overrides["secret_key_path"]
                ).expanduser().resolve()
            if "audit_log_path" in overrides:
                overrides["audit_log_path"] = Path(
                    overrides["audit_log_path"]
                ).expanduser().resolve()
            if "index_db_path" in overrides:
                overrides["index_db_path"] = Path(
                    overrides["index_db_path"]
                ).expanduser().resolve()
            if "index_fls_command" in overrides:
                overrides["index_fls_command"] = tuple(
                    overrides["index_fls_command"]
                )
            if "triage_db_path" in overrides:
                overrides["triage_db_path"] = Path(
                    overrides["triage_db_path"]
                ).expanduser().resolve()
            if "virustotal_db_path" in overrides:
                overrides["virustotal_db_path"] = Path(
                    overrides["virustotal_db_path"]
                ).expanduser().resolve()
            if "browser_db_path" in overrides:
                overrides["browser_db_path"] = Path(
                    overrides["browser_db_path"]
                ).expanduser().resolve()
            if "evtx_db_path" in overrides:
                overrides["evtx_db_path"] = Path(
                    overrides["evtx_db_path"]
                ).expanduser().resolve()
            if "registry_db_path" in overrides:
                overrides["registry_db_path"] = Path(
                    overrides["registry_db_path"]
                ).expanduser().resolve()
            if "virustotal_secret_dir" in overrides:
                overrides["virustotal_secret_dir"] = Path(
                    overrides["virustotal_secret_dir"]
                ).expanduser().resolve()
            if "triage_yara_rules_dir" in overrides and overrides[
                "triage_yara_rules_dir"
            ] is not None:
                overrides["triage_yara_rules_dir"] = Path(
                    overrides["triage_yara_rules_dir"]
                ).expanduser().resolve()
            if "triage_file_command" in overrides:
                overrides["triage_file_command"] = tuple(
                    overrides["triage_file_command"]
                )
            if "triage_exiftool_command" in overrides:
                overrides["triage_exiftool_command"] = tuple(
                    overrides["triage_exiftool_command"]
                )

            settings = replace(settings, **overrides)

        return settings
