from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from .audit import AuditLogger
from .command import CommandRunner
from .config import Settings
from .evidence import EvidenceService, ImageProvider, Registry
from .filesystem import FilesystemService
from .index_store import IndexStore
from .indexer import FilesystemIndexer
from .policy import SecurityPolicy
from .triage import FileTriageService
from .triage_store import TriageStore
from .virustotal import VirusTotalService, VirusTotalStore
from .vt_secrets import SecretStore
from .registry.index import RegistryStore
from .registry.service import RegistryService
from .evtx.index import EvtxStore
from .evtx.service import EvtxService
from .browser_artifacts.index import BrowserStore
from .browser_artifacts.service import BrowserArtifactService
from .preview import FilePreviewService


@dataclass(slots=True)
class Services:
    settings: Settings
    policy: SecurityPolicy
    runner: CommandRunner
    registry: Registry
    filesystem: FilesystemService
    provider: ImageProvider
    evidence: EvidenceService
    audit: AuditLogger
    index_store: IndexStore
    indexer: FilesystemIndexer
    triage_store: TriageStore
    triage: FileTriageService
    virustotal_store: VirusTotalStore
    virustotal: VirusTotalService
    registry_store: RegistryStore
    registry_browser: RegistryService
    evtx_store: EvtxStore
    evtx: EvtxService
    browser_store: BrowserStore
    browser_artifacts: BrowserArtifactService
    preview: FilePreviewService

    def cleanup(self) -> None:
        self.preview.cleanup()
        self.evtx.cleanup()
        self.browser_artifacts.cleanup()
        self.registry_browser.cleanup()
        self.triage.cleanup()
        self.indexer.cancel_all()
        self.provider.cleanup_managed()


def build_services(settings: Settings | None = None) -> Services:
    settings = settings or Settings.from_env()
    for directory in (
        settings.var_dir,
        settings.var_dir / "cases",
        settings.var_dir / "mounts",
        settings.var_dir / "audit",
        settings.var_dir / "index",
        settings.var_dir / "index" / "locks",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass

    policy = SecurityPolicy(
        allowed_roots=settings.allowed_roots, var_dir=settings.var_dir
    )
    audit = AuditLogger(settings.audit_file())
    runner = CommandRunner(
        timeout=settings.command_timeout,
        max_output_bytes=settings.max_output_bytes,
        audit_logger=audit,
    )
    registry = Registry(settings.var_dir / "registry.json")
    filesystem = FilesystemService(policy, runner, settings)
    provider = ImageProvider(
        mappings=settings.ewf_mappings,
        automount=settings.ewf_automount,
        runner=runner,
        mounts_dir=settings.var_dir / "mounts",
    )
    evidence = EvidenceService(
        policy=policy,
        runner=runner,
        registry=registry,
        provider=provider,
        filesystem=filesystem,
        settings=settings,
    )
    filesystem.evidence = evidence
    index_store = IndexStore(settings.index_database())
    index_store.ensure_schema()
    indexer = FilesystemIndexer(
        settings=settings,
        store=index_store,
        evidence=evidence,
        runner=runner,
        audit=audit,
    )
    triage_store = TriageStore(settings.triage_database())
    triage_store.ensure_schema()
    triage = FileTriageService(
        settings=settings,
        policy=policy,
        filesystem=filesystem,
        evidence=evidence,
        indexer=indexer,
        audit=audit,
        store=triage_store,
    )
    virustotal_store = VirusTotalStore(settings.virustotal_database())
    virustotal_store.ensure_schema()
    virustotal = VirusTotalService(
        settings=settings,
        secret_store=SecretStore(settings.virustotal_secret_directory()),
        store=virustotal_store,
        evidence=evidence,
        indexer=indexer,
        triage=triage,
        audit=audit,
    )
    registry_store = RegistryStore(settings.registry_database())
    registry_store.ensure_schema()
    registry_browser = RegistryService(
        settings=settings,
        policy=policy,
        filesystem=filesystem,
        evidence=evidence,
        indexer=indexer,
        index_store=index_store,
        triage=triage,
        virustotal=virustotal,
        audit=audit,
        store=registry_store,
    )
    evtx_store = EvtxStore(settings.evtx_database())
    evtx_store.ensure_schema()
    evtx = EvtxService(
        settings=settings,
        policy=policy,
        filesystem=filesystem,
        evidence=evidence,
        indexer=indexer,
        index_store=index_store,
        audit=audit,
        store=evtx_store,
    )
    browser_store = BrowserStore(settings.browser_database())
    browser_store.ensure_schema()
    browser_artifacts = BrowserArtifactService(
        settings=settings,
        policy=policy,
        filesystem=filesystem,
        evidence=evidence,
        indexer=indexer,
        index_store=index_store,
        audit=audit,
        store=browser_store,
    )
    preview = FilePreviewService(
        settings=settings,
        policy=policy,
        filesystem=filesystem,
        evidence=evidence,
        indexer=indexer,
        audit=audit,
    )
    preview.attach_registry_lookup(
        lambda evidence_id, entry_id: _hive_summary(
            registry_store, evidence_id, entry_id
        )
    )
    return Services(
        settings=settings,
        policy=policy,
        runner=runner,
        registry=registry,
        filesystem=filesystem,
        provider=provider,
        evidence=evidence,
        audit=audit,
        index_store=index_store,
        indexer=indexer,
        triage_store=triage_store,
        triage=triage,
        virustotal_store=virustotal_store,
        virustotal=virustotal,
        registry_store=registry_store,
        registry_browser=registry_browser,
        evtx_store=evtx_store,
        evtx=evtx,
        browser_store=browser_store,
        browser_artifacts=browser_artifacts,
        preview=preview,
    )


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _hive_summary(
    registry_store: RegistryStore, evidence_id: str, entry_id: int
) -> dict[str, Any] | None:
    """Existing registry index row for an entry, if any. Never starts a job."""
    try:
        hive = registry_store.find_hive_by_entry(evidence_id, entry_id)
    except Exception:  # noqa: BLE001 - preview must not fail on registry state
        return None
    if hive is None:
        return None
    return {
        "hive_id": hive.hive_id,
        "state": hive.state,
        "hive_type": hive.hive_type,
        "key_count": hive.key_count,
        "value_count": hive.value_count,
        "amcache_count": hive.amcache_count,
        "sensitive": hive.sensitive,
        "dirty": hive.dirty,
    }
