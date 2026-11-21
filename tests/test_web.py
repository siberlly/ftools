from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from dfir_browser.core.config import Settings
from dfir_browser.core.evidence import EvidenceNotFound
from dfir_browser.core.index_models import (
    IndexedEntry,
    IndexStartResult,
    IndexStatus,
    PaginatedEntries,
)
from dfir_browser.core.models import (
    DirEntry,
    DirectoryListing,
    EvidenceRecord,
    ExtractionResult,
    Layout,
    MetadataResult,
    utc_now_iso,
)
from dfir_browser.web.app import create_app

EVIDENCE_ID = "ev_0123456789ab"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def make_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EVIDENCE_ID,
        resolved_source_path="/home/ubuntu/test/temp_extract_dir/SysInternals.E01",
        filename="SysInternals.E01",
        extension=".e01",
        source_sha256="a" * 64,
        source_size=123,
        source_mtime_ns=456_000_000_000,
        format="FTK Imager",
        media_size=4096,
        sector_size=512,
        md5="0" * 32,
        sha1="0" * 40,
        ewfinfo_version="ewfinfo 20140814",
        ewfinfo_duration_ms=1.0,
        ewfinfo_command={},
        raw_exposure_path="/home/ubuntu/mnt/ewf/ewf1",
        exposure_mode="explicit",
        exposure_verified_at=utc_now_iso(),
        exposure_details={"read_only": True},
        layout=Layout(
            scope="volume",
            filesystem="NTFS",
            offset_sectors=0,
            method="fsstat",
        ),
        registered_at=utc_now_iso(),
        status="ready",
        warnings=[],
    )


def make_entry(
    name: str,
    inode: int = 60734,
    entry_type: str = "file",
    *,
    full_path: str | None = None,
    deleted: bool = False,
) -> DirEntry:
    return DirEntry(
        name=name,
        inode=inode,
        sequence=1,
        attribute_id=128,
        entry_type=entry_type,
        allocated=not deleted,
        deleted=deleted,
        size=1,
        mtime="2019-03-19T13:01:28Z",
        full_path=full_path,
        parent_path=(
            full_path.rpartition("/")[0] if full_path else None
        ),
        basename=name,
    )


def make_listing(
    entries: list[DirEntry] | None = None,
    *,
    truncated: bool = False,
    warning: str | None = None,
) -> DirectoryListing:
    entries = entries or [
        make_entry("Users", inode=1746, entry_type="directory")
    ]
    warnings = [warning] if warning else []
    return DirectoryListing(
        evidence_id=EVIDENCE_ID,
        inode=5,
        offset_sectors=0,
        breadcrumb=[{"inode": 5, "name": "/"}],
        entries=entries,
        warnings=warnings,
        tool_version="fake-tsk 1.0",
        command={},
        complete=not truncated,
        truncated=truncated,
        warning=warning,
        cursor=None,
        next_cursor=None,
        source="live",
    )


def make_index_listing(
    entries: list[DirEntry] | None = None, *, status: IndexStatus | None = None
) -> DirectoryListing:
    status = status or make_index_status("ready")
    entries = entries or [
        make_entry(
            "IEUser",
            inode=83437,
            entry_type="directory",
            full_path="Users/IEUser",
        )
    ]
    return DirectoryListing(
        evidence_id=EVIDENCE_ID,
        inode=1746,
        offset_sectors=0,
        breadcrumb=[
            {"name": "/", "path": ""},
            {"name": "Users", "path": "Users"},
        ],
        entries=entries,
        warnings=[status.warning] if status.warning else [],
        tool_version="tsk",
        command={},
        complete=status.complete,
        truncated=False,
        warning=status.warning,
        source="index",
        path="Users",
        index_status=status.status,
        total=len(entries),
        page=1,
        page_size=100,
    )


def make_metadata(name: str = "bootmgr", raw: str = "Entry: 60734") -> MetadataResult:
    return MetadataResult(
        evidence_id=EVIDENCE_ID,
        inode=60734,
        summary={
            "inode": 60734,
            "sequence": 2,
            "allocated": True,
            "is_directory": False,
            "name": name,
            "parent_inode": 5,
            "security_id": 765,
            "flags": "Archive",
            "timestamps": {
                "created": "2019-03-19T21:54:52.575672700Z",
                "modified": "2019-03-19T13:15:36.395700100Z",
                "mft_modified": "2019-03-19T13:19:57.258797700Z",
                "accessed": "2019-03-19T13:19:57.258797700Z",
            },
            "data_size": 408364,
            "attributes": [],
        },
        raw=raw,
        raw_truncated=False,
        warnings=[],
        tool_version="fake-tsk 1.0",
        command={},
    )


def make_extraction() -> ExtractionResult:
    return ExtractionResult(
        evidence_id=EVIDENCE_ID,
        case_id="case01",
        inode=60021,
        name="BOOTNXT",
        output_path="/tmp/fake-out",
        relative_path="cases/case01/exports/fake-out",
        size=1,
        sha256=(
            "6e340b9cffb37a989ca544e6bb780a2"
            "c78901d3fb33738768511a30617afa01d"
        ),
        source_size=1,
        tool_version="fake-tsk 1.0",
        extracted_at=utc_now_iso(),
        untrusted=True,
    )


def make_index_status(
    status: str = "pending",
    *,
    entries_indexed: int = 0,
    parse_errors: int = 0,
    stale: bool = False,
    complete: bool | None = None,
    warning: str | None = None,
) -> IndexStatus:
    found = status != "pending"
    queryable = found and not stale and status in {"ready", "incomplete"}
    if complete is None:
        complete = status == "ready" and parse_errors == 0 and not stale
    if warning is None:
        warning = {
            "pending": "Filesystem index has not been built.",
            "running": "Filesystem index scan is running.",
            "incomplete": "Filesystem index is incomplete; results may be missing entries.",
            "failed": "Filesystem index failed.",
            "interrupted": "Filesystem index scan was interrupted.",
            "ready": None,
        }.get(status)
    return IndexStatus(
        evidence_id=EVIDENCE_ID,
        found=found,
        status=status,
        stale=stale,
        queryable=queryable,
        complete=complete,
        scan_id="scan1" if found else None,
        entries_seen=entries_indexed,
        entries_indexed=entries_indexed,
        parse_errors=parse_errors,
        deleted_files=3,
        deleted_directories=1,
        allocated_files=10,
        allocated_directories=2,
        scanner_version="fls-r-p-l-v1",
        fls_version="fake-tsk 1.0",
        warning=warning,
    )


def make_indexed_entry(
    full_path: str,
    *,
    deleted: bool = False,
    inode: int | None = 124567,
    entry_type: str = "file",
) -> IndexedEntry:
    parent, _, basename = full_path.rpartition("/")
    extension = (
        basename.rsplit(".", 1)[1].lower() if "." in basename else ""
    )
    return IndexedEntry(
        id=1,
        evidence_id=EVIDENCE_ID,
        full_path=full_path,
        parent_path=parent,
        basename=basename,
        extension=extension,
        inode=inode,
        sequence=1,
        attribute_id=128,
        fls_type="-/r" if deleted else "r/r",
        entry_type=entry_type,
        allocated=not deleted,
        deleted=deleted,
        size=57344,
        created_time="2022-11-15T21:18:51Z",
        modified_time="2022-11-15T21:18:51Z",
        accessed_time="2022-11-15T21:19:00Z",
        mft_modified_time="2022-11-15T21:19:00Z",
        raw_line_hash="a" * 64,
    )


def make_paginated(
    entries: list[IndexedEntry] | None = None,
    *,
    status: IndexStatus | None = None,
    total: int | None = None,
    page: int = 1,
    page_size: int = 100,
) -> PaginatedEntries:
    status = status or make_index_status("ready")
    entries = entries or []
    return PaginatedEntries(
        results=entries,
        total=len(entries) if total is None else total,
        page=page,
        page_size=page_size,
        index_status=status,
        complete=status.complete,
        warning=status.warning,
        summary={
            "deleted_files": 1,
            "deleted_directories": 1,
            "parse_errors": status.parse_errors,
            "index_complete": status.complete,
        },
        sort="path",
        sort_dir="asc",
    )


class FakeEvidence:
    def __init__(self, record: EvidenceRecord) -> None:
        self.record = record
        self.registered_paths: list[str] = []
        self.indexer = None

    def list(self):
        return [self.record]

    def get(self, evidence_id: str):
        if evidence_id != self.record.evidence_id:
            raise EvidenceNotFound(f"unknown evidence id: {evidence_id}")
        return self.record

    def register(self, path: str):
        self.registered_paths.append(path)
        return self.record

    def ensure_image(self, record):
        return Path("/tmp/fake-ewf1")

    def inspect(self, evidence_id: str):
        return {"trust": "untrusted_evidence_data", "evidence": self.record.to_dict()}


class FakeFilesystem:
    def __init__(
        self,
        listing: DirectoryListing,
        metadata: MetadataResult,
        extraction: ExtractionResult,
    ) -> None:
        self.listing = listing
        self.metadata = metadata
        self.extraction = extraction

    def list_directory(self, image, evidence_id, inode=5, offset_sectors=0):
        return self.listing

    def stat(self, image, evidence_id, inode, offset_sectors=0):
        return self.metadata

    def extract(self, image, evidence_id, inode, case_id, offset_sectors=0):
        return self.extraction


class FakeIndexer:
    def __init__(
        self,
        *,
        status: IndexStatus | None = None,
        listing: DirectoryListing | None = None,
        all_result: PaginatedEntries | None = None,
        deleted_result: PaginatedEntries | None = None,
        search_result: PaginatedEntries | None = None,
    ) -> None:
        self.status = status or make_index_status("pending")
        self.listing = listing or make_index_listing()
        self.all_result = all_result or make_paginated(
            [make_indexed_entry("Users/Public/Downloads/SysInternals.exe", deleted=True)],
            status=make_index_status("ready"),
            total=250,
        )
        self.deleted_result = deleted_result or make_paginated(
            [make_indexed_entry("Users/Public/Downloads/SysInternals.exe", deleted=True)],
            status=make_index_status("ready"),
        )
        self.search_result = search_result or make_paginated(
            [make_indexed_entry("Users/Public/Downloads/SysInternals.exe", deleted=True)],
            status=make_index_status("ready"),
        )
        self.starts: list[tuple[str, bool]] = []

    def status_for_record(self, record):
        return self.status

    def is_queryable(self, status):
        return status.queryable

    def list_directory(self, record, path="", page=1, page_size=None):
        self.listing.path = path
        self.listing.source = "index"
        self.listing.index_status = self.status.status
        self.listing.page = page
        self.listing.page_size = page_size or 100
        self.listing.total = len(self.listing.entries)
        self.listing.complete = self.status.complete
        self.listing.warning = self.status.warning
        return self.listing

    def resolve_directory_path(self, record, inode):
        return {5: "", 1746: "Users", 83437: "Users/IEUser"}.get(inode)

    def start_scan(self, evidence_id, rebuild=False):
        self.starts.append((evidence_id, rebuild))
        running = make_index_status("running")
        return IndexStartResult(
            started=True,
            scan_id="scan2",
            status=running,
            existing_index_status=self.status,
        )

    def list_all_under(
        self,
        record,
        path="",
        *,
        page=1,
        page_size=None,
        sort="path",
        sort_dir="asc",
    ):
        self.all_result.page = page
        self.all_result.page_size = page_size or 100
        self.all_result.sort = sort
        self.all_result.sort_dir = sort_dir
        return self.all_result

    def list_deleted(self, record, query):
        self.deleted_result.page = query.page
        self.deleted_result.page_size = query.page_size
        self.deleted_result.sort = query.sort
        self.deleted_result.sort_dir = query.sort_dir
        return self.deleted_result

    def search(self, record, query):
        self.search_result.page = query.page
        self.search_result.page_size = query.page_size
        self.search_result.sort = query.sort
        self.search_result.sort_dir = query.sort_dir
        return self.search_result

    def cancel_all(self):
        return None


def make_settings(tmp_path: Path, allowed: Path) -> Settings:
    return Settings.from_env(
        var_dir=tmp_path / "var",
        allowed_roots=(allowed,),
        ewf_mappings={},
        ewf_automount=False,
        auto_index=False,
        allowed_hosts=("127.0.0.1", "localhost", "testserver"),
        allowed_origins=(
            "http://testserver",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
        ),
    )


def make_fake_client(
    tmp_path: Path,
    *,
    listing: DirectoryListing | None = None,
    metadata: MetadataResult | None = None,
    extraction: ExtractionResult | None = None,
    indexer: FakeIndexer | None = None,
    status: IndexStatus | None = None,
) -> tuple[TestClient, FakeEvidence]:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    settings = make_settings(tmp_path, allowed)
    evidence = FakeEvidence(make_record())
    filesystem = FakeFilesystem(
        listing or make_listing(),
        metadata or make_metadata(),
        extraction or make_extraction(),
    )
    indexer = indexer or FakeIndexer(status=status or make_index_status("pending"))
    evidence.indexer = indexer
    services = SimpleNamespace(
        settings=settings,
        evidence=evidence,
        filesystem=filesystem,
        indexer=indexer,
        cleanup=lambda: None,
    )
    app = create_app(settings, services=services)
    return TestClient(app), evidence


def make_real_client(tmp_path: Path) -> tuple[TestClient, Path]:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    settings = make_settings(tmp_path, allowed)
    client = TestClient(create_app(settings))
    return client, allowed


def get_csrf(client: TestClient) -> str:
    response = client.get("/")
    assert response.status_code == 200
    match = CSRF_RE.search(response.text)
    assert match, response.text
    return match.group(1)


def test_index_static_assets_and_health(tmp_path: Path) -> None:
    client = make_real_client(tmp_path)[0]
    response = client.get("/")
    assert response.status_code == 200
    assert "Register evidence" in response.text
    assert CSRF_RE.search(response.text)
    assert "dfir_session" in response.headers.get("set-cookie", "")
    assert client.get("/static/htmx.min.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}


def test_invalid_host_rejected(tmp_path: Path) -> None:
    client = make_real_client(tmp_path)[0]
    response = client.get("/", headers={"host": "evil.example"})
    assert response.status_code == 400


def test_registration_requires_csrf(tmp_path: Path) -> None:
    client, evidence = make_fake_client(tmp_path)
    response = client.post("/evidence", data={"path": "/anything.E01"})
    assert response.status_code == 403
    assert evidence.registered_paths == []


def test_registration_with_valid_csrf(tmp_path: Path) -> None:
    client, evidence = make_fake_client(tmp_path)
    token = get_csrf(client)
    response = client.post(
        "/evidence",
        data={"path": "/anything.E01", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/evidence/{EVIDENCE_ID}"
    assert evidence.registered_paths == ["/anything.E01"]


def test_invalid_origin_rejected(tmp_path: Path) -> None:
    client, evidence = make_fake_client(tmp_path)
    token = get_csrf(client)
    response = client.post(
        "/evidence",
        data={"path": "/anything.E01", "csrf_token": token},
        headers={"origin": "http://evil.example"},
    )
    assert response.status_code == 403
    assert evidence.registered_paths == []


def test_invalid_referer_rejected(tmp_path: Path) -> None:
    client, evidence = make_fake_client(tmp_path)
    token = get_csrf(client)
    response = client.post(
        "/evidence",
        data={"path": "/anything.E01", "csrf_token": token},
        headers={"referer": "http://evil.example/attack"},
    )
    assert response.status_code == 403
    assert evidence.registered_paths == []


def test_allowed_origin_accepted(tmp_path: Path) -> None:
    client, evidence = make_fake_client(tmp_path)
    token = get_csrf(client)
    response = client.post(
        "/evidence",
        data={"path": "/anything.E01", "csrf_token": token},
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert evidence.registered_paths == ["/anything.E01"]


def test_csrf_token_is_bound_to_session(tmp_path: Path) -> None:
    client_a, evidence = make_fake_client(tmp_path)
    token_a = get_csrf(client_a)
    client_b = TestClient(client_a.app)
    get_csrf(client_b)
    response = client_b.post(
        "/evidence", data={"path": "/anything.E01", "csrf_token": token_a}
    )
    assert response.status_code == 403
    assert evidence.registered_paths == []


def test_get_browse_is_read_only(tmp_path: Path) -> None:
    client = make_fake_client(tmp_path)[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/browse?inode=5")
    assert response.status_code == 200
    assert "Users" in response.text
    assert "LIVE RESULT" in response.text


def test_truncated_listing_banner(tmp_path: Path) -> None:
    listing = make_listing(
        truncated=True,
        warning="fls output was truncated at 123 bytes; INCOMPLETE listing.",
    )
    client = make_fake_client(tmp_path, listing=listing)[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/browse?inode=5")
    assert response.status_code == 200
    assert "INCOMPLETE LISTING" in response.text
    assert "truncated" in response.text
    assert "incomplete" in response.text


def test_evidence_filenames_are_escaped(tmp_path: Path) -> None:
    names = [
        "<script>alert(1)</script>",
        "A & B",
        "quote\" and 'single'",
        "tab\tname",
        "line\nbreak",
        "Tiếng Việt 日本語",
    ]
    entries = [make_entry(name, inode=1000 + i) for i, name in enumerate(names)]
    client = make_fake_client(tmp_path, listing=make_listing(entries))[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/browse?inode=5")
    assert response.status_code == 200
    text = response.text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "A &amp; B" in text
    assert "quote&#34; and &#39;single&#39;" in text
    assert "Tiếng Việt 日本語" in text


def test_stat_metadata_and_raw_are_escaped(tmp_path: Path) -> None:
    metadata = make_metadata(
        name="<script>alert(2)</script>",
        raw="Name: <script>alert(3)</script>",
    )
    client = make_fake_client(tmp_path, metadata=metadata)[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/stat/60734")
    assert response.status_code == 200
    text = response.text
    assert "<script>alert(2)</script>" not in text
    assert "<script>alert(3)</script>" not in text
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in text
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in text
    assert "Untrusted evidence file" in text


def test_breadcrumb_names_are_escaped(tmp_path: Path) -> None:
    listing = make_listing()
    listing.breadcrumb = [
        {"inode": 5, "name": "/"},
        {"inode": 6, "name": "<script>crumb</script>"},
        {"inode": 1746, "name": "Users"},
    ]
    client = make_fake_client(tmp_path, listing=listing)[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/browse?inode=5")
    assert response.status_code == 200
    assert "<script>crumb</script>" not in response.text
    assert "&lt;script&gt;crumb&lt;/script&gt;" in response.text


def test_extract_requires_csrf(tmp_path: Path) -> None:
    client = make_fake_client(tmp_path)[0]
    response = client.post(
        f"/evidence/{EVIDENCE_ID}/extract",
        data={"inode": "60021", "case_id": "case01"},
    )
    assert response.status_code == 403


def test_extract_with_valid_csrf(tmp_path: Path) -> None:
    client = make_fake_client(tmp_path)[0]
    token = get_csrf(client)
    response = client.post(
        f"/evidence/{EVIDENCE_ID}/extract",
        data={
            "inode": "60021",
            "case_id": "case01",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200
    assert "Extraction complete" in response.text
    assert "untrusted" in response.text
    assert (
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        in response.text
    )


def test_unknown_evidence_detail_returns_404(tmp_path: Path) -> None:
    client = make_real_client(tmp_path)[0]
    response = client.get("/evidence/ev_000000000000")
    assert response.status_code == 404
    assert "unknown evidence id" in response.text


def test_registration_rejects_path_outside_allowlist_with_csrf(
    tmp_path: Path,
) -> None:
    client, _allowed = make_real_client(tmp_path)
    token = get_csrf(client)
    outside = tmp_path / "outside.E01"
    outside.write_bytes(b"not an image")
    response = client.post(
        "/evidence",
        data={"path": str(outside), "csrf_token": token},
    )
    assert response.status_code == 400
    assert "outside the allowed roots" in response.text


def test_registration_rejects_unsupported_extension_with_csrf(
    tmp_path: Path,
) -> None:
    client, allowed = make_real_client(tmp_path)
    token = get_csrf(client)
    notes = allowed / "notes.txt"
    notes.write_text("x")
    response = client.post(
        "/evidence",
        data={"path": str(notes), "csrf_token": token},
    )
    assert response.status_code == 400
    assert "unsupported evidence extension" in response.text


# ---------------------------------------------------------------------------
# Index-backed UI
# ---------------------------------------------------------------------------


def test_index_status_card_and_build_csrf(tmp_path: Path) -> None:
    client, evidence = make_fake_client(
        tmp_path, status=make_index_status("pending")
    )
    token = get_csrf(client)
    detail = client.get(f"/evidence/{EVIDENCE_ID}")
    assert detail.status_code == 200
    assert "Build index" in detail.text
    assert 'name="csrf_token"' in detail.text
    response = client.post(
        f"/evidence/{EVIDENCE_ID}/index",
        data={"rebuild": "1", "csrf_token": token},
        headers={"hx-request": "true"},
    )
    assert response.status_code == 200
    assert evidence.indexer.starts == [(EVIDENCE_ID, True)]
    assert "running" in response.text
    assert 'hx-trigger="every 2s"' in response.text


def test_index_build_requires_csrf(tmp_path: Path) -> None:
    client, evidence = make_fake_client(
        tmp_path, status=make_index_status("pending")
    )
    response = client.post(
        f"/evidence/{EVIDENCE_ID}/index", data={"rebuild": "1"}
    )
    assert response.status_code == 403
    assert evidence.indexer.starts == []


def test_index_status_polling_attributes(tmp_path: Path) -> None:
    client, evidence = make_fake_client(
        tmp_path, status=make_index_status("running")
    )
    response = client.get(f"/evidence/{EVIDENCE_ID}/index/status")
    assert response.status_code == 200
    assert 'hx-trigger="every 2s"' in response.text
    assert "running" in response.text
    evidence.indexer.status = make_index_status(
        "ready", entries_indexed=10
    )
    response = client.get(f"/evidence/{EVIDENCE_ID}/index/status")
    assert response.status_code == 200
    assert 'hx-trigger="every 2s"' not in response.text
    assert "ready" in response.text


def test_browse_from_index(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=10)
    listing = make_index_listing(status=status)
    client = make_fake_client(
        tmp_path, indexer=FakeIndexer(status=status, listing=listing)
    )[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/browse?path=Users")
    assert response.status_code == 200
    text = response.text
    assert "Indexed path" in text
    assert "IEUser" in text
    assert "LIVE RESULT" not in text
    assert "DELETED / UNALLOCATED" not in text


def test_all_entries_page_pagination(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=250)
    entry = make_indexed_entry(
        "Users/Public/Downloads/SysInternals.exe", deleted=True
    )
    result = make_paginated([entry], status=status, total=250)
    client = make_fake_client(
        tmp_path,
        indexer=FakeIndexer(status=status, all_result=result),
    )[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/entries?path=")
    assert response.status_code == 200
    text = response.text
    assert "All entries" in text
    assert "Users/Public/Downloads/SysInternals.exe" in text
    assert "Next" in text
    assert "DELETED / UNALLOCATED" in text


def test_deleted_page_and_summary(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=10)
    entry = make_indexed_entry(
        "Users/Public/Downloads/SysInternals.exe", deleted=True
    )
    result = make_paginated([entry], status=status)
    client = make_fake_client(
        tmp_path,
        indexer=FakeIndexer(status=status, deleted_result=result),
    )[0]
    response = client.get(
        f"/evidence/{EVIDENCE_ID}/deleted?q=Sysinternals.exe"
    )
    assert response.status_code == 200
    text = response.text
    assert "Deleted files" in text
    assert "SysInternals.exe" in text
    assert "DELETED / UNALLOCATED" in text
    assert "Deleted files" in text


def test_incomplete_index_warning_on_deleted_page(tmp_path: Path) -> None:
    status = make_index_status(
        "incomplete", entries_indexed=10, parse_errors=2
    )
    entry = make_indexed_entry(
        "Users/Public/Downloads/SysInternals.exe", deleted=True
    )
    result = make_paginated([entry], status=status)
    client = make_fake_client(
        tmp_path,
        indexer=FakeIndexer(status=status, deleted_result=result),
    )[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/deleted")
    assert response.status_code == 200
    assert "INCOMPLETE INDEX" in response.text
    assert "may be missing" in response.text


def test_search_page(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=10)
    entry = make_indexed_entry(
        "Users/Public/Downloads/SysInternals.exe", deleted=True
    )
    result = make_paginated([entry], status=status)
    client = make_fake_client(
        tmp_path,
        indexer=FakeIndexer(status=status, search_result=result),
    )[0]
    response = client.get(
        f"/evidence/{EVIDENCE_ID}/search?q=Sysinternals.exe&exact=1"
    )
    assert response.status_code == 200
    text = response.text
    assert "Search" in text
    assert "Users/Public/Downloads/SysInternals.exe" in text
    assert "DELETED / UNALLOCATED" in text


def test_invalid_search_page_size_is_reported(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=10)
    client = make_fake_client(
        tmp_path, indexer=FakeIndexer(status=status)
    )[0]
    response = client.get(
        f"/evidence/{EVIDENCE_ID}/search?q=x&page_size=9999"
    )
    assert response.status_code == 200
    assert "page_size" in response.text


def test_index_required_panel(tmp_path: Path) -> None:
    client = make_fake_client(
        tmp_path, status=make_index_status("running")
    )[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/deleted")
    assert response.status_code == 200
    assert "Filesystem index required" in response.text
    assert "running" in response.text


def test_entries_table_escapes_paths(tmp_path: Path) -> None:
    status = make_index_status("ready", entries_indexed=1)
    entry = make_indexed_entry(
        "<script>alert(4)</script>/evil.exe", deleted=True
    )
    result = make_paginated([entry], status=status)
    client = make_fake_client(
        tmp_path,
        indexer=FakeIndexer(status=status, all_result=result),
    )[0]
    response = client.get(f"/evidence/{EVIDENCE_ID}/entries?path=")
    assert response.status_code == 200
    assert "<script>alert(4)</script>" not in response.text
    assert "&lt;script&gt;alert(4)&lt;/script&gt;" in response.text
