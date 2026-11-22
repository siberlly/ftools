from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .errors import DFIRError
from .models import TRUST_LABEL

INDEX_SCHEMA_VERSION = 3
INDEX_STATUSES = {
    "pending",
    "running",
    "ready",
    "incomplete",
    "failed",
    "interrupted",
}
SORT_FIELDS = {
    "path",
    "basename",
    "name",
    "type",
    "modified",
    "created",
    "size",
    "deleted",
    "status",
}
SORT_DIRECTIONS = {"asc", "desc"}
MAX_SEARCH_QUERY_LENGTH = 256
MAX_ENTRY_ID = (1 << 62) - 1
MAX_TREE_FILTER_LENGTH = 128
EXTENSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


class IndexError(DFIRError):
    default_code = "index_error"


class IndexNotFoundError(IndexError):
    default_code = "index_not_found"


class IndexNotReadyError(IndexError):
    default_code = "index_not_ready"


class IndexStaleError(IndexError):
    default_code = "index_stale"


class IndexIncompleteError(IndexError):
    default_code = "index_incomplete"


class IndexRunningError(IndexError):
    default_code = "index_running"


class IndexFailedError(IndexError):
    default_code = "index_failed"


class InvalidPageError(IndexError):
    default_code = "invalid_page"


class InvalidPageSizeError(IndexError):
    default_code = "invalid_page_size"


class InvalidSearchQueryError(IndexError):
    default_code = "invalid_search_query"


class InvalidEntryIdError(IndexError):
    default_code = "invalid_entry_id"


class EntryNotFoundError(IndexError):
    default_code = "entry_not_found"


class IndexStoreError(IndexError):
    default_code = "index_store_error"


ROOT_ENTRY_ID = 0


def validate_entry_id(value: Any, *, allow_root: bool = True) -> int:
    """Validate a tree/entry identifier.

    Entry identifiers are SQLite index row IDs scoped to one evidence and one
    active scan generation. ``0`` is the synthetic root when allowed.
    """
    if isinstance(value, bool):
        raise InvalidEntryIdError("entry id must be a positive integer")
    if isinstance(value, str):
        if not value.strip().isdigit():
            raise InvalidEntryIdError("entry id must be digits only")
        value = int(value.strip())
    elif not isinstance(value, int):
        raise InvalidEntryIdError("entry id must be a positive integer")
    if value < 0 or value > MAX_ENTRY_ID:
        raise InvalidEntryIdError("entry id is out of range")
    if value == 0 and not allow_root:
        raise InvalidEntryIdError("entry id 0 is the synthetic root only")
    return value


def validate_tree_filter(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > MAX_TREE_FILTER_LENGTH:
        raise InvalidSearchQueryError(
            f"filter must not exceed {MAX_TREE_FILTER_LENGTH} characters"
        )
    return text


def validate_page(value: Any) -> int:
    if isinstance(value, bool):
        raise InvalidPageError("page must be a positive integer")
    try:
        page = int(value)
    except (TypeError, ValueError) as exc:
        raise InvalidPageError("page must be a positive integer") from exc
    if page < 1:
        raise InvalidPageError("page must be >= 1")
    return page


def validate_page_size(
    value: Any, *, default_size: int, max_size: int
) -> int:
    if value is None:
        value = default_size
    if isinstance(value, bool):
        raise InvalidPageSizeError("page_size must be an integer")
    try:
        page_size = int(value)
    except (TypeError, ValueError) as exc:
        raise InvalidPageSizeError("page_size must be an integer") from exc
    if page_size < 1:
        raise InvalidPageSizeError("page_size must be >= 1")
    if page_size > max_size:
        raise InvalidPageSizeError(
            f"page_size must not exceed {max_size}"
        )
    return page_size


def normalize_extension(value: str | None) -> str | None:
    if value is None:
        return None
    extension = str(value).strip().lower()
    if not extension:
        return None
    if extension.startswith("."):
        extension = extension[1:]
    if not EXTENSION_RE.fullmatch(extension):
        raise InvalidSearchQueryError("invalid extension filter")
    return extension


def validate_sort(sort: str, sort_dir: str) -> tuple[str, str]:
    if sort not in SORT_FIELDS:
        raise InvalidSearchQueryError(
            "invalid sort field; expected one of "
            + ", ".join(sorted(SORT_FIELDS))
        )
    direction = (sort_dir or "asc").lower()
    if direction not in SORT_DIRECTIONS:
        raise InvalidSearchQueryError("sort_dir must be asc or desc")
    return sort, direction


def validate_search_text(value: str, *, required: bool) -> str | None:
    text = (value or "").strip()
    if not text:
        if required:
            raise InvalidSearchQueryError("search query must not be empty")
        return None
    if len(text) > MAX_SEARCH_QUERY_LENGTH:
        raise InvalidSearchQueryError(
            f"search query must not exceed {MAX_SEARCH_QUERY_LENGTH} characters"
        )
    return text


def normalize_entry_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"", "any", "all"}:
        return None
    if normalized not in {"file", "directory"}:
        raise InvalidSearchQueryError(
            "entry_type must be 'file' or 'directory'"
        )
    return normalized


@dataclass(slots=True)
class IndexedEntry:
    id: int
    evidence_id: str
    full_path: str
    parent_path: str
    basename: str
    extension: str
    inode: int | None
    sequence: int | None
    attribute_id: int | None
    fls_type: str | None
    entry_type: str
    allocated: bool
    deleted: bool
    size: int | None
    created_time: str | None
    modified_time: str | None
    accessed_time: str | None
    mft_modified_time: str | None
    raw_line_hash: str | None
    parent_id: int | None = None
    backend_type: str | None = None
    source_ref: str | None = None
    stored_md5: str | None = None
    stored_sha1: str | None = None

    @property
    def status_label(self) -> str:
        return "deleted" if self.deleted else ("allocated" if self.allocated else "unallocated")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        data["status"] = self.status_label
        data["entry_id"] = self.id
        return data

    def to_tree_node(self, *, has_children: bool | None = None) -> "TreeNode":
        return TreeNode(
            entry_id=self.id,
            parent_id=self.parent_id,
            name=self.basename,
            path=self.full_path,
            entry_type=self.entry_type,
            inode=self.inode,
            size=self.size,
            allocated=self.allocated,
            deleted=self.deleted,
            has_children=(
                has_children
                if has_children is not None
                else self.entry_type == "directory"
            ),
            modified_time=self.modified_time,
        )

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "IndexedEntry":
        keys = set(row.keys()) if hasattr(row, "keys") else set()
        parent_id = (
            int(row["parent_id"])
            if "parent_id" in keys and row["parent_id"] is not None
            else None
        )
        return cls(
            id=int(row["id"]),
            evidence_id=str(row["evidence_id"]),
            full_path=str(row["full_path"]),
            parent_path=str(row["parent_path"]),
            basename=str(row["basename"]),
            extension=str(row["extension"] or ""),
            inode=int(row["inode"]) if row["inode"] is not None else None,
            backend_type=row["backend_type"] if "backend_type" in keys else None,
            source_ref=row["source_ref"] if "source_ref" in keys else None,
            stored_md5=row["stored_md5"] if "stored_md5" in keys else None,
            stored_sha1=row["stored_sha1"] if "stored_sha1" in keys else None,
            sequence=int(row["sequence"]) if row["sequence"] is not None else None,
            attribute_id=(
                int(row["attribute_id"])
                if row["attribute_id"] is not None
                else None
            ),
            fls_type=row["fls_type"],
            entry_type=str(row["entry_type"]),
            allocated=bool(row["allocated"]),
            deleted=bool(row["deleted"]),
            size=int(row["size"]) if row["size"] is not None else None,
            created_time=row["created_time"],
            modified_time=row["modified_time"],
            accessed_time=row["accessed_time"],
            mft_modified_time=row["mft_modified_time"],
            raw_line_hash=row["raw_line_hash"],
            parent_id=parent_id,
        )


@dataclass(slots=True)
class TreeNode:
    entry_id: int
    parent_id: int | None
    name: str
    path: str
    entry_type: str
    inode: int | None
    size: int | None
    allocated: bool
    deleted: bool
    has_children: bool
    modified_time: str | None = None

    @property
    def status_label(self) -> str:
        return (
            "deleted"
            if self.deleted
            else ("allocated" if self.allocated else "unallocated")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "entry_id": self.entry_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "path": self.path,
            "type": self.entry_type,
            "mft": self.inode,
            "size": self.size,
            "allocated": self.allocated,
            "deleted": self.deleted,
            "status": self.status_label,
            "has_children": self.has_children,
            "modified_time": self.modified_time,
        }


@dataclass(slots=True)
class TreePage:
    evidence_id: str
    parent: TreeNode | None
    children: list[TreeNode]
    total: int
    page: int
    page_size: int
    include_deleted: bool
    directories_only: bool
    filter: str | None
    index_status: IndexStatus
    complete: bool
    warning: str | None = None
    sort: str = "path"
    sort_dir: str = "asc"
    prev_url: str | None = None
    next_url: str | None = None
    sort_urls: dict[str, str] = field(default_factory=dict)

    @property
    def pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "evidence_id": self.evidence_id,
            "parent": self.parent.to_dict() if self.parent else None,
            "children": [child.to_dict() for child in self.children],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "has_more": self.has_more,
            "include_deleted": self.include_deleted,
            "directories_only": self.directories_only,
            "filter": self.filter,
            "index_status": self.index_status.status,
            "complete": self.complete,
            "warning": self.warning,
        }


@dataclass(slots=True)
class TreeAncestors:
    evidence_id: str
    entry: TreeNode
    ancestors: list[TreeNode]
    root_id: int = ROOT_ENTRY_ID
    resolvable: bool = True
    warning: str | None = None
    index_status: IndexStatus | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "evidence_id": self.evidence_id,
            "entry": self.entry.to_dict(),
            "ancestors": [node.to_dict() for node in self.ancestors],
            "root_id": self.root_id,
            "resolvable": self.resolvable,
            "warning": self.warning,
            "index_status": (
                self.index_status.status if self.index_status else None
            ),
        }


@dataclass(slots=True)
class IndexStatus:
    evidence_id: str
    found: bool
    status: str
    stale: bool
    queryable: bool
    complete: bool
    scan_id: str | None = None
    source_sha256: str | None = None
    raw_exposure_path: str | None = None
    filesystem: str | None = None
    offset_sectors: int | None = None
    fls_version: str | None = None
    index_schema_version: int = INDEX_SCHEMA_VERSION
    scanner_version: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    elapsed_seconds: float | None = None
    entries_seen: int = 0
    entries_indexed: int = 0
    parse_errors: int = 0
    deleted_files: int = 0
    deleted_directories: int = 0
    allocated_files: int = 0
    allocated_directories: int = 0
    current_path: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class IndexProgress:
    evidence_id: str
    found: bool
    status: str
    stale: bool
    complete: bool
    elapsed_seconds: float | None
    entries_seen: int
    entries_indexed: int
    parse_errors: int
    deleted_files: int
    deleted_directories: int
    current_path: str | None
    warning: str | None

    @classmethod
    def from_status(cls, status: IndexStatus) -> "IndexProgress":
        return cls(
            evidence_id=status.evidence_id,
            found=status.found,
            status=status.status,
            stale=status.stale,
            complete=status.complete,
            elapsed_seconds=status.elapsed_seconds,
            entries_seen=status.entries_seen,
            entries_indexed=status.entries_indexed,
            parse_errors=status.parse_errors,
            deleted_files=status.deleted_files,
            deleted_directories=status.deleted_directories,
            current_path=status.current_path,
            warning=status.warning,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["trust"] = TRUST_LABEL
        return data


@dataclass(slots=True)
class PaginatedEntries:
    results: list[IndexedEntry]
    total: int
    page: int
    page_size: int
    index_status: IndexStatus
    complete: bool
    warning: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    sort: str = "path"
    sort_dir: str = "asc"
    prev_url: str | None = None
    next_url: str | None = None
    sort_urls: dict[str, str] = field(default_factory=dict)

    @property
    def pages(self) -> int:
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "entries": [entry.to_dict() for entry in self.results],
            "total": self.total,
            "page": self.page,
            "page_size": self.page_size,
            "pages": self.pages,
            "index_status": self.index_status.status,
            "index": self.index_status.to_dict(),
            "complete": self.complete,
            "warning": self.warning,
            "summary": self.summary,
            "sort": self.sort,
            "sort_dir": self.sort_dir,
            "prev_url": self.prev_url,
            "next_url": self.next_url,
        }


@dataclass(slots=True)
class DeletedFilesQuery:
    include_directories: bool = False
    extension: str | None = None
    search: str | None = None
    page: int = 1
    page_size: int = 100
    sort: str = "path"
    sort_dir: str = "asc"

    @classmethod
    def create(
        cls,
        *,
        include_directories: bool = False,
        extension: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
        default_page_size: int = 100,
        max_page_size: int = 500,
    ) -> "DeletedFilesQuery":
        sort, sort_dir = validate_sort(sort, sort_dir)
        return cls(
            include_directories=bool(include_directories),
            extension=normalize_extension(extension),
            search=validate_search_text(search or "", required=False),
            page=validate_page(page),
            page_size=validate_page_size(
                page_size,
                default_size=default_page_size,
                max_size=max_page_size,
            ),
            sort=sort,
            sort_dir=sort_dir,
        )


@dataclass(slots=True)
class FileSearchQuery:
    query: str
    exact: bool = False
    extension: str | None = None
    deleted_only: bool = False
    allocated_only: bool = False
    entry_type: str | None = None
    page: int = 1
    page_size: int = 100
    sort: str = "path"
    sort_dir: str = "asc"

    @classmethod
    def create(
        cls,
        *,
        query: str,
        exact: bool = False,
        extension: str | None = None,
        deleted_only: bool = False,
        allocated_only: bool = False,
        entry_type: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
        default_page_size: int = 100,
        max_page_size: int = 500,
    ) -> "FileSearchQuery":
        text = validate_search_text(query, required=True) or ""
        if deleted_only and allocated_only:
            raise InvalidSearchQueryError(
                "deleted_only and allocated_only are mutually exclusive"
            )
        sort, sort_dir = validate_sort(sort, sort_dir)
        return cls(
            query=text,
            exact=bool(exact),
            extension=normalize_extension(extension),
            deleted_only=bool(deleted_only),
            allocated_only=bool(allocated_only),
            entry_type=normalize_entry_type(entry_type),
            page=validate_page(page),
            page_size=validate_page_size(
                page_size,
                default_size=default_page_size,
                max_size=max_page_size,
            ),
            sort=sort,
            sort_dir=sort_dir,
        )


@dataclass(slots=True)
class IndexStartResult:
    started: bool
    scan_id: str | None
    status: IndexStatus
    existing_index_status: IndexStatus | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": TRUST_LABEL,
            "started": self.started,
            "job_id": self.scan_id,
            "scan_id": self.scan_id,
            "status": self.status.status,
            "index": self.status.to_dict(),
            "existing_index_status": (
                self.existing_index_status.to_dict()
                if self.existing_index_status is not None
                else None
            ),
            "note": self.note,
        }


def not_ready_error(status: IndexStatus) -> IndexError:
    code_map = {
        "running": "index_running",
        "failed": "index_failed",
        "incomplete": "index_incomplete",
        "pending": "index_not_ready",
        "interrupted": "index_not_ready",
    }
    code = code_map.get(status.status, "index_not_ready")
    error_type: type[IndexError] = {
        "index_running": IndexRunningError,
        "index_failed": IndexFailedError,
        "index_incomplete": IndexIncompleteError,
    }.get(code, IndexNotReadyError)
    return error_type(
        status.warning or f"filesystem index is not ready: {status.status}",
        code=code,
        details={"status": status.status, "stale": status.stale},
    )


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
