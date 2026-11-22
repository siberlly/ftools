from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ..core.audit import correlation_scope
from ..core.config import Settings
from ..core.errors import DFIRError
from ..core.index_models import (
    DeletedFilesQuery,
    EntryNotFoundError,
    FileSearchQuery,
    IndexStatus,
    PaginatedEntries,
)
from ..core.models import DirectoryListing, EvidenceRecord, human_size
from ..core.triage_models import TriageNotFoundError
from ..core.virustotal import VirusTotalError, VirusTotalNotConfigured
from ..core.registry.models import (
    HiveNotFoundError,
    HiveNotReadyError,
    RegistryError as RegistryBrowserError,
)
from ..core.evtx.models import (
    EventQuery as EvtxEventQuery,
    EvtxLogNotFound,
    EvtxLogNotReady,
)
from ..core.evtx.presets import list_presets
from ..core.registry.detector import classify_entry as classify_hive_entry
from ..core.services import Services, build_services, configure_logging
from .security import (
    SESSION_COOKIE,
    SESSION_MAX_AGE_SECONDS,
    CSRFProtection,
    CsrfRejected,
    CsrfSession,
    load_or_create_secret,
)

logger = logging.getLogger("dfir_browser.web")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

USER_ERRORS = (DFIRError, OSError)


def _csrf_forbidden(exc: Exception) -> HTMLResponse:
    logger.warning("web request rejected by CSRF/origin policy: %s", exc)
    return HTMLResponse(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Request rejected</title></head><body>"
        "<h1>403 Request rejected</h1>"
        "<p>CSRF token, session cookie, or request origin validation failed.</p>"
        "<p><a href='/'>Back</a></p>"
        "</body></html>",
        status_code=403,
    )


def _error_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, DFIRError):
        return exc.to_dict()
    return {"code": "error", "message": str(exc), "details": {}}


def _not_ready_payload(status: IndexStatus) -> dict[str, Any]:
    code = {
        "running": "index_running",
        "failed": "index_failed",
        "incomplete": "index_incomplete",
    }.get(status.status, "index_not_ready")
    if status.stale:
        code = "index_stale"
    return {
        "code": code,
        "message": status.warning or f"filesystem index is not ready: {status.status}",
        "details": {"status": status.status, "stale": status.stale},
    }


def _tree_query(
    evidence_id: str,
    entry_id: int,
    *,
    include_deleted: bool,
    directories_only: bool,
    filter_text: str | None = None,
) -> str:
    values: dict[str, Any] = {
        "include_deleted": "1" if include_deleted else "0",
        "directories_only": "1" if directories_only else "0",
    }
    if filter_text:
        values["filter"] = filter_text
    return f"/evidence/{evidence_id}/entry/{entry_id}?" + urlencode(values)


def _attach_tree_urls(
    page,
    evidence_id: str,
    entry_id: int,
    *,
    include_deleted: bool,
    directories_only: bool,
    filter_text: str | None,
) -> None:
    def build(page_no: int, sort: str, sort_dir: str) -> str:
        values: dict[str, Any] = {
            "include_deleted": "1" if include_deleted else "0",
            "directories_only": "1" if directories_only else "0",
            "page": page_no,
            "sort": sort,
            "sort_dir": sort_dir,
        }
        if filter_text:
            values["filter"] = filter_text
        return f"/evidence/{evidence_id}/entry/{entry_id}?" + urlencode(values)

    page.prev_url = (
        build(page.page - 1, page.sort, page.sort_dir) if page.page > 1 else None
    )
    page.next_url = (
        build(page.page + 1, page.sort, page.sort_dir) if page.has_more else None
    )
    page.sort_urls = {
        field: build(
            1,
            field,
            "desc"
            if page.sort == field and page.sort_dir == "asc"
            else "asc",
        )
        for field in ("path", "type", "size", "modified", "status")
    }


def _clean_params(params: dict[str, Any]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            if not value:
                continue
            cleaned[key] = "1"
        elif value == "":
            continue
        else:
            cleaned[key] = str(value)
    return cleaned


def _url(evidence_id: str, route: str, params: dict[str, Any]) -> str:
    query = urlencode(_clean_params(params))
    return f"/evidence/{evidence_id}/{route}" + (f"?{query}" if query else "")


def _paginate(
    result: PaginatedEntries,
    evidence_id: str,
    route: str,
    filters: dict[str, Any],
) -> PaginatedEntries:
    base = dict(filters)
    result.prev_url = (
        _url(evidence_id, route, {**base, "page": result.page - 1})
        if result.page > 1
        else None
    )
    result.next_url = (
        _url(evidence_id, route, {**base, "page": result.page + 1})
        if result.page * result.page_size < result.total
        else None
    )
    result.sort_urls = {}
    for field in ("path", "basename", "modified", "created", "size", "deleted"):
        direction = (
            "desc"
            if result.sort == field and result.sort_dir == "asc"
            else "asc"
        )
        result.sort_urls[field] = _url(
            evidence_id,
            route,
            {**base, "sort": field, "sort_dir": direction, "page": 1},
        )
    return result


def _paginate_tree(
    listing: DirectoryListing, evidence_id: str
) -> DirectoryListing:
    if listing.total is None or listing.page_size <= 0:
        return listing
    base = {"path": listing.path} if listing.path else {}
    listing.prev_url = (
        _url(evidence_id, "browse", {**base, "page": listing.page - 1})
        if listing.page > 1
        else None
    )
    listing.next_url = (
        _url(evidence_id, "browse", {**base, "page": listing.page + 1})
        if listing.page * listing.page_size < listing.total
        else None
    )
    return listing


def create_app(
    settings: Settings | None = None, services: Services | None = None
) -> FastAPI:
    settings = settings or Settings.from_env()
    services = services or build_services(settings)

    allowed_origins = settings.allowed_origins or (
        f"http://127.0.0.1:{settings.port}",
        f"http://localhost:{settings.port}",
        "http://testserver",
    )
    csrf = CSRFProtection(
        load_or_create_secret(settings.secret_key_file()),
        tuple(allowed_origins),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            cleanup = getattr(services, "cleanup", None)
            if callable(cleanup):
                cleanup()

    app = FastAPI(
        title="DFIR Browser",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.services = services
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["filesize"] = human_size

    def evtx_path_hint(event) -> str:
        data = getattr(event, "event_data", None) or {}
        for key in (
            "Image",
            "NewProcessName",
            "ProcessName",
            "TargetFilename",
            "ScriptBlockText",
            "CommandLine",
        ):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                text = value.strip()
                if text.startswith("\\") or (len(text) > 2 and text[1] == ":"):
                    return text[:180]
        return ""

    templates.env.globals["evtx_path_hint"] = evtx_path_hint

    @app.middleware("http")
    async def correlation_middleware(request: Request, call_next):
        with correlation_scope("http") as request_id:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response

    def render(
        request: Request,
        name: str,
        context: dict[str, Any],
        *,
        status_code: int = 200,
        session: CsrfSession | None = None,
    ) -> HTMLResponse:
        session = session or csrf.ensure_session(request)
        context = dict(context)
        context["csrf_token"] = session.token
        response = templates.TemplateResponse(
            request=request,
            name=name,
            context=context,
            status_code=status_code,
        )
        response.set_cookie(
            SESSION_COOKIE,
            session.cookie_value,
            max_age=SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        return response

    def get_record(evidence_id: str) -> EvidenceRecord:
        return services.evidence.get(evidence_id)

    def index_status(record: EvidenceRecord) -> IndexStatus:
        return services.indexer.status_for_record(record)

    def live_listing(
        record: EvidenceRecord, status: IndexStatus, inode: int = 5
    ) -> DirectoryListing:
        exposure = services.evidence.ensure_image(record)
        listing = services.filesystem.list_directory(
            exposure,
            record.evidence_id,
            inode=inode,
            offset_sectors=record.layout.offset_sectors,
        )
        status_label = "stale" if status.stale else status.status
        listing.source = "live"
        listing.index_status = status_label
        listing.warning = (
            "Filesystem index is not ready "
            f"({status_label}); this is a live fls result."
        )
        listing.warnings = list(
            dict.fromkeys([*listing.warnings, listing.warning])
        )
        return listing

    def index_listing(
        record: EvidenceRecord,
        path: str,
        page: int = 1,
        page_size: int | None = None,
    ) -> DirectoryListing:
        listing = services.indexer.list_directory(
            record, path, page=page, page_size=page_size
        )
        return _paginate_tree(listing, record.evidence_id)

    def index_required(
        request: Request, status: IndexStatus, message: str
    ) -> HTMLResponse:
        return render(
            request,
            "partials/index_required.html",
            {"status": status, "message": message},
        )

    def index_context(error: str | None = None) -> dict[str, Any]:
        evidences: list[EvidenceRecord] = []
        registry_error = None
        try:
            evidences = services.evidence.list()
        except USER_ERRORS as exc:
            registry_error = str(exc)
            logger.error("cannot read evidence registry: %s", exc)
        return {
            "evidences": evidences,
            "allowed_roots": [str(root) for root in settings.allowed_roots],
            "error": error or registry_error,
        }

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return render(request, "index.html", index_context())

    @app.post("/evidence", response_class=HTMLResponse)
    def register_evidence(
        request: Request,
        path: str = Form(...),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = services.evidence.register(path)
        except USER_ERRORS as exc:
            logger.warning("evidence registration rejected: %s", exc)
            return render(
                request,
                "index.html",
                index_context(error=str(exc)),
                status_code=400,
            )
        if settings.auto_index:
            try:
                services.indexer.start_scan(record.evidence_id)
            except USER_ERRORS as exc:
                logger.warning(
                    "automatic index start failed for %s: %s",
                    record.evidence_id,
                    exc,
                )
        return RedirectResponse(
            url=f"/evidence/{record.evidence_id}", status_code=303
        )

    @app.get("/evidence/{evidence_id}", response_class=HTMLResponse)
    def evidence_detail(
        request: Request,
        evidence_id: str,
        entry_id: int | None = Query(None, alias="entry"),
        include_deleted: bool = True,
        directories_only: bool = False,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
        except USER_ERRORS as exc:
            return render(
                request,
                "error.html",
                {"title": "Evidence not found", "error": str(exc)},
                status_code=404,
            )

        status = index_status(record)
        params: dict[str, Any] = {}
        if entry_id is not None:
            params["entry_id"] = entry_id
        if not include_deleted:
            params["include_deleted"] = "0"
        if directories_only:
            params["directories_only"] = "1"
        tree_url = f"/evidence/{evidence_id}/tree"
        if params:
            tree_url += "?" + urlencode(params)
        return render(
            request,
            "evidence.html",
            {
                "record": record,
                "exposure_path": record.raw_exposure_path,
                "status": status,
                "auto_index": settings.auto_index,
                "tree_url": tree_url,
            },
        )

    @app.get("/evidence/{evidence_id}/browse", response_class=HTMLResponse)
    def browse(
        request: Request,
        evidence_id: str,
        path: str | None = None,
        inode: int = 5,
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if services.indexer.is_queryable(status):
                target_path = path
                if target_path is None:
                    target_path = (
                        "" 
                        if inode == 5
                        else services.indexer.resolve_directory_path(
                            record, inode
                        )
                    )
                if target_path is not None:
                    listing = index_listing(
                        record, target_path, page, page_size
                    )
                    return render(
                        request, "partials/tree.html", {"listing": listing}
                    )
            if path not in (None, ""):
                return index_required(
                    request,
                    status,
                    "Path browsing requires a ready filesystem index. "
                    f"Current index status: {status.status}.",
                )
            listing = live_listing(record, status, inode=inode)
            return render(
                request, "partials/tree.html", {"listing": listing}
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )

    @app.get(
        "/evidence/{evidence_id}/stat/{inode}", response_class=HTMLResponse
    )
    def stat_entry(
        request: Request,
        evidence_id: str,
        inode: int,
        focus: str | None = None,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            exposure = services.evidence.ensure_image(record)
            metadata = services.filesystem.stat(
                exposure,
                record.evidence_id,
                inode=inode,
                offset_sectors=record.layout.offset_sectors,
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/stat.html",
            {"metadata": metadata, "focus": focus},
        )

    @app.post(
        "/evidence/{evidence_id}/extract", response_class=HTMLResponse
    )
    def extract_entry(
        request: Request,
        evidence_id: str,
        inode: int = Form(...),
        case_id: str = Form(...),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            exposure = services.evidence.ensure_image(record)
            result = services.filesystem.extract(
                exposure,
                record.evidence_id,
                inode=inode,
                case_id=case_id,
                offset_sectors=record.layout.offset_sectors,
            )
        except USER_ERRORS as exc:
            logger.warning("extraction rejected: %s", exc)
            return render(
                request,
                "partials/extract.html",
                {"result": None, "error": str(exc)},
            )
        return render(
            request,
            "partials/extract.html",
            {"result": result, "error": None},
        )

    @app.get(
        "/evidence/{evidence_id}/index/status", response_class=HTMLResponse
    )
    def index_status_partial(
        request: Request, evidence_id: str
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/index_status.html",
            {"status": status, "error": None, "auto_index": settings.auto_index},
        )

    @app.post(
        "/evidence/{evidence_id}/index", response_class=HTMLResponse
    )
    def start_index(
        request: Request,
        evidence_id: str,
        rebuild: bool = Form(False),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/error.html",
                {"error": str(exc)},
                status_code=404,
            )
        error: str | None = None
        try:
            result = services.indexer.start_scan(
                evidence_id, rebuild=rebuild
            )
            status = result.status
        except USER_ERRORS as exc:
            logger.warning("index start rejected: %s", exc)
            status = index_status(record)
            error = str(exc)
        if request.headers.get("hx-request") != "true":
            return RedirectResponse(
                url=f"/evidence/{evidence_id}", status_code=303
            )
        return render(
            request,
            "partials/index_status.html",
            {"status": status, "error": error, "auto_index": settings.auto_index},
        )

    @app.get(
        "/evidence/{evidence_id}/entries", response_class=HTMLResponse
    )
    def all_entries(
        request: Request,
        evidence_id: str,
        path: str = "",
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return index_required(
                    request,
                    status,
                    "The recursive file table requires a ready filesystem index.",
                )
            result = services.indexer.list_all_under(
                record,
                path,
                page=page,
                page_size=page_size,
                sort=sort,
                sort_dir=sort_dir,
            )
            _paginate(result, evidence_id, "entries", {"path": path})
            return render(
                request,
                "partials/entries_table.html",
                {
                    "result": result,
                    "evidence_id": evidence_id,
                    "status": status,
                    "title": (
                        f"All entries under /{path}" if path else "All entries"
                    ),
                    "mode": "all",
                    "error": None,
                },
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )

    @app.get(
        "/evidence/{evidence_id}/deleted", response_class=HTMLResponse
    )
    def deleted_entries(
        request: Request,
        evidence_id: str,
        include_directories: bool = False,
        extension: str | None = None,
        q: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return index_required(
                    request,
                    status,
                    "The Deleted Files view requires a ready filesystem index.",
                )
            form = {
                "include_directories": include_directories,
                "extension": extension or "",
                "q": q or "",
                "sort": sort,
                "sort_dir": sort_dir,
            }
            error = None
            result = None
            try:
                query = DeletedFilesQuery.create(
                    include_directories=include_directories,
                    extension=extension,
                    search=q,
                    page=page,
                    page_size=page_size,
                    sort=sort,
                    sort_dir=sort_dir,
                    default_page_size=settings.index_page_size_default,
                    max_page_size=settings.index_page_size_max,
                )
                result = services.indexer.list_deleted(record, query)
                _paginate(
                    result,
                    evidence_id,
                    "deleted",
                    {
                        "include_directories": include_directories,
                        "extension": extension or "",
                        "q": q or "",
                    },
                )
            except USER_ERRORS as exc:
                error = str(exc)
            return render(
                request,
                "partials/deleted.html",
                {
                    "result": result,
                    "error": error,
                    "status": status,
                    "evidence_id": evidence_id,
                    "form": form,
                    "mode": "deleted",
                },
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )

    @app.get(
        "/evidence/{evidence_id}/search", response_class=HTMLResponse
    )
    def search_entries(
        request: Request,
        evidence_id: str,
        q: str = "",
        exact: bool = False,
        extension: str | None = None,
        deleted_only: bool = False,
        allocated_only: bool = False,
        entry_type: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return index_required(
                    request,
                    status,
                    "Search requires a ready filesystem index.",
                )
            form = {
                "q": q,
                "exact": exact,
                "extension": extension or "",
                "deleted_only": deleted_only,
                "allocated_only": allocated_only,
                "entry_type": entry_type or "",
                "sort": sort,
                "sort_dir": sort_dir,
            }
            error = None
            result = None
            if q.strip():
                try:
                    query = FileSearchQuery.create(
                        query=q,
                        exact=exact,
                        extension=extension,
                        deleted_only=deleted_only,
                        allocated_only=allocated_only,
                        entry_type=entry_type,
                        page=page,
                        page_size=page_size,
                        sort=sort,
                        sort_dir=sort_dir,
                        default_page_size=settings.index_page_size_default,
                        max_page_size=settings.index_page_size_max,
                    )
                    result = services.indexer.search(record, query)
                    _paginate(
                        result,
                        evidence_id,
                        "search",
                        {
                            "q": q,
                            "exact": exact,
                            "extension": extension or "",
                            "deleted_only": deleted_only,
                            "allocated_only": allocated_only,
                            "entry_type": entry_type or "",
                        },
                    )
                except USER_ERRORS as exc:
                    error = str(exc)
            return render(
                request,
                "partials/search.html",
                {
                    "result": result,
                    "error": error,
                    "status": status,
                    "evidence_id": evidence_id,
                    "form": form,
                    "mode": "search",
                },
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )

    # ------------------------------------------------------------------
    # Filesystem tree (explorer-style, lazy loaded from the SQLite index)
    # ------------------------------------------------------------------

    def tree_available(
        request: Request, record: EvidenceRecord
    ) -> tuple[IndexStatus, HTMLResponse | None]:
        status = index_status(record)
        if services.indexer.is_queryable(status):
            return status, None
        return status, render(
            request,
            "partials/tree_unavailable.html",
            {"status": status},
        )

    @app.get("/evidence/{evidence_id}/tree", response_class=HTMLResponse)
    def tree_view(
        request: Request,
        evidence_id: str,
        entry_id: int | None = None,
        include_deleted: bool = True,
        directories_only: bool = False,
        path: str | None = None,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/error.html",
                {"error": str(exc)},
                status_code=404,
            )
        status = index_status(record)
        if not services.indexer.is_queryable(status):
            return render(
                request, "partials/tree_unavailable.html", {"status": status}
            )
        selected: dict[str, Any] | None = None
        if entry_id:
            try:
                entry = services.indexer.tree_entry(record, entry_id)
                selected = entry.to_tree_node().to_dict()
            except USER_ERRORS as exc:
                selected = {"error": str(exc)}
        elif path:
            try:
                resolved = services.indexer.resolve_entry_path(record, path)
                selected = resolved.to_tree_node().to_dict()
            except USER_ERRORS as exc:
                selected = {"error": str(exc)}
        return render(
            request,
            "partials/tree_explorer.html",
            {
                "record": record,
                "status": status,
                "auto_index": settings.auto_index,
                "include_deleted": include_deleted,
                "directories_only": directories_only,
                "selected": selected,
            },
        )

    @app.get("/evidence/{evidence_id}/tree/children")
    def tree_children(
        request: Request,
        evidence_id: str,
        parent_id: str = "0",
        include_deleted: bool = True,
        directories_only: bool = False,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
        filter: str | None = None,
    ) -> JSONResponse:
        try:
            record = get_record(evidence_id)
        except USER_ERRORS as exc:
            return JSONResponse(
                {"ok": False, "error": _error_payload(exc)}, status_code=404
            )
        status = index_status(record)
        if not services.indexer.is_queryable(status):
            return JSONResponse(
                {
                    "ok": False,
                    "error": _not_ready_payload(status),
                },
                status_code=409,
            )
        try:
            result = services.indexer.tree_page(
                record,
                parent_id,
                include_deleted=include_deleted,
                directories_only=directories_only,
                filter_text=filter,
                page=page,
                page_size=page_size,
                sort=sort,
                sort_dir=sort_dir,
            )
            payload = result.to_dict()
            entry_ids = [child["entry_id"] for child in payload["children"]]
            try:
                latest = services.triage.latest_for_entries(
                    record.evidence_id, entry_ids
                )
            except Exception:  # noqa: BLE001 - badge enrichment is optional
                latest = {}
            for child in payload["children"]:
                info = latest.get(child["entry_id"])
                if info:
                    child["triage"] = info
            payload["ok"] = True
            return JSONResponse(payload)
        except USER_ERRORS as exc:
            return JSONResponse(
                {"ok": False, "error": _error_payload(exc)}, status_code=400
            )

    @app.get("/evidence/{evidence_id}/tree/reveal")
    def tree_reveal(
        request: Request, evidence_id: str, entry_id: str
    ) -> JSONResponse:
        try:
            record = get_record(evidence_id)
        except USER_ERRORS as exc:
            return JSONResponse(
                {"ok": False, "error": _error_payload(exc)}, status_code=404
            )
        status = index_status(record)
        if not services.indexer.is_queryable(status):
            return JSONResponse(
                {"ok": False, "error": _not_ready_payload(status)},
                status_code=409,
            )
        try:
            payload = services.indexer.tree_reveal(record, entry_id)
            payload["ok"] = True
            return JSONResponse(payload)
        except USER_ERRORS as exc:
            return JSONResponse(
                {"ok": False, "error": _error_payload(exc)}, status_code=400
            )

    # ------------------------------------------------------------------
    # read-only file content preview
    # ------------------------------------------------------------------

    def _registry_link(record, entry) -> dict[str, Any] | None:
        """Describe registry-hive actions for one entry without parsing it."""
        if entry is None or entry.entry_type != "file":
            return None
        candidate = None
        try:
            candidate = classify_hive_entry(entry, evidence_id=record.evidence_id)
        except Exception:  # noqa: BLE001 - classification is best effort
            candidate = None
        indexed = None
        try:
            indexed = services.registry_browser.store.find_hive_by_entry(
                record.evidence_id, entry.id
            )
        except Exception:  # noqa: BLE001 - registry index is optional
            indexed = None
        if candidate is None and indexed is None:
            return None
        hive_type = (
            indexed.hive_type
            if indexed is not None
            else (candidate.hive_type if candidate else "other")
        )
        state = indexed.state if indexed is not None else None
        return {
            "is_hive": True,
            "hive_id": indexed.hive_id if indexed is not None else None,
            "hive_type": hive_type,
            "state": state,
            "openable": state in {"ready", "partial"},
            "key_count": indexed.key_count if indexed is not None else None,
            "value_count": indexed.value_count if indexed is not None else None,
            "sensitive": bool(
                indexed.sensitive if indexed is not None else candidate.sensitive
            ),
            "evidence_id": record.evidence_id,
            "entry_id": entry.id,
        }

    def _preview_payload(
        record, entry_id: str, mode: str, offset: int, limit: int | None
    ) -> dict[str, Any]:
        result = services.preview.preview(
            record, entry_id, mode=mode, offset=offset, limit=limit
        )
        return result.to_dict()

    @app.get("/evidence/{evidence_id}/entries/{entry_id}/preview")
    def entry_preview_json(
        evidence_id: str,
        entry_id: str,
        offset: int = 0,
        limit: int | None = None,
        mode: str = "auto",
    ) -> JSONResponse:
        try:
            record = get_record(evidence_id)
            payload = _preview_payload(record, entry_id, mode, offset, limit)
        except USER_ERRORS as exc:
            code = getattr(exc, "code", "")
            not_found = code.endswith("not_found") or code.endswith("not_found_error")
            status_code = 404 if not_found else 400
            return JSONResponse(
                {"ok": False, "error": _error_payload(exc)},
                status_code=status_code,
            )
        payload["ok"] = True
        return JSONResponse(payload)

    @app.get(
        "/evidence/{evidence_id}/entries/{entry_id}/preview/panel",
        response_class=HTMLResponse,
    )
    def entry_preview_panel(
        request: Request,
        evidence_id: str,
        entry_id: str,
        offset: int = 0,
        limit: int | None = None,
        mode: str = "auto",
    ) -> HTMLResponse:
        context: dict[str, Any] = {
            "evidence_id": evidence_id,
            "entry_id": entry_id,
            "render_offset": offset,
            "render_limit": limit,
            "mode": mode,
            "preview": None,
            "error": None,
            "error_code": None,
        }
        try:
            record = get_record(evidence_id)
            payload = _preview_payload(record, entry_id, mode, offset, limit)
            context["preview"] = payload
            context["entry"] = services.indexer.tree_entry(record, entry_id)
            context["registry"] = _registry_link(record, context["entry"])
        except USER_ERRORS as exc:
            context["error"] = str(exc)
            context["error_code"] = getattr(exc, "code", "preview_error")
        return render(request, "partials/preview_panel.html", context)

    @app.get(
        "/evidence/{evidence_id}/entry/{entry_id}", response_class=HTMLResponse
    )
    def tree_entry_panel(
        request: Request,
        evidence_id: str,
        entry_id: str,
        include_deleted: bool = True,
        directories_only: bool = False,
        page: int = 1,
        page_size: int | None = None,
        sort: str = "path",
        sort_dir: str = "asc",
        filter: str | None = None,
        reveal: int = 0,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return render(
                    request,
                    "partials/tree_unavailable.html",
                    {"status": status},
                )
            if entry_id == "0":
                root_page = services.indexer.tree_page(
                    record,
                    0,
                    include_deleted=include_deleted,
                    directories_only=directories_only,
                    filter_text=filter,
                    page=page,
                    page_size=page_size,
                    sort=sort,
                    sort_dir=sort_dir,
                )
                _attach_tree_urls(
                    root_page,
                    evidence_id,
                    0,
                    include_deleted=include_deleted,
                    directories_only=directories_only,
                    filter_text=filter,
                )
                volume_name = record.layout.details.get(
                    "volume_name"
                ) or record.filename
                return render(
                    request,
                    "partials/tree_directory.html",
                    {
                        "entry": {
                            "entry_id": 0,
                            "name": volume_name,
                            "path": "/",
                            "type": "directory",
                            "allocated": True,
                            "deleted": False,
                            "mft": record.layout.details.get("root_inode"),
                        },
                        "page": root_page,
                        "reveal": bool(reveal),
                        "is_root": True,
                    },
                )
            entry = services.indexer.tree_entry(record, entry_id)
            if entry.entry_type == "directory":
                page_result = services.indexer.tree_page(
                    record,
                    entry.id,
                    include_deleted=include_deleted,
                    directories_only=directories_only,
                    filter_text=filter,
                    page=page,
                    page_size=page_size,
                    sort=sort,
                    sort_dir=sort_dir,
                )
                _attach_tree_urls(
                    page_result,
                    evidence_id,
                    entry.id,
                    include_deleted=include_deleted,
                    directories_only=directories_only,
                    filter_text=filter,
                )
                return render(
                    request,
                    "partials/tree_directory.html",
                    {
                        "entry": entry.to_tree_node().to_dict(),
                        "page": page_result,
                        "reveal": bool(reveal),
                    },
                )
            metadata = None
            metadata_error = None
            if entry.backend_type != "ad1":
                try:
                    exposure = services.evidence.ensure_image(record)
                    metadata = services.filesystem.stat(
                        exposure,
                        record.evidence_id,
                        inode=entry.inode,
                        offset_sectors=record.layout.offset_sectors,
                    )
                except USER_ERRORS as exc:
                    metadata_error = str(exc)
            latest_triage = None
            try:
                latest_triage = services.triage.latest_for_entry(
                    record.evidence_id, entry.id
                )
            except Exception:  # noqa: BLE001 - triage badge is optional
                latest_triage = None
            context = {
                "record": record,
                "entry": entry.to_dict(),
                "reveal": bool(reveal),
                "metadata": metadata,
                "metadata_error": metadata_error,
                "latest_triage": latest_triage,
                "registry_link": _registry_link(record, entry),
                "preview_default_limit": services.settings.preview_default_limit,
                "related": (services.investigation.related(record.evidence_id, entry.id)
                            if getattr(services, "investigation", None) else {"items": [], "sources": {}}),
            }
            try:
                context.update(_vt_context(record, entry))
            except USER_ERRORS:
                pass
            return render(request, "partials/tree_file.html", context)
        except EntryNotFoundError as exc:
            return render(
                request,
                "partials/tree_entry_error.html",
                {"error": str(exc)},
                status_code=404,
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/tree_entry_error.html",
                {"error": str(exc)},
                status_code=400,
            )

    @app.get("/evidence/{evidence_id}/related/{entry_id}")
    def related_artifacts(evidence_id: str, entry_id: int, limit: int = 100):
        return services.investigation.related(evidence_id, entry_id, limit)

    @app.get("/evidence/{evidence_id}/timeline", response_class=HTMLResponse)
    def timeline_panel(request: Request, evidence_id: str, page: int = 1,
                       source: str | None = None, kind: str | None = None,
                       keyword: str | None = None, time_from: str | None = None,
                       time_to: str | None = None, path: str | None = None,
                       hash_value: str | None = None):
        status = services.investigation.status(evidence_id)
        result = services.investigation.query(evidence_id, page=page, source=source, kind=kind, keyword=keyword,
                                              time_from=time_from, time_to=time_to, path=path, hash_value=hash_value)
        return render(request, "partials/timeline.html", {"evidence_id": evidence_id, "status": status, "result": result,
                      "filters": {"source": source or "", "kind": kind or "", "keyword": keyword or ""}})

    @app.post("/evidence/{evidence_id}/timeline/index")
    def timeline_start(evidence_id: str, rebuild: bool = False):
        return services.investigation.start(evidence_id, rebuild)

    @app.get("/evidence/{evidence_id}/timeline/status")
    def timeline_status(evidence_id: str):
        return services.investigation.status(evidence_id)

    @app.get("/evidence/{evidence_id}/timeline/query")
    def timeline_query(evidence_id: str, time_from: str | None = None, time_to: str | None = None,
                       source: str | None = None, kind: str | None = None, keyword: str | None = None,
                       path: str | None = None, hash_value: str | None = None, page: int = 1,
                       page_size: int = 100, sort: str = "desc"):
        return services.investigation.query(evidence_id, time_from=time_from, time_to=time_to,
            source=source, kind=kind, keyword=keyword, path=path, hash_value=hash_value,
            page=page, page_size=page_size, sort=sort)

    @app.get("/evidence/{evidence_id}/timeline/event/{event_id}")
    def timeline_event(evidence_id: str, event_id: str):
        return services.investigation.event(evidence_id, event_id)

    @app.get("/registry/amcache/{hive_id}/{record_id}", response_class=HTMLResponse)
    def amcache_record_page(request: Request, hive_id: str, record_id: int):
        payload = services.registry_browser.amcache_record(hive_id, record_id)
        return render(request, "partials/amcache_record.html", {"record": payload})

    @app.post(
        "/evidence/{evidence_id}/entry/{entry_id}/extract",
        response_class=HTMLResponse,
    )
    def tree_entry_extract(
        request: Request,
        evidence_id: str,
        entry_id: str,
        case_id: str = Form(...),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            entry = services.indexer.tree_entry(record, entry_id)
            if entry.entry_type == "directory":
                raise DFIRError(
                    "refusing to extract a directory as a file",
                    code="directory_extraction",
                )
            if entry.inode is None and entry.backend_type != "ad1":
                raise DFIRError(
                    "this entry has no MFT/inode and cannot be extracted",
                    code="entry_without_inode",
                )
            result = services.filesystem.extract_entry(record, entry, case_id)
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/extract.html",
                {"result": None, "error": str(exc)},
            )
        return render(
            request,
            "partials/extract.html",
            {"result": result, "error": None},
        )

    # ------------------------------------------------------------------
    # static file triage (read-only extracted copy, background jobs)
    # ------------------------------------------------------------------

    def _triage_entry(record, entry_id: str):
        return services.indexer.tree_entry(record, int(entry_id))

    def _triage_render(
        request: Request,
        job_id: str,
        *,
        strings_page: int = 1,
        strings_page_size: int = 50,
        status_code: int = 200,
    ) -> HTMLResponse:
        result = services.triage.result(job_id)
        job = result["job"]
        entry = None
        try:
            record = services.evidence.get(job["evidence_id"])
            entry = services.indexer.tree_entry(
                record, job["entry_id"]
            ).to_dict()
        except USER_ERRORS:
            entry = None
        strings = None
        if job["status"] in ("complete", "partial"):
            try:
                strings = services.triage.strings(
                    job_id,
                    page=strings_page,
                    page_size=strings_page_size,
                )
            except USER_ERRORS:
                strings = None
        latest_triage = None
        summary_entry = entry
        summary_record = None
        if entry is not None:
            try:
                summary_record = services.evidence.get(job["evidence_id"])
                latest_triage = services.triage.latest_for_entry(
                    job["evidence_id"], job["entry_id"]
                )
            except USER_ERRORS:
                latest_triage = None
        return render(
            request,
            "partials/triage_job.html",
            {
                "job": job,
                "entry": entry,
                "result": result,
                "strings": strings,
                "latest_triage": latest_triage,
                "summary_entry": summary_entry,
                "summary_record": summary_record,
            },
            status_code=status_code,
        )

    @app.get(
        "/evidence/{evidence_id}/entries/{entry_id}/triage/panel",
        response_class=HTMLResponse,
    )
    def triage_panel(
        request: Request, evidence_id: str, entry_id: str
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return render(
                    request,
                    "partials/tree_unavailable.html",
                    {"status": status},
                )
            entry = services.indexer.tree_entry(record, int(entry_id))
            latest = services.triage.latest_for_entry(
                record.evidence_id, entry.id
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/tree_entry_error.html",
                {"error": str(exc)},
                status_code=400,
            )
        context = {
            "record": record,
            "entry": entry.to_dict(),
            "latest_triage": latest,
        }
        try:
            context.update(_vt_context(record, entry))
        except USER_ERRORS:
            pass
        return render(request, "partials/triage_panel.html", context)

    @app.post(
        "/evidence/{evidence_id}/entries/{entry_id}/triage",
        response_class=HTMLResponse,
    )
    def start_triage(
        request: Request,
        evidence_id: str,
        entry_id: str,
        case_id: str = Form("case01"),
        force: str = Form("0"),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            job = services.triage.start(
                record,
                int(entry_id),
                case_id=case_id,
                force=str(force).lower() in {"1", "true", "yes", "on"},
            )
        except USER_ERRORS as exc:
            logger.warning("triage start rejected: %s", exc)
            return render(
                request,
                "partials/triage_start_error.html",
                {"error": str(exc)},
                status_code=400,
            )
        if request.headers.get("hx-request") != "true":
            return RedirectResponse(
                url=f"/evidence/{evidence_id}?entry={job.entry_id}",
                status_code=303,
            )
        return _triage_render(request, job.job_id)

    @app.get("/triage/jobs/{job_id}", response_class=HTMLResponse)
    def triage_job(
        request: Request,
        job_id: str,
        page: int = 1,
        page_size: int = 50,
    ) -> HTMLResponse:
        try:
            return _triage_render(
                request,
                job_id,
                strings_page=page,
                strings_page_size=page_size,
            )
        except TriageNotFoundError as exc:
            return render(
                request,
                "partials/triage_job_missing.html",
                {"error": str(exc)},
                status_code=404,
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/triage_job_missing.html",
                {"error": str(exc)},
                status_code=400,
            )

    @app.get("/triage/jobs/{job_id}/results", response_class=HTMLResponse)
    def triage_results(
        request: Request,
        job_id: str,
        page: int = 1,
        page_size: int = 50,
    ) -> HTMLResponse:
        return triage_job(request, job_id, page, page_size)

    @app.get(
        "/triage/jobs/{job_id}/strings", response_class=HTMLResponse
    )
    def triage_strings(
        request: Request,
        job_id: str,
        page: int = 1,
        page_size: int = 50,
        encoding: str | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        try:
            strings = services.triage.strings(
                job_id,
                page=page,
                page_size=page_size,
                encoding=encoding or None,
                query=q,
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/triage_job_missing.html",
                {"error": str(exc)},
                status_code=400,
            )
        return render(
            request, "partials/triage_strings.html", {"strings": strings}
        )

    # ------------------------------------------------------------------
    # VirusTotal hash lookup (hash only; never uploads evidence)
    # ------------------------------------------------------------------

    def _vt_context(record, entry) -> dict[str, Any]:
        vt_hash = None
        try:
            vt_hash = services.virustotal.known_hash_for_entry(
                record.evidence_id, entry.id
            )
        except USER_ERRORS:
            vt_hash = None
        cached = None
        if vt_hash:
            try:
                cached = services.virustotal.cached_result(vt_hash)
            except USER_ERRORS:
                cached = None
        return {
            "record": record,
            "entry": entry.to_dict(),
            "vt_status": services.virustotal.status(),
            "vt_hash": vt_hash,
            "vt_result": cached,
            "vt_error": None,
        }

    @app.get("/settings/integrations", response_class=HTMLResponse)
    def integrations_page(request: Request) -> HTMLResponse:
        return render(
            request,
            "settings.html",
            {"vt_status": services.virustotal.status(), "notice": None},
        )

    @app.post(
        "/settings/integrations/virustotal", response_class=HTMLResponse
    )
    def save_virustotal_key(
        request: Request,
        api_key: str = Form(""),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        notice = "VirusTotal API key saved."
        status = None
        try:
            status = services.virustotal.save_key(api_key)
        except USER_ERRORS as exc:
            notice = f"Could not save the key: {exc}"
        return render(
            request,
            "partials/virustotal_settings.html",
            {
                "vt_status": status or services.virustotal.status(),
                "notice": notice,
            },
        )

    @app.post(
        "/settings/integrations/virustotal/remove",
        response_class=HTMLResponse,
    )
    def remove_virustotal_key(
        request: Request, csrf_token: str | None = Form(None)
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        notice = "Stored VirusTotal key removed."
        status = None
        try:
            status = services.virustotal.remove_key()
        except USER_ERRORS as exc:
            notice = f"Could not remove the key: {exc}"
        return render(
            request,
            "partials/virustotal_settings.html",
            {
                "vt_status": status or services.virustotal.status(),
                "notice": notice,
            },
        )

    @app.post(
        "/settings/integrations/virustotal/test",
        response_class=HTMLResponse,
    )
    def test_virustotal_key(
        request: Request,
        hash_value: str = Form(""),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            result = services.virustotal.lookup_hash(hash_value)
        except VirusTotalError as exc:
            return render(
                request,
                "partials/virustotal_error.html",
                {"vt_error": exc.to_dict()},
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/virustotal_error.html",
                {
                    "vt_error": {
                        "code": "virustotal_error",
                        "message": str(exc),
                        "details": {},
                    }
                },
            )
        return render(
            request,
            "partials/virustotal_report.html",
            {"vt_result": result},
        )

    def _vt_entry(evidence_id: str, entry_id: str):
        record = get_record(evidence_id)
        entry = services.indexer.tree_entry(record, int(entry_id))
        return record, entry

    @app.post(
        "/evidence/{evidence_id}/entries/{entry_id}/virustotal",
        response_class=HTMLResponse,
    )
    def virustotal_lookup(
        request: Request,
        evidence_id: str,
        entry_id: str,
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        return _run_virustotal_lookup(
            request, evidence_id, entry_id, csrf_token, force_refresh=False
        )

    @app.post(
        "/evidence/{evidence_id}/entries/{entry_id}/virustotal/refresh",
        response_class=HTMLResponse,
    )
    def virustotal_refresh(
        request: Request,
        evidence_id: str,
        entry_id: str,
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        return _run_virustotal_lookup(
            request, evidence_id, entry_id, csrf_token, force_refresh=True
        )

    @app.get(
        "/evidence/{evidence_id}/entries/{entry_id}/virustotal",
        response_class=HTMLResponse,
    )
    def virustotal_panel(
        request: Request, evidence_id: str, entry_id: str
    ) -> HTMLResponse:
        try:
            record, entry = _vt_entry(evidence_id, entry_id)
            if entry.entry_type != "file":
                raise DFIRError(
                    "VirusTotal lookup only applies to files",
                    code="virustotal_directory_rejected",
                )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/tree_entry_error.html",
                {"error": str(exc)},
                status_code=400,
            )
        return render(
            request, "partials/virustotal_panel.html", _vt_context(record, entry)
        )

    def _run_virustotal_lookup(
        request: Request,
        evidence_id: str,
        entry_id: str,
        csrf_token: str | None,
        *,
        force_refresh: bool,
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record, entry = _vt_entry(evidence_id, entry_id)
            result = services.virustotal.lookup_entry(
                record, entry.id, force_refresh=force_refresh
            )
        except VirusTotalError as exc:
            try:
                record, entry = _vt_entry(evidence_id, entry_id)
                context = _vt_context(record, entry)
            except USER_ERRORS:
                context = {
                    "record": None,
                    "entry": {"entry_id": int(entry_id) if entry_id.isdigit() else 0},
                    "vt_status": services.virustotal.status(),
                    "vt_hash": None,
                    "vt_result": None,
                }
            context["vt_error"] = exc.to_dict()
            return render(
                request, "partials/virustotal_panel.html", context
            )
        except USER_ERRORS as exc:
            try:
                record, entry = _vt_entry(evidence_id, entry_id)
                context = _vt_context(record, entry)
            except USER_ERRORS:
                context = {
                    "record": None,
                    "entry": {"entry_id": int(entry_id) if entry_id.isdigit() else 0},
                    "vt_status": services.virustotal.status(),
                    "vt_hash": None,
                    "vt_result": None,
                }
            context["vt_error"] = {
                "code": "virustotal_error",
                "message": str(exc),
                "details": {},
            }
            return render(
                request, "partials/virustotal_panel.html", context
            )
        record, entry = _vt_entry(evidence_id, entry_id)
        context = _vt_context(record, entry)
        context["vt_hash"] = result.get("hash")
        context["vt_result"] = result
        return render(
            request, "partials/virustotal_panel.html", context
        )

    # ------------------------------------------------------------------
    # registry hive browser and Amcache
    # ------------------------------------------------------------------

    def _registry_json_error(exc: Exception, status_code: int = 400) -> JSONResponse:
        payload = _error_payload(exc)
        return JSONResponse({"ok": False, "error": payload}, status_code=status_code)

    def _registry_hive(hive_id: str):
        return services.registry_browser.status(hive_id)

    @app.get(
        "/evidence/{evidence_id}/registry", response_class=HTMLResponse
    )
    def registry_tab(
        request: Request,
        evidence_id: str,
        include_deleted: bool = False,
        page: int = 1,
        highlight: int | None = None,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return render(
                    request,
                    "partials/index_required.html",
                    {
                        "status": status,
                        "message": "Registry hives require a ready filesystem index.",
                    },
                )
            result = services.registry_browser.list_hives(
                record, include_deleted=include_deleted, page=page
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/registry.html",
            {
                "record": record,
                "result": result,
                "include_deleted": include_deleted,
                "highlight": highlight,
            },
        )

    @app.post(
        "/evidence/{evidence_id}/registry/{entry_id}/index",
        response_class=HTMLResponse,
    )
    def registry_index_start(
        request: Request,
        evidence_id: str,
        entry_id: str,
        recover_with_logs: str = Form("0"),
        rebuild: str = Form("0"),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            result = services.registry_browser.start_index(
                record,
                int(entry_id),
                recover_with_logs=str(recover_with_logs).lower()
                in {"1", "true", "on"},
                rebuild=str(rebuild).lower() in {"1", "true", "on"},
            )
        except USER_ERRORS as exc:
            logger.warning("registry index start rejected: %s", exc)
            return render(
                request,
                "partials/registry_status.html",
                {
                    "hive": {
                        "hive_id": "",
                        "state": "failed",
                        "phase": "ready",
                        "error_message": str(exc),
                        "error_code": getattr(exc, "code", "registry_error"),
                    },
                    "start_error": str(exc),
                },
            )
        if request.headers.get("hx-request") != "true":
            return RedirectResponse(
                url=f"/evidence/{evidence_id}?tab=registry", status_code=303
            )
        return render(
            request,
            "partials/registry_status.html",
            {"hive": result["hive"], "started": result["started"], "cached": result["cached"]},
        )

    @app.get(
        "/registry/hives/{hive_id}/status", response_class=HTMLResponse
    )
    def registry_hive_status(request: Request, hive_id: str) -> HTMLResponse:
        try:
            hive = _registry_hive(hive_id)
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/registry_status.html",
                {"hive": None, "start_error": str(exc)},
                status_code=404,
            )
        return render(
            request,
            "partials/registry_status.html",
            {"hive": hive.to_dict()},
        )

    @app.get("/registry/hives/{hive_id}", response_class=HTMLResponse)
    def registry_hive_browser(
        request: Request, hive_id: str
    ) -> HTMLResponse:
        try:
            hive = _registry_hive(hive_id)
            if hive.state not in {"ready", "partial"}:
                return render(
                    request,
                    "partials/registry_status.html",
                    {"hive": hive.to_dict()},
                )
            root = services.registry_store.root_key(hive_id)
            try:
                record = services.evidence.get(hive.evidence_id)
            except USER_ERRORS:
                record = None
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/error.html",
                {"error": str(exc)},
                status_code=404,
            )
        return render(
            request,
            "partials/registry_browser.html",
            {
                "hive": hive.to_dict(),
                "root": root.to_dict(),
                "record": record,
                "vt_configured": services.virustotal.status()["configured"],
            },
        )

    @app.get("/registry/hives/{hive_id}/keys")
    def registry_keys(
        request: Request,
        hive_id: str,
        parent_key_id: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> JSONResponse:
        try:
            parent_id = (
                int(parent_key_id)
                if parent_key_id not in (None, "")
                else None
            )
            result = services.registry_browser.list_subkeys(
                hive_id,
                parent_key_id=parent_id,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            return _registry_json_error(exc)
        payload = result.to_dict()
        payload["ok"] = True
        return JSONResponse(payload)

    @app.get(
        "/registry/hives/{hive_id}/key/{key_id}",
        response_class=HTMLResponse,
    )
    def registry_key_detail(
        request: Request,
        hive_id: str,
        key_id: str,
        preview: int | None = None,
    ) -> HTMLResponse:
        try:
            detail = services.registry_browser.get_key(
                hive_id,
                int(key_id),
                include_values=True,
                binary_preview_bytes=preview,
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}
            )
        return render(
            request, "partials/registry_key.html", {"detail": detail}
        )

    @app.get(
        "/registry/hives/{hive_id}/search", response_class=HTMLResponse
    )
    def registry_search(
        request: Request,
        hive_id: str,
        q: str = "",
        keys: bool = True,
        value_names: bool = True,
        strings: bool = True,
        exact: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        result = None
        error = None
        if q.strip():
            try:
                result = services.registry_browser.search(
                    hive_id,
                    q,
                    search_key_names=keys,
                    search_value_names=value_names,
                    search_string_values=strings,
                    exact=exact,
                    page=page,
                    page_size=page_size,
                )
            except USER_ERRORS as exc:
                error = str(exc)
        return render(
            request,
            "partials/registry_search.html",
            {
                "hive_id": hive_id,
                "result": result,
                "error": error,
                "form": {
                    "q": q,
                    "keys": keys,
                    "value_names": value_names,
                    "strings": strings,
                    "exact": exact,
                },
            },
        )

    @app.get(
        "/registry/hives/{hive_id}/reveal"
    )
    def registry_reveal(
        request: Request, hive_id: str, key_id: int
    ) -> JSONResponse:
        try:
            hive = services.registry_browser.status(hive_id)
            if hive.state not in {"ready", "partial"}:
                raise HiveNotReadyError(
                    "registry hive is not ready",
                    details={"hive_id": hive_id, "state": hive.state},
                )
            ancestors = services.registry_store.key_ancestors(hive_id, key_id)
            key = services.registry_store.get_key(hive_id, key_id, 0).key
        except USER_ERRORS as exc:
            return _registry_json_error(exc)
        return JSONResponse(
            {
                "ok": True,
                "hive_id": hive_id,
                "key": key.to_dict(),
                "ancestors": [node.to_dict() for node in ancestors],
                "trust": "untrusted_evidence_data",
            }
        )

    @app.get(
        "/registry/hives/{hive_id}/amcache", response_class=HTMLResponse
    )
    def registry_amcache(
        request: Request,
        hive_id: str,
        q: str = "",
        exact: bool = False,
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        result = services.registry_browser.amcache_search(
            hive_id, q, exact=exact, page=page, page_size=page_size
        ) if q.strip() else None
        return render(
            request,
            "partials/registry_amcache.html",
            {
                "hive_id": hive_id,
                "result": result,
                "form": {"q": q, "exact": exact},
                "vt_configured": services.virustotal.status()["configured"],
            },
        )

    @app.post(
        "/registry/hives/{hive_id}/amcache/{record_id}/compare",
        response_class=HTMLResponse,
    )
    def registry_amcache_compare(
        request: Request,
        hive_id: str,
        record_id: str,
        entry_id: str = Form(...),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            hive = services.registry_browser.status(hive_id)
            record = services.evidence.get(hive.evidence_id)
            result = services.registry_browser.compare_triage(
                record, hive_id, int(record_id), int(entry_id)
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/registry_compare.html",
                {"compare": None, "error": str(exc)},
            )
        return render(
            request,
            "partials/registry_compare.html",
            {"compare": result.to_dict(), "error": None},
        )

    @app.post(
        "/registry/hives/{hive_id}/amcache/{record_id}/virustotal",
        response_class=HTMLResponse,
    )
    def registry_amcache_virustotal(
        request: Request,
        hive_id: str,
        record_id: str,
        force: str = Form("0"),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            hive = services.registry_browser.status(hive_id)
            record = services.evidence.get(hive.evidence_id)
            result = services.registry_browser.amcache_lookup_virustotal(
                record,
                hive_id,
                int(record_id),
                force_refresh=str(force).lower() in {"1", "true", "on"},
            )
        except USER_ERRORS as exc:
            return render(
                request,
                "partials/virustotal_error.html",
                {"vt_error": _error_payload(exc)},
            )
        return render(
            request,
            "partials/virustotal_report.html",
            {"vt_result": result},
        )

    # ------------------------------------------------------------------
    # Windows event log (EVTX) explorer
    # ------------------------------------------------------------------

    def _evtx_status_context(log_id: str) -> dict[str, Any]:
        try:
            log = services.evtx.status(log_id)
        except USER_ERRORS as exc:
            return {"log": None, "start_error": str(exc)}
        return {"log": log.to_dict(), "start_error": None}

    @app.get(
        "/evidence/{evidence_id}/event-logs", response_class=HTMLResponse
    )
    def event_logs_tab(
        request: Request,
        evidence_id: str,
        include_deleted: bool = False,
        indexed_only: bool = False,
        page: int = 1,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return render(
                    request,
                    "partials/index_required.html",
                    {
                        "status": status,
                        "message": "Event log discovery requires a ready filesystem index.",
                    },
                )
            result = services.evtx.list_logs(
                record,
                include_deleted=include_deleted,
                indexed_only=indexed_only,
                page=page,
            )
        except USER_ERRORS as exc:
            return render(request, "partials/error.html", {"error": str(exc)})
        return render(
            request,
            "partials/evtx_logs.html",
            {
                "record": record,
                "result": result,
                "include_deleted": include_deleted,
                "indexed_only": indexed_only,
                "presets": list_presets(),
            },
        )

    @app.post(
        "/evidence/{evidence_id}/event-logs/{entry_id}/index",
        response_class=HTMLResponse,
    )
    def event_log_index(
        request: Request,
        evidence_id: str,
        entry_id: str,
        rebuild: str = Form("0"),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            result = services.evtx.start_index(
                record,
                int(entry_id),
                rebuild=str(rebuild).lower() in {"1", "true", "on"},
            )
        except USER_ERRORS as exc:
            logger.warning("EVTX index start rejected: %s", exc)
            return render(
                request,
                "partials/evtx_status.html",
                {
                    "log": None,
                    "start_error": str(exc),
                    "record": None,
                },
            )
        log = result["log"]
        try:
            record = services.evidence.get(log["evidence_id"])
        except USER_ERRORS:
            record = None
        return render(
            request,
            "partials/evtx_status.html",
            {
                "log": log,
                "start_error": None,
                "started": result["started"],
                "cached": result["cached"],
                "record": record,
            },
        )

    @app.get(
        "/event-logs/{log_id}/status", response_class=HTMLResponse
    )
    def event_log_status(request: Request, log_id: str) -> HTMLResponse:
        context = _evtx_status_context(log_id)
        try:
            record = (
                services.evidence.get(context["log"]["evidence_id"])
                if context["log"]
                else None
            )
        except USER_ERRORS:
            record = None
        context["record"] = record
        return render(request, "partials/evtx_status.html", context)

    @app.get("/event-logs/{log_id}", response_class=HTMLResponse)
    def event_log_explorer(request: Request, log_id: str) -> HTMLResponse:
        try:
            log = services.evtx.status(log_id)
            if log.status not in {"ready", "partial"}:
                return render(
                    request,
                    "partials/evtx_status.html",
                    {"log": log.to_dict(), "start_error": None, "record": None},
                )
            record = services.evidence.get(log.evidence_id)
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}, status_code=404
            )
        return render(
            request,
            "partials/evtx_explorer.html",
            {"log": log.to_dict(), "record": record, "presets": list_presets()},
        )

    @app.get(
        "/evidence/{evidence_id}/event-logs/query", response_class=HTMLResponse
    )
    def event_log_query(
        request: Request,
        evidence_id: str,
        log_id: str | None = None,
        channel: str | None = None,
        provider: str | None = None,
        event_ids: str = "",
        level: str | None = None,
        user_sid: str | None = None,
        computer: str | None = None,
        process_id: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        q: str | None = None,
        preset: str | None = None,
        sort_dir: str = "asc",
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        form = {
            "log_id": log_id or "",
            "channel": channel or "",
            "provider": provider or "",
            "event_ids": event_ids or "",
            "level": level or "",
            "user_sid": user_sid or "",
            "computer": computer or "",
            "process_id": process_id or "",
            "time_from": time_from or "",
            "time_to": time_to or "",
            "q": q or "",
            "preset": preset or "",
            "sort_dir": sort_dir,
        }
        result = None
        error = None
        try:
            record = get_record(evidence_id)
            parsed_ids = []
            for piece in str(event_ids or "").replace(",", " ").split():
                if piece.isdigit():
                    parsed_ids.append(int(piece))
                else:
                    raise DFIRError(
                        f"invalid event id: {piece[:20]}",
                        code="evtx_invalid_event_id",
                    )
            parsed_levels = [int(level)] if level not in (None, "") else None
            result = services.evtx.query(
                record,
                log_ids=[log_id] if log_id else None,
                channels=[channel] if channel else None,
                providers=[provider] if provider else None,
                event_ids=parsed_ids or None,
                levels=parsed_levels,
                user_sid=user_sid or None,
                computer=computer or None,
                process_id=int(process_id) if process_id else None,
                time_from=time_from or None,
                time_to=time_to or None,
                text=q or None,
                preset=preset or None,
                sort_dir=sort_dir,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/evtx_events.html",
            {
                "result": result,
                "error": error,
                "form": form,
                "evidence_id": evidence_id,
                "log_id": log_id or "",
            },
        )

    @app.get(
        "/event-logs/{log_id}/events/{record_id}", response_class=HTMLResponse
    )
    def event_log_detail(
        request: Request,
        log_id: str,
        record_id: str,
        raw: int = 0,
    ) -> HTMLResponse:
        try:
            log = services.evtx.status(log_id)
            event = services.evtx.get_event(
                log_id, int(record_id), include_raw_xml=bool(raw)
            )
            record = services.evidence.get(log.evidence_id)
        except USER_ERRORS as exc:
            return render(
                request, "partials/evtx_detail_error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/evtx_detail.html",
            {
                "event": event,
                "log": log.to_dict(),
                "record": record,
                "include_raw_xml": bool(raw),
            },
        )

    @app.get(
        "/event-logs/{log_id}/events/{record_id}/context",
        response_class=HTMLResponse,
    )
    def event_log_context(
        request: Request,
        log_id: str,
        record_id: str,
        before: int | None = None,
        after: int | None = None,
    ) -> HTMLResponse:
        try:
            context = services.evtx.context(
                log_id,
                int(record_id),
                before=before if before is not None else int(services.settings.evtx_context_before),
                after=after if after is not None else int(services.settings.evtx_context_after),
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/evtx_detail_error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/evtx_context.html",
            {"context": context},
        )

    @app.get(
        "/evidence/{evidence_id}/event-logs/summary", response_class=HTMLResponse
    )
    def event_log_summary(
        request: Request,
        evidence_id: str,
        log_id: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        top_n: int = 20,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            summary = services.evtx.summary(
                record,
                log_ids=[log_id] if log_id else None,
                time_from=time_from or None,
                time_to=time_to or None,
                top_n=top_n,
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/evtx_detail_error.html", {"error": str(exc)}
            )
        return render(
            request, "partials/evtx_summary.html", {"summary": summary}
        )

    # ------------------------------------------------------------------
    # browser artifacts (WebCache / Chromium / Firefox)
    # ------------------------------------------------------------------

    def _browser_artifact_payload(artifact_id: str) -> dict[str, Any]:
        try:
            status = services.browser_artifacts.status(artifact_id)
        except USER_ERRORS as exc:
            return {"artifact": None, "start_error": str(exc)}
        return {"artifact": status, "start_error": None}

    @app.get("/evidence/{evidence_id}/browser", response_class=HTMLResponse)
    def browser_tab(
        request: Request,
        evidence_id: str,
        browser: str | None = None,
        artifact_type: str | None = None,
        include_deleted: bool = False,
        page: int = 1,
    ) -> HTMLResponse:
        try:
            record = get_record(evidence_id)
            status = index_status(record)
            if not services.indexer.is_queryable(status):
                return render(
                    request,
                    "partials/index_required.html",
                    {
                        "status": status,
                        "message": (
                            "Browser artifact discovery requires a ready "
                            "filesystem index."
                        ),
                    },
                )
            result = services.browser_artifacts.list_artifacts(
                record,
                browser=browser or None,
                artifact_type=artifact_type or None,
                include_deleted=include_deleted,
                page=page,
            )
        except USER_ERRORS as exc:
            return render(request, "partials/error.html", {"error": str(exc)})
        return render(
            request,
            "partials/browser_artifacts.html",
            {
                "record": record,
                "result": result,
                "browser": browser or "",
                "artifact_type": artifact_type or "",
                "include_deleted": include_deleted,
                "presets": services.browser_artifacts.list_presets(),
            },
        )

    @app.post(
        "/evidence/{evidence_id}/browser/{entry_id}/index",
        response_class=HTMLResponse,
    )
    def browser_index(
        request: Request,
        evidence_id: str,
        entry_id: str,
        rebuild: str = Form("0"),
        recover_sidecars: str = Form("1"),
        csrf_token: str | None = Form(None),
    ) -> HTMLResponse:
        try:
            csrf.validate(request, csrf_token)
        except CsrfRejected as exc:
            return _csrf_forbidden(exc)
        try:
            record = get_record(evidence_id)
            result = services.browser_artifacts.start_index(
                record,
                int(entry_id),
                rebuild=str(rebuild).lower() in {"1", "true", "on"},
                recover_sidecars=str(recover_sidecars).lower()
                in {"1", "true", "on"},
            )
        except USER_ERRORS as exc:
            logger.warning("browser index start rejected: %s", exc)
            return render(
                request,
                "partials/browser_status.html",
                {"artifact": None, "start_error": str(exc), "record": None},
            )
        artifact = result["artifact"]
        try:
            record = services.evidence.get(artifact["evidence_id"])
        except USER_ERRORS:
            record = None
        return render(
            request,
            "partials/browser_status.html",
            {
                "artifact": artifact,
                "start_error": None,
                "started": result["started"],
                "cached": result["cached"],
                "record": record,
            },
        )

    @app.get(
        "/browser/artifacts/{artifact_id}/status", response_class=HTMLResponse
    )
    def browser_status(request: Request, artifact_id: str) -> HTMLResponse:
        context = _browser_artifact_payload(artifact_id)
        try:
            record = (
                services.evidence.get(context["artifact"]["evidence_id"])
                if context["artifact"]
                else None
            )
        except USER_ERRORS:
            record = None
        context["record"] = record
        return render(request, "partials/browser_status.html", context)

    @app.get("/browser/artifacts/{artifact_id}", response_class=HTMLResponse)
    def browser_explorer(request: Request, artifact_id: str) -> HTMLResponse:
        try:
            artifact = services.browser_artifacts.status(artifact_id)
            if artifact["status"] not in {"ready", "partial"}:
                return render(
                    request,
                    "partials/browser_status.html",
                    {
                        "artifact": artifact,
                        "start_error": None,
                        "record": None,
                    },
                )
            record = services.evidence.get(artifact["evidence_id"])
        except USER_ERRORS as exc:
            return render(
                request, "partials/error.html", {"error": str(exc)}, status_code=404
            )
        return render(
            request,
            "partials/browser_explorer.html",
            {
                "artifact": artifact,
                "record": record,
                "presets": services.browser_artifacts.list_presets(),
            },
        )

    @app.get(
        "/evidence/{evidence_id}/browser/downloads", response_class=HTMLResponse
    )
    def browser_downloads(
        request: Request,
        evidence_id: str,
        artifact_id: str | None = None,
        q: str | None = None,
        domain: str | None = None,
        filename: str | None = None,
        extension: str | None = None,
        state: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        executable_only: int = 0,
        preset: str | None = None,
        include_query_string: int = 0,
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        form = {
            "artifact_id": artifact_id or "",
            "q": q or "",
            "domain": domain or "",
            "filename": filename or "",
            "extension": extension or "",
            "state": state or "",
            "time_from": time_from or "",
            "time_to": time_to or "",
            "executable_only": int(executable_only or 0),
            "preset": preset or "",
            "include_query_string": int(include_query_string or 0),
            "sort_dir": sort_dir,
        }
        result = None
        error = None
        try:
            get_record(evidence_id)
            profile_ids = None
            if artifact_id:
                artifact = services.browser_artifacts.status(artifact_id)
                if artifact["evidence_id"] != evidence_id:
                    raise DFIRError(
                        "artifact does not belong to this evidence",
                        code="browser_evidence_mismatch",
                    )
                profiles = services.browser_artifacts.store.list_profiles(
                    evidence_id
                )
                profile_ids = [
                    p.profile_id
                    for p in profiles
                    if p.artifact_id == artifact_id
                ]
            result = services.browser_artifacts.query_downloads(
                evidence_id,
                profile_ids=profile_ids,
                query=q or None,
                domain=domain or None,
                filename=filename or None,
                extension=extension or None,
                state=state or None,
                time_from=time_from or None,
                time_to=time_to or None,
                executable_only=bool(executable_only),
                preset=preset or None,
                include_query_string=bool(include_query_string),
                sort_dir=sort_dir,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/browser_downloads.html",
            {
                "result": result,
                "error": error,
                "form": form,
                "evidence_id": evidence_id,
            },
        )

    @app.get(
        "/evidence/{evidence_id}/browser/history", response_class=HTMLResponse
    )
    def browser_history(
        request: Request,
        evidence_id: str,
        artifact_id: str | None = None,
        q: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: int = 0,
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        form = {
            "artifact_id": artifact_id or "",
            "q": q or "",
            "domain": domain or "",
            "time_from": time_from or "",
            "time_to": time_to or "",
            "include_query_string": int(include_query_string or 0),
            "sort_dir": sort_dir,
        }
        result = None
        error = None
        try:
            get_record(evidence_id)
            profile_ids = None
            if artifact_id:
                artifact = services.browser_artifacts.status(artifact_id)
                if artifact["evidence_id"] != evidence_id:
                    raise DFIRError(
                        "artifact does not belong to this evidence",
                        code="browser_evidence_mismatch",
                    )
                profiles = services.browser_artifacts.store.list_profiles(
                    evidence_id
                )
                profile_ids = [
                    p.profile_id
                    for p in profiles
                    if p.artifact_id == artifact_id
                ]
            result = services.browser_artifacts.query_history(
                evidence_id,
                profile_ids=profile_ids,
                query=q or None,
                domain=domain or None,
                time_from=time_from or None,
                time_to=time_to or None,
                include_query_string=bool(include_query_string),
                sort_dir=sort_dir,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/browser_history.html",
            {
                "result": result,
                "error": error,
                "form": form,
                "evidence_id": evidence_id,
            },
        )

    @app.get(
        "/evidence/{evidence_id}/browser/cache", response_class=HTMLResponse
    )
    def browser_cache(
        request: Request,
        evidence_id: str,
        artifact_id: str | None = None,
        q: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: int = 0,
        sort_dir: str = "desc",
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        form = {
            "artifact_id": artifact_id or "",
            "q": q or "",
            "domain": domain or "",
            "time_from": time_from or "",
            "time_to": time_to or "",
            "include_query_string": int(include_query_string or 0),
            "sort_dir": sort_dir,
        }
        result = None
        error = None
        try:
            get_record(evidence_id)
            profile_ids = None
            if artifact_id:
                artifact = services.browser_artifacts.status(artifact_id)
                if artifact["evidence_id"] != evidence_id:
                    raise DFIRError(
                        "artifact does not belong to this evidence",
                        code="browser_evidence_mismatch",
                    )
                profiles = services.browser_artifacts.store.list_profiles(
                    evidence_id
                )
                profile_ids = [
                    p.profile_id
                    for p in profiles
                    if p.artifact_id == artifact_id
                ]
            result = services.browser_artifacts.query_cache(
                evidence_id,
                profile_ids=profile_ids,
                query=q or None,
                domain=domain or None,
                time_from=time_from or None,
                time_to=time_to or None,
                include_query_string=bool(include_query_string),
                sort_dir=sort_dir,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/browser_cache.html",
            {
                "result": result,
                "error": error,
                "form": form,
                "evidence_id": evidence_id,
            },
        )

    @app.get(
        "/evidence/{evidence_id}/browser/search", response_class=HTMLResponse
    )
    def browser_search(
        request: Request,
        evidence_id: str,
        artifact_id: str | None = None,
        q: str | None = None,
        domain: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        include_query_string: int = 0,
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        form = {
            "artifact_id": artifact_id or "",
            "q": q or "",
            "domain": domain or "",
            "time_from": time_from or "",
            "time_to": time_to or "",
            "include_query_string": int(include_query_string or 0),
        }
        result = None
        error = None
        try:
            get_record(evidence_id)
            result = services.browser_artifacts.search_all(
                evidence_id,
                query=q or None,
                domain=domain or None,
                time_from=time_from or None,
                time_to=time_to or None,
                include_query_string=bool(include_query_string),
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/browser_search.html",
            {
                "result": result,
                "error": error,
                "form": form,
                "evidence_id": evidence_id,
            },
        )

    @app.get(
        "/evidence/{evidence_id}/browser/profiles", response_class=HTMLResponse
    )
    def browser_profiles(
        request: Request,
        evidence_id: str,
        browser: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> HTMLResponse:
        result = None
        error = None
        try:
            get_record(evidence_id)
            result = services.browser_artifacts.list_profiles(
                evidence_id,
                browser=browser or None,
                page=page,
                page_size=page_size,
            )
        except USER_ERRORS as exc:
            error = str(exc)
        return render(
            request,
            "partials/browser_profiles.html",
            {
                "result": result,
                "error": error,
                "evidence_id": evidence_id,
                "browser": browser or "",
            },
        )

    @app.get("/browser/records/{record_type}/{record_id}", response_class=HTMLResponse)
    def browser_record_detail(
        request: Request, record_type: str, record_id: str
    ) -> HTMLResponse:
        try:
            record = services.browser_artifacts.get_record(
                record_type, int(record_id)
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/browser_detail_error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/browser_detail.html",
            {"detail": record, "record_type": record_type},
        )

    @app.get(
        "/evidence/{evidence_id}/browser/downloads/{download_id}/correlate",
        response_class=HTMLResponse,
    )
    def browser_correlate(
        request: Request, evidence_id: str, download_id: str
    ) -> HTMLResponse:
        try:
            get_record(evidence_id)
            result = services.browser_artifacts.correlate_download(
                evidence_id, int(download_id)
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/browser_detail_error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/browser_correlation.html",
            {"correlation": result["correlation"], "download": result["download"]},
        )

    @app.get(
        "/evidence/{evidence_id}/browser/summary", response_class=HTMLResponse
    )
    def browser_summary(
        request: Request,
        evidence_id: str,
        artifact_id: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        top_n: int = 20,
    ) -> HTMLResponse:
        try:
            get_record(evidence_id)
            profile_ids = None
            if artifact_id:
                artifact = services.browser_artifacts.status(artifact_id)
                if artifact["evidence_id"] != evidence_id:
                    raise DFIRError(
                        "artifact does not belong to this evidence",
                        code="browser_evidence_mismatch",
                    )
                profiles = services.browser_artifacts.store.list_profiles(
                    evidence_id
                )
                profile_ids = [
                    p.profile_id
                    for p in profiles
                    if p.artifact_id == artifact_id
                ]
            summary = services.browser_artifacts.summary(
                evidence_id,
                profile_ids=profile_ids,
                time_from=time_from or None,
                time_to=time_to or None,
                top_n=top_n,
            )
        except USER_ERRORS as exc:
            return render(
                request, "partials/browser_detail_error.html", {"error": str(exc)}
            )
        return render(
            request,
            "partials/browser_summary.html",
            {"summary": summary},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> Response:
        return Response(status_code=204)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return app


app = create_app()


def main() -> None:
    configure_logging()
    settings = Settings.from_env()
    import uvicorn

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
