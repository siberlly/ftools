"""ShellBags discovery, parsing jobs, queries and export."""
from __future__ import annotations

import csv
import io
import logging
import os
import stat
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..audit import get_correlation_id
from ..config import Settings
from ..errors import DFIRError
from ..index_models import validate_entry_id
from ..models import TRUST_LABEL
from ..registry.detector import classify_entry as classify_registry_entry
from .index import ShellbagStore, escape_like
from .models import (
    ShellbagDeviceRecord,
    ShellbagHiveRecord,
    ShellbagIndexState,
    ShellbagNodeRecord,
    ShellbagRejected,
)
from .parser import parse_hive

logger = logging.getLogger("dfir_browser.shellbags")

CASE_ID = "case01"
SHELLBAG_HIVE_TYPES = {"usrclass", "ntuser"}


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _user_from_path(path: str) -> str | None:
    lowered = (path or "").lower()
    marker = "/users/"
    if marker in lowered:
        rest = path[lowered.index(marker) + len(marker):]
        return rest.split("/", 1)[0] or None
    return None


class ShellbagService:
    def __init__(
        self,
        *,
        settings: Settings,
        policy,
        filesystem,
        evidence,
        indexer,
        index_store,
        audit,
        store: ShellbagStore,
        registry_store=None,
    ) -> None:
        self.settings = settings
        self.policy = policy
        self.filesystem = filesystem
        self.evidence = evidence
        self.indexer = indexer
        self.index_store = index_store
        self.audit = audit
        self.store = store
        self.registry_store = registry_store
        self._lock = threading.Lock()
        self._futures: dict[str, Future[None]] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="dfir-shellbags"
        )
        self.store.ensure_schema()
        interrupted = self.store.recover_interrupted()
        if interrupted:
            logger.warning(
                "marked %s shellbag index job(s) interrupted after restart",
                interrupted,
            )

    def cleanup(self) -> None:
        with self._lock:
            futures = list(self._futures.values())
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    # discovery
    # ------------------------------------------------------------------
    def _scan_id(self, record) -> str:
        row = self.index_store.get_index_row(record.evidence_id)
        if row is None or not row.get("scan_id"):
            raise ShellbagRejected(
                "filesystem index is not available for this evidence",
                code="shellbag_index_missing",
            )
        return str(row["scan_id"])

    def candidates(self, record) -> list[dict[str, Any]]:
        """UsrClass.dat / NTUSER.DAT entries from the filesystem index."""
        status = self.indexer.status_for_record(record)
        if not self.indexer.is_queryable(status):
            raise ShellbagRejected(
                "filesystem index must be ready to find shellbag hives",
                code="shellbag_index_not_ready",
                details={"status": status.status},
            )
        scan_id = self._scan_id(record)
        out: list[dict[str, Any]] = []
        for entry in self.index_store.find_registry_candidates(
            record.evidence_id, scan_id, include_deleted=False
        ):
            candidate = classify_registry_entry(
                entry, evidence_id=record.evidence_id
            )
            if candidate is None or candidate.hive_type not in SHELLBAG_HIVE_TYPES:
                continue
            out.append(
                {
                    "entry_id": entry.id,
                    "inode": entry.inode,
                    "path": entry.full_path,
                    "name": entry.basename,
                    "hive_type": candidate.hive_type,
                    "user": candidate.owner or _user_from_path(entry.full_path),
                    "size": entry.size,
                }
            )
        return out

    # ------------------------------------------------------------------
    # index job
    # ------------------------------------------------------------------
    def state(self, evidence_id: str) -> dict[str, Any]:
        state = self.store.state(evidence_id)
        if state is None:
            return ShellbagIndexState(
                evidence_id=evidence_id,
                state="not_indexed",
                progress=0,
                hives=0,
                nodes=0,
                devices=0,
            ).to_dict()
        return state

    def start(self, record, *, rebuild: bool = False) -> dict[str, Any]:
        current = self.store.state(record.evidence_id)
        if (
            current is not None
            and not rebuild
            and current["state"] in {"running", "queued"}
        ):
            return {"started": False, "state": current, "note": "already running"}
        if (
            current is not None
            and not rebuild
            and current["state"] in {"ready", "partial"}
        ):
            return {
                "started": False,
                "cached": True,
                "state": current,
                "note": "shellbag index already exists; nothing was re-parsed",
            }
        hives = self.candidates(record)
        if not hives:
            self.store.finish(
                record.evidence_id,
                state="empty",
                hives=0,
                nodes=0,
                devices=0,
                warnings=[
                    "no UsrClass.dat or NTUSER.DAT hive was found in this evidence"
                ],
            )
            return {
                "started": False,
                "state": self.store.state(record.evidence_id),
                "note": "no shellbag hives found",
            }
        if rebuild:
            self.store.clear(record.evidence_id)
        self.store.mark_running(record.evidence_id)
        with self._lock:
            future = self._executor.submit(
                self._run, record.evidence_id, hives
            )
            self._futures[record.evidence_id] = future
            future.add_done_callback(
                lambda _f, key=record.evidence_id: self._forget(key)
            )
        self.audit.event(
            "shellbag_index_start",
            evidence_id=record.evidence_id,
            request_id=get_correlation_id(),
            details={"hives": len(hives), "rebuild": bool(rebuild)},
        )
        return {
            "started": True,
            "state": self.store.state(record.evidence_id),
            "note": "shellbag index job started",
        }

    def _forget(self, evidence_id: str) -> None:
        with self._lock:
            self._futures.pop(evidence_id, None)

    def _run(self, evidence_id: str, hives: list[dict[str, Any]]) -> None:
        started = time.monotonic()
        errors: list[str] = []
        warnings: list[str] = []
        total_nodes = 0
        total_devices = 0
        parsed_hives = 0
        deadline = started + float(self.settings.shellbag_index_timeout)
        try:
            record = self.evidence.get(evidence_id)
            for position, candidate in enumerate(hives, start=1):
                if time.monotonic() > deadline:
                    warnings.append("index deadline reached; remaining hives skipped")
                    break
                self.store.set_progress(
                    evidence_id, int(position * 100 / max(1, len(hives)))
                )
                try:
                    nodes, devices, relpath, sid = self._index_hive(
                        record, candidate, deadline
                    )
                except DFIRError as exc:
                    errors.append(f"{candidate['name']}: {exc}")
                    self.store.upsert_hive(
                        ShellbagHiveRecord(
                            hive_id=f"sb_{candidate['entry_id']}",
                            evidence_id=evidence_id,
                            entry_id=candidate["entry_id"],
                            path=candidate["path"],
                            name=candidate["name"],
                            hive_type=candidate["hive_type"],
                            user_sid=candidate.get("user"),
                            state="failed",
                            error=str(exc)[:500],
                            node_count=0,
                            device_count=0,
                            extract_relpath=None,
                            updated_at=_now(),
                        )
                    )
                    continue
                total_nodes += nodes
                total_devices += devices
                parsed_hives += 1
            state = "ready" if not errors else ("partial" if parsed_hives else "failed")
            self.store.finish(
                evidence_id,
                state=state,
                hives=parsed_hives,
                nodes=total_nodes,
                devices=total_devices,
                errors=errors,
                warnings=warnings,
            )
        except Exception as exc:  # noqa: BLE001 - job isolation
            logger.exception("shellbag index failed for %s", evidence_id)
            self.store.finish(
                evidence_id,
                state="failed",
                hives=parsed_hives,
                nodes=total_nodes,
                devices=total_devices,
                errors=[*errors, str(exc)[:500]],
                warnings=warnings,
            )
        finally:
            self.audit.event(
                "shellbag_index_finish",
                evidence_id=evidence_id,
                request_id=get_correlation_id(),
                details={
                    "state": (self.store.state(evidence_id) or {}).get("state"),
                    "nodes": total_nodes,
                    "devices": total_devices,
                    "hives": parsed_hives,
                    "duration_ms": round((time.monotonic() - started) * 1000.0, 1),
                },
            )

    def _index_hive(self, record, candidate, deadline):
        entry = self.indexer.tree_entry(record, candidate["entry_id"])
        workdir = self._workdir(record.evidence_id)
        path, relpath, reused = self._ensure_copy(record, entry, workdir)
        nodes = parse_hive(
            path,
            deadline=deadline,
            max_nodes=int(self.settings.shellbag_max_nodes),
            user_hint=candidate.get("user"),
        )
        hive_key = f"sb_{entry.id}"
        if self.registry_store is not None:
            try:
                known = self.registry_store.find_hive_by_entry(
                    record.evidence_id, entry.id
                )
            except Exception:  # noqa: BLE001
                known = None
            if known is not None:
                # Share the registry hive id so node -> registry key links and
                # the registry browser resolve to the same hive.
                hive_key = known.hive_id
        sid = next((n.user_sid for n in nodes if n.user_sid), None)
        records = []
        for node in nodes:
            record_node = ShellbagNodeRecord(
                node_id=0,
                evidence_id=record.evidence_id,
                hive_id=hive_key,
                parent_id=node.parent_index,
                depth=node.depth,
                name=node.name,
                path=node.path,
                item_type=node.item_type,
                type_name=node.type_name,
                name_source=node.name_source,
                is_dir=node.is_dir,
                is_device=node.is_device,
                device_id=None,
                drive=node.drive,
                volume_label=node.volume_label,
                guid=node.guid,
                device_path=node.device_path,
                size_bytes=node.size_bytes,
                key_last_write_utc=node.key_last_write_utc,
                embedded_timestamps=list(node.embedded_timestamps),
                registry_key_path=node.registry_key_path,
                registry_value_name=node.registry_value_name,
                registry_key_id=None,
                user_sid=node.user_sid,
                mru_rank=node.mru_rank,
                warnings=list(node.warnings),
            )
            records.append(record_node)
        mapping = self.store.insert_nodes(list(enumerate(records)))
        # Resolve parent links now that ids exist.
        for index, db_id in mapping.items():
            parent_index = nodes[index].parent_index
            if parent_index is None:
                continue
            parent_db = mapping.get(parent_index)
            if parent_db is not None:
                self.store.set_parent(db_id, parent_db)
        # Devices: one row per device node, counting its subtree.
        device_count = 0
        for index, db_id in mapping.items():
            node = nodes[index]
            if not node.is_device:
                continue
            children = sum(
                1 for other in nodes if _is_descendant(other, node)
            )
            device_id = self.store.insert_device(
                ShellbagDeviceRecord(
                    device_id=0,
                    evidence_id=record.evidence_id,
                    node_id=db_id,
                    name=node.name,
                    kind=node.device_kind or "portable",
                    detail=node.device_path,
                    drive=node.drive,
                    volume_label=node.volume_label,
                    user_sid=node.user_sid,
                    first_seen_utc=node.key_last_write_utc,
                    node_count=children,
                    warnings=list(node.warnings),
                )
            )
            self.store.set_node_device(db_id, device_id)
            device_count += 1
        self.store.upsert_hive(
            ShellbagHiveRecord(
                hive_id=hive_key,
                evidence_id=record.evidence_id,
                entry_id=entry.id,
                path=entry.full_path,
                name=entry.basename,
                hive_type=candidate["hive_type"],
                user_sid=sid or candidate.get("user"),
                state="ready",
                error=None,
                node_count=len(records),
                device_count=device_count,
                extract_relpath=relpath,
                updated_at=_now(),
                warnings=[] if reused else ["hive was extracted for this index"],
            )
        )
        return len(records), device_count, relpath, sid

    def _workdir(self, evidence_id: str) -> Path:
        directory = (
            self.policy.case_exports_dir(CASE_ID) / "shellbags" / evidence_id
        )
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory

    def _ensure_copy(self, record, entry, workdir: Path):
        # 1) Reuse a registry working copy recorded for this hive.
        if self.registry_store is not None:
            try:
                hive = self.registry_store.find_hive_by_entry(
                    record.evidence_id, entry.id
                )
            except Exception:  # noqa: BLE001
                hive = None
            if hive is not None and hive.extract_relpath:
                candidate = self.settings.var_dir / hive.extract_relpath
                validated = self._validate(candidate)
                if validated is not None:
                    return (
                        validated,
                        hive.extract_relpath,
                        True,
                    )
        # 2) Reuse a previously extracted shellbag copy for this entry.
        marker = workdir / f"entry_{entry.id}.json"
        if marker.is_file():
            try:
                import json

                data = json.loads(marker.read_text(encoding="utf-8"))
                candidate = self.settings.var_dir / str(data.get("relpath"))
                validated = self._validate(candidate)
                if validated is not None:
                    return validated, data.get("relpath"), True
            except (OSError, ValueError):
                pass
        # 3) Extract once.
        extraction = self.filesystem.extract_entry(record, entry, CASE_ID)
        source = Path(extraction.output_path)
        destination = workdir / f"entry_{entry.id}_{entry.basename}"
        if source.resolve() != destination.resolve():
            try:
                if destination.exists():
                    destination.unlink()
                os.replace(source, destination)
            except OSError:
                destination = source
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        try:
            relpath = str(destination.resolve().relative_to(self.settings.var_dir))
        except ValueError:
            relpath = str(destination.resolve())
        import json

        marker.write_text(json.dumps({"relpath": relpath}), encoding="utf-8")
        return destination.resolve(), relpath, False

    def _validate(self, path: Path) -> Path | None:
        try:
            info = os.lstat(path)
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return None
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return None
        exports = self.policy.case_exports_dir(CASE_ID).resolve()
        if not resolved.is_relative_to(exports) or not resolved.is_file():
            return None
        return resolved

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    @staticmethod
    def _page(page: int, page_size: int | None, settings: Settings) -> tuple[int, int]:
        try:
            number = max(1, int(page))
        except (TypeError, ValueError):
            number = 1
        try:
            size = int(page_size) if page_size else 100
        except (TypeError, ValueError):
            size = 100
        size = max(1, min(size, int(settings.shellbag_page_size_max)))
        return number, size

    def tree(
        self,
        evidence_id: str,
        *,
        parent_id: int | None = None,
        hive_id: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        include_files: bool = True,
    ) -> dict[str, Any]:
        page, size = self._page(page, page_size, self.settings)
        nodes, total = self.store.children(
            evidence_id, parent_id, hive_id=hive_id, page=page, page_size=size
        )
        if not include_files:
            nodes = [n for n in nodes if n.is_dir or n.is_device]
        breadcrumb = []
        if parent_id is not None:
            breadcrumb = [
                {
                    "node_id": node.node_id,
                    "name": node.name,
                    "path": node.path,
                }
                for node in self.store.ancestors(parent_id)
            ]
        return {
            "trust": TRUST_LABEL,
            "evidence_id": evidence_id,
            "parent_id": parent_id,
            "hive_id": hive_id,
            "breadcrumb": breadcrumb,
            "items": [_node_payload(n) for n in nodes],
            "total": total,
            "page": page,
            "page_size": size,
            "pages": (total + size - 1) // size if size else 0,
            "has_more": page * size < total,
        }

    def devices(self, evidence_id: str) -> dict[str, Any]:
        devices = self.store.devices(evidence_id)
        return {
            "trust": TRUST_LABEL,
            "evidence_id": evidence_id,
            "items": [d.to_dict() for d in devices],
            "total": len(devices),
        }

    def hives(self, evidence_id: str) -> dict[str, Any]:
        hives = self.store.list_hives(evidence_id)
        return {
            "trust": TRUST_LABEL,
            "evidence_id": evidence_id,
            "items": [h.to_dict() for h in hives],
            "total": len(hives),
        }

    def search(
        self,
        evidence_id: str,
        *,
        query: str | None = None,
        device_id: int | None = None,
        user_sid: str | None = None,
        hive_id: str | None = None,
        kind: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        page, size = self._page(page, page_size, self.settings)
        if query and len(query) > int(self.settings.shellbag_max_query_length):
            raise ShellbagRejected(
                "query exceeds the configured maximum length",
                code="shellbag_query_too_long",
            )
        _validate_time(time_from)
        _validate_time(time_to)
        nodes, total = self.store.search(
            evidence_id,
            query=(query or "").strip() or None,
            device_id=device_id,
            user_sid=user_sid,
            hive_id=hive_id,
            kind=kind,
            time_from=time_from,
            time_to=time_to,
            page=page,
            page_size=size,
        )
        return {
            "trust": TRUST_LABEL,
            "evidence_id": evidence_id,
            "query": query,
            "items": [_node_payload(n) for n in nodes],
            "total": total,
            "page": page,
            "page_size": size,
            "pages": (total + size - 1) // size if size else 0,
            "has_more": page * size < total,
        }

    def node(self, node_id: int) -> dict[str, Any]:
        node = self.store.get_node(node_id)
        payload = _node_payload(node)
        payload["breadcrumb"] = [
            {"node_id": a.node_id, "name": a.name, "path": a.path}
            for a in self.store.ancestors(node_id)
        ]
        payload["registry"] = self._registry_link(node)
        return payload

    def _registry_link(self, node: ShellbagNodeRecord) -> dict[str, Any] | None:
        if self.registry_store is None or not node.registry_key_path:
            return None
        store = self.registry_store
        try:
            hive = store.get_hive(node.hive_id)
        except Exception:  # noqa: BLE001 - hive row may be missing
            hive = None
        key_id = None
        try:
            with store._connect() as connection:
                row = connection.execute(
                    "SELECT id FROM registry_keys WHERE hive_id=? "
                    "AND key_path=? ORDER BY id LIMIT 1",
                    (node.hive_id, node.registry_key_path),
                ).fetchone()
                if row is not None:
                    key_id = int(row["id"])
        except Exception:  # noqa: BLE001 - registry DB may not exist
            key_id = None
        if hive is None and key_id is None:
            return None
        return {
            "hive_id": node.hive_id,
            "hive_name": getattr(hive, "name", None),
            "hive_state": getattr(hive, "state", None),
            "key_path": node.registry_key_path,
            "value_name": node.registry_value_name,
            "key_id": key_id,
        }

    # ------------------------------------------------------------------
    # export
    # ------------------------------------------------------------------
    def export(
        self,
        evidence_id: str,
        *,
        fmt: str = "json",
        query: str | None = None,
        device_id: int | None = None,
        user_sid: str | None = None,
        hive_id: str | None = None,
        kind: str | None = None,
        time_from: str | None = None,
        time_to: str | None = None,
        limit: int | None = None,
    ) -> tuple[str, str, bytes]:
        fmt = (fmt or "json").lower()
        if fmt not in {"json", "csv"}:
            raise ShellbagRejected(
                "export format must be json or csv",
                code="shellbag_invalid_format",
            )
        cap = min(
            int(limit or self.settings.shellbag_export_max_rows),
            int(self.settings.shellbag_export_max_rows),
        )
        result = self.search(
            evidence_id,
            query=query,
            device_id=device_id,
            user_sid=user_sid,
            hive_id=hive_id,
            kind=kind,
            time_from=time_from,
            time_to=time_to,
            page=1,
            page_size=cap,
        )
        rows = result["items"]
        if fmt == "json":
            import json

            payload = {
                "trust": TRUST_LABEL,
                "evidence_id": evidence_id,
                "exported_at": _now(),
                "filters": {
                    "query": query,
                    "device_id": device_id,
                    "user_sid": user_sid,
                    "hive_id": hive_id,
                    "kind": kind,
                    "time_from": time_from,
                    "time_to": time_to,
                },
                "total": result["total"],
                "returned": len(rows),
                "truncated": result["total"] > len(rows),
                "items": rows,
                "note": (
                    "ShellBags record folder/device views opened in Explorer. "
                    "They do not prove that a file was copied or deleted."
                ),
            }
            body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
            return "application/json", "shellbags.json", body
        stream = io.StringIO()
        fields = [
            "node_id", "hive_id", "user_sid", "path", "name", "type_name",
            "is_dir", "is_device", "device_id", "drive", "device_path",
            "key_last_write_utc", "embedded_timestamps", "registry_key_path",
            "registry_value_name",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            item = dict(row)
            item["embedded_timestamps"] = ";".join(
                item.get("embedded_timestamps") or []
            )
            writer.writerow(item)
        return (
            "text/csv",
            "shellbags.csv",
            stream.getvalue().encode("utf-8"),
        )


def _is_descendant(other, parent) -> bool:
    return (other.path or "").startswith((parent.path or "") + "\\")


def _validate_time(value: str | None) -> None:
    if not value:
        return
    try:
        datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ShellbagRejected(
            "time filters must be ISO-8601", code="shellbag_invalid_time"
        ) from exc


def _node_payload(node: ShellbagNodeRecord) -> dict[str, Any]:
    payload = node.to_dict()
    payload["has_children"] = False
    return payload
