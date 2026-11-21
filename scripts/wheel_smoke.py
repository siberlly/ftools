#!/usr/bin/env python3
"""Import the built wheel from an isolated directory and render the web UI."""

from __future__ import annotations

import argparse
import sys
import tempfile
import zipfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    wheel = Path(args.wheel).resolve()
    if not wheel.is_file():
        raise SystemExit(f"wheel not found: {wheel}")

    with tempfile.TemporaryDirectory(prefix="dfir-wheel-") as temporary:
        extract_dir = Path(temporary) / "wheel"
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(extract_dir)
        sys.path.insert(0, str(extract_dir))

        import dfir_browser  # noqa: PLC0415

        package_dir = Path(dfir_browser.__file__).resolve().parent
        if not package_dir.is_relative_to(extract_dir):
            raise SystemExit(
                f"imported package is not from the wheel: {package_dir}"
            )
        templates = package_dir / "web" / "templates"
        static = package_dir / "web" / "static"
        assert (templates / "base.html").is_file()
        assert (templates / "settings.html").is_file()
        assert (templates / "partials" / "tree.html").is_file()
        assert (templates / "partials" / "index_status.html").is_file()
        assert (templates / "partials" / "entries_table.html").is_file()
        assert (templates / "partials" / "deleted.html").is_file()
        assert (templates / "partials" / "search.html").is_file()
        assert (templates / "partials" / "index_required.html").is_file()
        for name in (
            "tree_explorer.html",
            "tree_unavailable.html",
            "tree_directory.html",
            "tree_file.html",
            "tree_entry_error.html",
            "triage_panel.html",
            "triage_job.html",
            "triage_strings.html",
            "virustotal_panel.html",
            "virustotal_report.html",
            "virustotal_error.html",
            "virustotal_settings.html",
            "registry.html",
            "registry_status.html",
            "registry_browser.html",
            "registry_key.html",
            "registry_search.html",
            "registry_amcache.html",
            "registry_compare.html",
            "evtx_logs.html",
            "evtx_status.html",
            "evtx_explorer.html",
            "evtx_events.html",
            "evtx_detail.html",
            "evtx_context.html",
            "evtx_summary.html",
            "evtx_detail_error.html",
        ):
            assert (templates / "partials" / name).is_file(), name
        assert (static / "htmx.min.js").is_file()
        assert (static / "tree.js").is_file()
        assert (static / "triage.js").is_file()
        assert (static / "forms.js").is_file()
        assert (static / "registry.js").is_file()
        assert (static / "evtx.js").is_file()
        assert (static / "style.css").is_file()

        from dfir_browser.core.index_store import IndexStore  # noqa: PLC0415
        from dfir_browser.core.indexer import FilesystemIndexer  # noqa: PLC0415

        assert IndexStore is not None
        assert FilesystemIndexer is not None

        from dfir_browser.core.triage import FileTriageService  # noqa: PLC0415
        from dfir_browser.core.triage_store import TriageStore  # noqa: PLC0415
        from dfir_browser.core.virustotal import VirusTotalClient  # noqa: PLC0415
        from dfir_browser.core.vt_secrets import SecretStore  # noqa: PLC0415
        from dfir_browser.core.registry.index import RegistryStore  # noqa: PLC0415
        from dfir_browser.core.registry.service import RegistryService  # noqa: PLC0415
        from dfir_browser.core.evtx.index import EvtxStore  # noqa: PLC0415
        from dfir_browser.core.evtx.service import EvtxService  # noqa: PLC0415

        assert FileTriageService is not None
        assert TriageStore is not None
        assert VirusTotalClient is not None
        assert SecretStore is not None
        assert RegistryStore is not None
        assert RegistryService is not None
        assert EvtxStore is not None
        assert EvtxService is not None

        from dfir_browser.core.config import Settings  # noqa: PLC0415
        from dfir_browser.web.app import create_app  # noqa: PLC0415
        from fastapi.testclient import TestClient  # noqa: PLC0415

        work = Path(temporary) / "work"
        allowed = work / "allowed"
        allowed.mkdir(parents=True)
        settings = Settings.from_env(
            var_dir=work / "var",
            allowed_roots=(allowed,),
            ewf_mappings={},
            ewf_automount=False,
            allowed_hosts=("testserver",),
            allowed_origins=("http://testserver",),
        )
        application = create_app(settings)
        with TestClient(application) as client:
            response = client.get("/")
            assert response.status_code == 200, response.text
            assert "Register evidence" in response.text
            assert client.get("/static/htmx.min.js").status_code == 200
            tree_js = client.get("/static/tree.js")
            assert tree_js.status_code == 200
            assert "aria-expanded" in tree_js.text
            assert "textContent" in tree_js.text
            triage_js = client.get("/static/triage.js")
            assert triage_js.status_code == 200
            assert "data-copy-value" in triage_js.text
            forms_js = client.get("/static/forms.js")
            assert forms_js.status_code == 200
            assert "requestSubmit" in forms_js.text
            settings = client.get("/settings/integrations")
            assert settings.status_code == 200
            assert "VirusTotal" in settings.text
            assert "Not configured" in settings.text
            registry_js = client.get("/static/registry.js")
            assert registry_js.status_code == 200
            assert "data-registry-tree" in registry_js.text
            evtx_js = client.get("/static/evtx.js")
            assert evtx_js.status_code == 200
            assert "data-evtx-detail" in evtx_js.text

        print(f"[wheel] package={package_dir}")
        print("[ok] wheel import, templates, static assets, and web index verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
