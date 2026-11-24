from __future__ import annotations

import dataclasses
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError

import dfir_browser.mcp_server as mcp_server
from dfir_browser.core.config import Settings
from dfir_browser.core.models import EvidenceRecord, Layout
from dfir_browser.core.services import build_services
from dfir_browser.core.shellbags.index import ShellbagStore
from dfir_browser.core.shellbags.models import (
    ShellbagDeviceRecord,
    ShellbagHiveRecord,
    ShellbagNodeRecord,
)
from dfir_browser.core.shellbags.parser import parse_hive
from dfir_browser.web.app import create_app

EVIDENCE = "ev_0123456789ab"
SOURCE_SHA = "f" * 64
SCANNER = "test-scanner"


# ----------------------------------------------------------------------
# fake registry for the BagMRU walk
# ----------------------------------------------------------------------
class FakeValue:
    def __init__(self, name, data):
        self._name = name
        self._data = data

    def name(self):
        return self._name

    def value(self):
        return self._data


class FakeKey:
    def __init__(self, path, values=None, subkeys=None):
        self._path = path
        self._values = values or []
        self._subkeys = subkeys or []
        self._timestamp = datetime(2021, 4, 30, 0, 28, 25, tzinfo=timezone.utc)

    def path(self):
        return self._path

    def name(self):
        return self._path.rsplit("\\", 1)[-1]

    def values(self):
        return list(self._values)

    def subkeys(self):
        return list(self._subkeys)

    def timestamp(self):
        return self._timestamp


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def dir_item(name: str) -> bytes:
    short = name.encode("cp1252")[:12]
    body = bytearray(0x0E + len(short) + 1)
    struct.pack_into("<H", body, 0, len(body))
    body[2] = 0x31
    body[3] = 0x00
    struct.pack_into("<H", body, 0x0C, 0x10)
    body[0x0E:0x0E + len(short)] = short
    return bytes(body)


def device_item(name: str, path: str) -> bytes:
    body = bytearray(0x28)
    body[2] = 0x2E
    body += utf16(name) + utf16(path)
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


def mtp_storage(name: str) -> bytes:
    body = bytearray(0x08)
    body[2] = 0x00
    body += utf16(name) + utf16("SID-{10001,,22687535104}")
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


def build_fake_root():
    camera = FakeKey(
        r"ROOT\Local Settings\Shell\BagMRU\0\0\0",
        values=[FakeValue("0", mtp_storage("Camera"))],
    )
    dcim = FakeKey(
        r"ROOT\Local Settings\Shell\BagMRU\0\0",
        values=[FakeValue("0", mtp_storage("DCIM"))],
        subkeys=[camera],
    )
    storage = FakeKey(
        r"ROOT\Local Settings\Shell\BagMRU\0",
        values=[FakeValue("0", mtp_storage("Internal storage"))],
        subkeys=[dcim],
    )
    phone = FakeKey(
        r"ROOT\Local Settings\Shell\BagMRU",
        values=[
            FakeValue(
                "0",
                device_item(
                    "LG Q7",
                    "\\\\?\\usb#vid_1004&pid_633e#x#"
                    "{6ac27878-a6fa-4155-ba85-f98f491d4f33}",
                ),
            ),
            FakeValue("1", dir_item("Users")),
            FakeValue("MRUListEx", struct.pack("<II", 1, 0)),
        ],
        subkeys=[storage],
    )
    root = FakeKey(
        r"ROOT\Local Settings\Software\Microsoft\Windows",
        subkeys=[
            FakeKey(r"ROOT\Local Settings\Software\Microsoft\Windows\Shell",
                    subkeys=[phone])
        ],
    )
    return root


def test_parse_hive_walks_bagmru(monkeypatch):
    import Registry.Registry as registry_module

    class FakeRegistry:
        def __init__(self, path):
            self._root = build_fake_root()

        def root(self):
            return self._root

    monkeypatch.setattr(registry_module, "Registry", FakeRegistry)
    nodes = parse_hive(
        Path("/nonexistent/UsrClass.dat"),
        deadline=9999999999,
        max_nodes=1000,
        user_hint=None,
    )
    names = [node.name for node in nodes]
    # MRUListEx orders 1 before 0 at the top level.
    assert names[:2] == ["Users", "LG Q7"]
    paths = [node.path for node in nodes]
    assert r"LG Q7\Internal storage\DCIM\Camera" in paths
    device = next(node for node in nodes if node.is_device)
    assert device.name == "LG Q7"
    assert device.device_kind == "mtp"
    assert device.key_last_write_utc == "2021-04-30T00:28:25Z"
    child = next(node for node in nodes if node.name == "DCIM")
    assert child.parent_index is not None
    assert nodes[child.parent_index].name == "Internal storage"


def test_parse_hive_respects_node_limit(monkeypatch):
    import Registry.Registry as registry_module

    class FakeRegistry:
        def __init__(self, path):
            self._root = build_fake_root()

        def root(self):
            return self._root

    monkeypatch.setattr(registry_module, "Registry", FakeRegistry)
    nodes = parse_hive(Path("/x"), deadline=9999999999, max_nodes=2)
    assert len(nodes) == 2


# ----------------------------------------------------------------------
# service / store / web
# ----------------------------------------------------------------------
def make_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=EVIDENCE,
        resolved_source_path="/evidence/sample.ad1",
        filename="sample.ad1",
        extension=".ad1",
        source_sha256=SOURCE_SHA,
        source_size=1024,
        source_mtime_ns=1,
        format="AD1",
        media_size=1024,
        sector_size=512,
        md5=None,
        sha1=None,
        ewfinfo_version="20200101",
        ewfinfo_duration_ms=1.0,
        ewfinfo_command={},
        raw_exposure_path="/raw/exposure",
        exposure_mode="direct",
        exposure_verified_at="2020-01-01T00:00:00Z",
        exposure_details={},
        layout=Layout(scope="volume", filesystem="", offset_sectors=0, method="ad1"),
        registered_at="2020-01-01T00:00:00Z",
        status="ready",
        warnings=[],
    )


@pytest.fixture()
def env(tmp_path, monkeypatch):
    settings = dataclasses.replace(
        Settings.from_env(),
        var_dir=tmp_path / "var",
        index_db_path=tmp_path / "index" / "filesystem.db",
        shellbag_db_path=tmp_path / "var" / "cases" / "shellbags.db",
        audit_log_path=tmp_path / "var" / "audit" / "commands.jsonl",
        auto_index=False,
        shellbag_auto_index=False,
        index_scanner_version=SCANNER,
    )
    services = build_services(settings)
    services.evidence.registry.upsert(make_record().to_dict())
    store = services.shellbag_store
    store.upsert_hive(
        ShellbagHiveRecord(
            hive_id="hive_test",
            evidence_id=EVIDENCE,
            entry_id=100,
            path="Users/John Doe/AppData/Local/Microsoft/Windows/UsrClass.dat",
            name="UsrClass.dat",
            hive_type="usrclass",
            user_sid="S-1-5-21-1-2-3-1001",
            state="ready",
            error=None,
            node_count=5,
            device_count=1,
            extract_relpath=None,
            updated_at="2021-04-30T00:00:00Z",
        )
    )

    def node(**kwargs):
        base = dict(
            node_id=0,
            evidence_id=EVIDENCE,
            hive_id="hive_test",
            parent_id=None,
            depth=0,
            name="node",
            path="node",
            item_type=0x31,
            type_name="directory",
            name_source="ansi",
            is_dir=True,
            is_device=False,
            device_id=None,
            drive=None,
            volume_label=None,
            guid=None,
            device_path=None,
            size_bytes=None,
            key_last_write_utc="2021-04-30T00:28:25Z",
            embedded_timestamps=[],
            registry_key_path=r"ROOT\Shell\BagMRU",
            registry_value_name="0",
            registry_key_id=None,
            user_sid="S-1-5-21-1-2-3-1001",
            mru_rank=0,
            warnings=[],
        )
        base.update(kwargs)
        return ShellbagNodeRecord(**base)

    records = [
        node(name="My Computer", path="My Computer"),
        node(name="LG Q7", path="My Computer\\LG Q7", item_type=0x2E,
             type_name="guid_folder", is_device=True),
        node(name="Internal storage", path="My Computer\\LG Q7\\Internal storage",
             item_type=0x00, type_name="unknown", name_source="utf16", depth=2),
        node(name="DCIM", path="My Computer\\LG Q7\\Internal storage\\DCIM",
             item_type=0x00, type_name="unknown", name_source="utf16", depth=3),
        node(name="Camera",
             path="My Computer\\LG Q7\\Internal storage\\DCIM\\Camera",
             item_type=0x00, type_name="unknown", name_source="utf16", depth=4),
    ]
    mapping = store.insert_nodes(list(enumerate(records)))
    ids = [mapping[i] for i in range(len(records))]
    for index in range(1, len(records)):
        store.set_parent(ids[index], ids[index - 1])
    device_id = store.insert_device(
        ShellbagDeviceRecord(
            device_id=0,
            evidence_id=EVIDENCE,
            node_id=ids[1],
            name="LG Q7",
            kind="mtp",
            detail="\\\\?\\usb#vid_1004&pid_633e#x#{6ac27878-a6fa-4155-ba85-f98f491d4f33}",
            drive=None,
            volume_label=None,
            user_sid="S-1-5-21-1-2-3-1001",
            first_seen_utc="2021-04-30T00:28:25Z",
            node_count=3,
        )
    )
    store.set_node_device(ids[1], device_id)
    store.finish(EVIDENCE, state="ready", hives=1, nodes=len(records), devices=1)

    app = create_app(settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, ids
    services.cleanup()


def test_service_tree_and_devices(env):
    client, services, ids = env
    tree = services.shellbags.tree(EVIDENCE)
    assert tree["total"] == 1
    assert tree["items"][0]["name"] == "My Computer"
    subs = services.shellbags.tree(EVIDENCE, parent_id=ids[0])
    assert [item["name"] for item in subs["items"]] == ["LG Q7"]
    devices = services.shellbags.devices(EVIDENCE)
    assert devices["items"][0]["kind"] == "mtp"
    assert devices["items"][0]["node_count"] == 3


def test_service_search_filters(env):
    client, services, ids = env
    # DCIM matches the folder and its Camera child (path substring).
    assert services.shellbags.search(EVIDENCE, query="DCIM")["total"] == 2
    assert services.shellbags.search(EVIDENCE, query="Camera")["total"] == 1
    # "LG Q7" is a prefix of every descendant path.
    assert services.shellbags.search(EVIDENCE, query="LG")["total"] == 4
    assert services.shellbags.search(EVIDENCE, query="nomatch")["total"] == 0
    with pytest.raises(Exception):
        services.shellbags.search(EVIDENCE, query="x" * 500)
    with pytest.raises(Exception):
        services.shellbags.search(EVIDENCE, time_from="not-a-time")


def test_service_node_has_breadcrumb(env):
    client, services, ids = env
    node = services.shellbags.node(ids[3])
    assert [crumb["name"] for crumb in node["breadcrumb"]] == [
        "My Computer", "LG Q7", "Internal storage", "DCIM",
    ]


def test_export_json_and_csv(env):
    client, services, ids = env
    media, name, body = services.shellbags.export(EVIDENCE, fmt="json")
    assert media == "application/json" and name == "shellbags.json"
    assert b"DCIM" in body
    media, name, body = services.shellbags.export(EVIDENCE, fmt="csv")
    assert media == "text/csv"
    assert body.splitlines()[0].startswith(b"node_id,")
    with pytest.raises(Exception):
        services.shellbags.export(EVIDENCE, fmt="xml")


def test_web_tab_and_fragments(env):
    client, services, ids = env
    tab = client.get(f"/evidence/{EVIDENCE}/shellbags")
    assert tab.status_code == 200
    assert "ShellBags" in tab.text
    assert "LG Q7" in tab.text
    tree = client.get(f"/evidence/{EVIDENCE}/shellbags/tree")
    assert tree.status_code == 200
    assert "My Computer" in tree.text
    devices = client.get(f"/evidence/{EVIDENCE}/shellbags/devices")
    assert "mtp" in devices.text
    detail = client.get(f"/shellbags/nodes/{ids[3]}")
    assert detail.status_code == 200
    assert "BagMRU last write" in detail.text
    assert "Registry source" in detail.text


def test_web_search_and_escape(env):
    client, services, ids = env
    response = client.get(f"/evidence/{EVIDENCE}/shellbags/search?q=DCIM")
    assert response.status_code == 200
    assert "DCIM" in response.text
    assert "<script" not in response.text.lower()


def test_web_export_download(env):
    client, services, ids = env
    response = client.get(f"/evidence/{EVIDENCE}/shellbags/export?format=json")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.json()["items"]
    bad = client.get(f"/evidence/{EVIDENCE}/shellbags/export?format=xml")
    assert bad.status_code == 400


def test_web_json_apis(env):
    client, services, ids = env
    assert client.get(f"/evidence/{EVIDENCE}/shellbags/api/devices").json()["items"]
    tree = client.get(f"/evidence/{EVIDENCE}/shellbags/api/tree").json()
    assert tree["total"] == 1
    found = client.get(
        f"/evidence/{EVIDENCE}/shellbags/api/search?q=Camera"
    ).json()
    assert found["total"] == 1
    node = client.get(f"/shellbags/api/nodes/{ids[4]}").json()
    assert node["name"] == "Camera"
    missing = client.get("/shellbags/api/nodes/999999")
    assert missing.status_code == 404


def test_mcp_parity(env):
    client, services, ids = env
    devices = mcp_server.shellbags_list_devices(EVIDENCE)
    assert devices["items"][0]["name"] == "LG Q7"
    assert devices["items"][0]["kind"] == "mtp"
    tree = mcp_server.shellbags_tree(EVIDENCE)
    assert tree["total"] == 1
    found = mcp_server.shellbags_search(EVIDENCE, query="Camera")
    assert found["total"] == 1
    node = mcp_server.shellbags_get_node(ids[3])
    assert node["name"] == "DCIM"
    assert node["trust"] == "untrusted_evidence_data"
    state = mcp_server.shellbags_index_status(EVIDENCE)
    assert state["state"] == "ready"


def test_mcp_rejects_unknown_evidence(env):
    client, services, ids = env
    with pytest.raises(ToolError):
        mcp_server.shellbags_tree("ev_000000000000")
    with pytest.raises(ToolError):
        mcp_server.shellbags_get_node(9999999)


def test_tool_annotations_read_only(env):
    import asyncio

    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    for name in (
        "shellbags_index_status",
        "shellbags_list_devices",
        "shellbags_tree",
        "shellbags_search",
        "shellbags_get_node",
    ):
        assert tools[name].annotations.readOnlyHint is True, name
    assert tools["shellbags_index_start"].annotations.readOnlyHint is False
