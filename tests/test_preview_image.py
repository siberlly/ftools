from __future__ import annotations

import dataclasses
import struct

import pytest
from fastapi.testclient import TestClient

import dfir_browser.mcp_server as mcp_server
from dfir_browser.core.preview import image_info
from dfir_browser.web.app import create_app

from preview_helpers import (
    EVIDENCE,
    _row,
    build_preview_services,
    entry_id,
    stub_preview_extract,
)

PNG_PATH = "Users/IEUser/Pictures/sample.png"
JPEG_PATH = "Users/IEUser/Pictures/sample.jpg"
GIF_PATH = "Users/IEUser/Pictures/anim.gif"
SVG_PATH = "Users/IEUser/Pictures/vector.svg"
BIG_PATH = "Users/IEUser/Pictures/huge.png"

PNG_INODE = 62001
JPEG_INODE = 62002
GIF_INODE = 62003
SVG_INODE = 62004
BIG_INODE = 62005


def png_bytes(width: int = 640, height: int = 480, pad: int = 0) -> bytes:
    ihdr = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
    chunk = struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr + b"\x00\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + chunk + b"\x00" * pad


def jpeg_bytes(width: int = 1920, height: int = 1080) -> bytes:
    sof = (
        b"\xff\xc0"
        + struct.pack(">H", 17)
        + b"\x08"
        + struct.pack(">HH", height, width)
        + b"\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
    )
    return b"\xff\xd8" + sof + b"\xff\xd9"


def gif_bytes(width: int = 100, height: int = 50) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00" * 16


CLAIM = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


@pytest.fixture()
def env(tmp_path, monkeypatch):
    rows = [
        _row(PNG_PATH, "sample.png", PNG_INODE, 0),
        _row(JPEG_PATH, "sample.jpg", JPEG_INODE, 0),
        _row(GIF_PATH, "anim.gif", GIF_INODE, 0),
        _row(SVG_PATH, "vector.svg", SVG_INODE, 0),
        _row(BIG_PATH, "huge.png", BIG_INODE, 0),
    ]
    payloads = {
        PNG_INODE: png_bytes(),
        JPEG_INODE: jpeg_bytes(),
        GIF_INODE: gif_bytes(),
        SVG_INODE: CLAIM,
        BIG_INODE: png_bytes(pad=2 * 1024 * 1024),
    }
    services, record = build_preview_services(
        tmp_path,
        payloads,
        rows=rows,
        preview_max_image_bytes=1024 * 1024,
    )
    stub_preview_extract(services, payloads)
    app = create_app(services.settings, services)
    monkeypatch.setattr(mcp_server, "get_services", lambda: services)
    with TestClient(app) as client:
        yield client, services, record
    services.cleanup()


def test_image_info_formats():
    assert image_info(png_bytes(10, 20))["width"] == 10
    assert image_info(png_bytes(10, 20))["height"] == 20
    assert image_info(jpeg_bytes(30, 40))["format"] == "jpeg"
    assert image_info(jpeg_bytes(30, 40))["width"] == 30
    assert image_info(gif_bytes(7, 9))["width"] == 7
    assert image_info(CLAIM) is None


@pytest.mark.parametrize(
    "path,inode,mime,width",
    [
        (PNG_PATH, PNG_INODE, "image/png", 640),
        (JPEG_PATH, JPEG_INODE, "image/jpeg", 1920),
        (GIF_PATH, GIF_INODE, "image/gif", 100),
    ],
)
def test_preview_returns_image_mode(env, path, inode, mime, width):
    client, services, record = env
    result = services.preview.preview(record, entry_id(services, path))
    assert result.preview_mode == "image"
    assert result.mime_type == mime
    assert result.image["width"] == width
    assert result.image["bytes"] > 0
    assert result.image["url"].endswith("/image")
    assert result.content == ""


def test_image_route_serves_bytes_with_safe_headers(env):
    client, services, record = env
    response = client.get(
        f"/evidence/{EVIDENCE}/entries/{entry_id(services, PNG_PATH)}/image"
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.content.startswith(b"\x89PNG")


def test_svg_is_never_served_as_an_image(env):
    client, services, record = env
    svg = entry_id(services, SVG_PATH)
    preview = services.preview.preview(record, svg)
    assert preview.preview_mode == "text"
    assert "<svg" in preview.content
    response = client.get(f"/evidence/{EVIDENCE}/entries/{svg}/image")
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "preview_not_an_image"


def test_oversized_image_falls_back_to_hex(env):
    client, services, record = env
    big = entry_id(services, BIG_PATH)
    result = services.preview.preview(record, big)
    assert result.preview_mode == "hex"
    assert any("inline limit" in w for w in result.warnings)
    refused = client.get(f"/evidence/{EVIDENCE}/entries/{big}/image")
    assert refused.status_code == 400
    assert refused.json()["error"]["code"] == "preview_image_too_large"


def test_image_route_rejects_unknown_evidence(env):
    client, services, record = env
    png = entry_id(services, PNG_PATH)
    response = client.get(f"/evidence/ev_000000000000/entries/{png}/image")
    assert response.status_code == 400


def test_mcp_image_mode_has_no_binary_payload(env):
    client, services, record = env
    png = entry_id(services, PNG_PATH)
    payload = mcp_server.preview_file_content(EVIDENCE, png)
    assert payload["preview_mode"] == "image"
    assert payload["image"]["media_type"] == "image/png"
    assert payload["content"] == ""
    assert payload["trust"] == "untrusted_evidence_data"
