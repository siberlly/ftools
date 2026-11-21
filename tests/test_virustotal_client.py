from __future__ import annotations

import hashlib
import json
import threading
import time

import httpx
import pytest

from dfir_browser.core.virustotal import (
    VirusTotalClient,
    VirusTotalForbidden,
    VirusTotalInvalidKey,
    VirusTotalInvalidResponse,
    VirusTotalNetworkError,
    VirusTotalRateLimited,
    VirusTotalRedirectRejected,
    VirusTotalResponseTooLarge,
    VirusTotalTimeout,
    VirusTotalTlsError,
    VirusTotalTransient,
    VirusTotalUnexpectedHost,
)

KEY = "a" * 64
HASH = "d3c3bc26a836ab7d70b8384d13b237cccc45ce883eb74e98429dcaec31b09a0b"


def report_body(**overrides):
    attributes = {
        "sha256": HASH,
        "md5": "ee18b3a542e2c27ab8e7506bc4b39379",
        "sha1": "374b883f0c782621d10cfa6f17fc997b3e7b0c6c",
        "meaningful_name": "sample.exe",
        "type_description": "Win32 EXE",
        "size": 57344,
        "reputation": 0,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 1,
            "undetected": 60,
            "harmless": 0,
            "timeout": 0,
        },
        "times_submitted": 3,
        "first_submission_date": 1600000000,
        "last_submission_date": 1700000000,
        "last_analysis_date": 1710000000,
        "tags": ["pe", "signed"],
    }
    attributes.update(overrides)
    return {"data": {"type": "file", "attributes": attributes}}


def make_client(handler, **kwargs):
    return VirusTotalClient(
        transport=httpx.MockTransport(handler),
        timeout=5.0,
        max_response_bytes=kwargs.pop("max_response_bytes", 2_000_000),
    )


def test_found_report_normalized() -> None:
    client = make_client(lambda request: httpx.Response(200, json=report_body()))
    result = client.lookup(HASH, KEY)
    assert result.status == "found"
    assert result.http_status == 200
    data = result.report
    assert data["sha256"] == HASH
    assert data["meaningful_name"] == "sample.exe"
    assert data["type_description"] == "Win32 EXE"
    assert data["size"] == 57344
    assert data["last_analysis_stats"]["suspicious"] == 1
    assert data["first_submission_date"].startswith("2020-")
    assert data["permalink"] == f"https://www.virustotal.com/gui/file/{HASH}"
    assert data["tags"] == ["pe", "signed"]


def test_request_is_hash_only_and_https_host() -> None:
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        seen["method"] = request.method
        seen["body"] = request.content
        return httpx.Response(200, json=report_body())

    client = make_client(handler)
    client.lookup(HASH, KEY)
    assert seen["method"] == "GET"
    assert seen["url"] == f"https://www.virustotal.com/api/v3/files/{HASH}"
    assert seen["body"] == b""
    assert seen["headers"]["x-apikey"] == KEY
    assert "upload" not in seen["url"]
    assert "evidence" not in seen["url"]


def test_404_not_found() -> None:
    client = make_client(lambda request: httpx.Response(404, json={}))
    result = client.lookup(HASH, KEY)
    assert result.status == "not_found"
    assert result.report is None


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, VirusTotalInvalidKey),
        (403, VirusTotalForbidden),
    ],
)
def test_auth_errors(status, error) -> None:
    client = make_client(lambda request: httpx.Response(status, json={}))
    with pytest.raises(error):
        client.lookup(HASH, KEY)


def test_429_retry_after() -> None:
    client = make_client(
        lambda request: httpx.Response(429, headers={"Retry-After": "42"})
    )
    with pytest.raises(VirusTotalRateLimited) as excinfo:
        client.lookup(HASH, KEY)
    assert excinfo.value.retry_after == 42


def test_503_retries_once_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503)
        return httpx.Response(200, json=report_body())

    client = make_client(handler)
    result = client.lookup(HASH, KEY)
    assert result.status == "found"
    assert calls["n"] == 2


def test_503_twice_fails() -> None:
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503)

    with pytest.raises(VirusTotalTransient):
        make_client(handler).lookup(HASH, KEY)
    assert calls["n"] == 2


def test_timeout() -> None:
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(VirusTotalTimeout):
        make_client(handler).lookup(HASH, KEY)


def test_tls_error() -> None:
    def handler(request):
        raise httpx.ConnectError("certificate verify failed", request=request)

    with pytest.raises(VirusTotalTlsError):
        make_client(handler).lookup(HASH, KEY)


def test_network_error() -> None:
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(VirusTotalNetworkError):
        make_client(handler).lookup(HASH, KEY)


def test_invalid_json() -> None:
    client = make_client(lambda request: httpx.Response(200, content=b"not json"))
    with pytest.raises(VirusTotalInvalidResponse):
        client.lookup(HASH, KEY)


def test_invalid_shape() -> None:
    client = make_client(lambda request: httpx.Response(200, json={"data": 1}))
    with pytest.raises(VirusTotalInvalidResponse):
        client.lookup(HASH, KEY)


def test_oversized_response() -> None:
    client = make_client(
        lambda request: httpx.Response(200, content=b"x" * 5000),
        max_response_bytes=100,
    )
    with pytest.raises(VirusTotalResponseTooLarge):
        client.lookup(HASH, KEY)


def test_redirect_rejected() -> None:
    client = make_client(
        lambda request: httpx.Response(
            302, headers={"Location": "https://evil.example/"}
        )
    )
    with pytest.raises(VirusTotalRedirectRejected):
        client.lookup(HASH, KEY)


def test_unexpected_host_rejected() -> None:
    client = make_client(lambda request: httpx.Response(200, json=report_body()))
    with pytest.raises(VirusTotalUnexpectedHost):
        client._validate_url("https://evil.example/api/v3/files/" + HASH)
    with pytest.raises(VirusTotalUnexpectedHost):
        client._validate_url("http://www.virustotal.com/api/v3/files/" + HASH)


def test_invalid_hash_rejected() -> None:
    client = make_client(lambda request: httpx.Response(200, json={}))
    for bad in ("", "xyz", "../etc/passwd", "a" * 63):
        with pytest.raises(Exception) as excinfo:
            client.lookup(bad, KEY)
        assert getattr(excinfo.value, "code", "") == "virustotal_invalid_hash"


def test_missing_key() -> None:
    client = make_client(lambda request: httpx.Response(200, json=report_body()))
    with pytest.raises(Exception) as excinfo:
        client.lookup(HASH, "")
    assert getattr(excinfo.value, "code", "") == "virustotal_not_configured"
