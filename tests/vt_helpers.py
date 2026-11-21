from __future__ import annotations

import hashlib
import json
import time

import httpx

from dfir_browser.core.virustotal import VirusTotalClient

from triage_helpers import build_services, sample_payload, stub_extraction

KEY = "d" * 64
HASH = hashlib.sha256(sample_payload()).hexdigest()


def report_body(**overrides):
    attributes = {
        "sha256": HASH,
        "md5": hashlib.md5(sample_payload()).hexdigest(),
        "sha1": hashlib.sha1(sample_payload()).hexdigest(),
        "meaningful_name": "sample.bin",
        "type_description": "data",
        "size": len(sample_payload()),
        "reputation": 0,
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 61,
            "harmless": 0,
            "timeout": 0,
        },
        "times_submitted": 1,
        "first_submission_date": 1600000000,
        "last_submission_date": 1700000000,
        "last_analysis_date": 1710000000,
        "tags": ["test"],
    }
    attributes.update(overrides)
    return {"data": {"type": "file", "attributes": attributes}}


class Upstream:
    def __init__(self, status=200, body=None, headers=None, delay=None):
        self.status = status
        self.body = body if body is not None else report_body()
        self.headers = headers or {}
        self.calls = 0
        self.urls = []
        self.delay = delay

    def __call__(self, request):
        self.calls += 1
        self.urls.append(str(request.url))
        if self.delay:
            self.delay()
        if isinstance(self.body, bytes):
            return httpx.Response(self.status, content=self.body, headers=self.headers)
        return httpx.Response(self.status, json=self.body, headers=self.headers)


def build(tmp_path, upstream: Upstream, **overrides):
    services, record, entry_id = build_services(
        tmp_path, sample_payload(), **overrides
    )
    stub_extraction(services, sample_payload())
    services.virustotal.client = VirusTotalClient(
        transport=httpx.MockTransport(upstream), timeout=5.0
    )
    services.virustotal.save_key(KEY)
    return services, record, entry_id
