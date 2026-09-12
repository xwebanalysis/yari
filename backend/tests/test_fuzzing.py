"""Fuzzing engine tests: safety limits, strategies and abort behaviour."""

import json

import httpx
import pytest

from app import fuzzing
from tests.conftest import mock_client

TARGET = "http://127.0.0.1:9999"


def _endpoint(**overrides) -> dict:
    endpoint = {
        "id": 1,
        "protocol": "rest",
        "method": "GET",
        "path": "/api/search",
        "host": "127.0.0.1",
        "params": [{"name": "q", "in": "query"}],
        "auth_required": None,
    }
    endpoint.update(overrides)
    return endpoint


@pytest.mark.anyio
async def test_safe_mode_skips_mutating_methods():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("mutating endpoint must not be contacted")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_endpoint(method="POST")],
        strategy="safe",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.requests_sent == 0
    assert summary.outcomes[0].status == "SKIPPED"
    assert "mutating" in (summary.outcomes[0].skipped_reason or "")


@pytest.mark.anyio
async def test_reflect_strategy_finds_canary_reflection():
    def handler(request):
        value = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<h1>results for {value}</h1>")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET, [_endpoint()], strategy="reflect", client=client, delay_ms=(0, 0)
    )
    await client.aclose()

    assert summary.requests_sent == 1
    assert len(summary.findings) == 1
    finding = summary.findings[0]
    assert finding.check == "reflected_input"
    assert finding.severity == "low"
    assert finding.evidence["poc_payload"].startswith("xwa-canary-")
    assert finding.evidence["param"] == "q"


@pytest.mark.anyio
async def test_error_based_strategy_reports_anomaly():
    def handler(request):
        payload = request.url.params.get("q", "")
        if payload not in ("", "1"):
            return httpx.Response(500, text="Traceback: database error at line 42")
        return httpx.Response(200, text="ok")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET, [_endpoint()], strategy="error_based", client=client, delay_ms=(0, 0)
    )
    await client.aclose()

    checks = [f.check for f in summary.findings]
    assert "error_based_anomaly" in checks
    anomaly = next(f for f in summary.findings if f.check == "error_based_anomaly")
    assert anomaly.evidence["poc_payload"] in fuzzing.ERROR_PAYLOADS
    assert anomaly.evidence["baseline"]["status_code"] == 200
    assert anomaly.evidence["observed"]["status_code"] == 500


@pytest.mark.anyio
async def test_safe_engine_respects_global_request_budget():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        return httpx.Response(200, text="stable response")

    endpoints = [
        _endpoint(id=i, path=f"/api/search{i}", params=[{"name": "q", "in": "query"}])
        for i in range(5)
    ]
    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        endpoints,
        strategy="safe",
        max_requests=5,
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.requests_sent == 5
    assert calls["count"] == 5
    assert summary.requests_sent <= fuzzing.SAFE_MAX_REQUESTS


@pytest.mark.anyio
async def test_engine_aborts_on_429():
    def handler(request):
        return httpx.Response(429, text="too many requests")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET, [_endpoint()], strategy="rate_limit", client=client, delay_ms=(0, 0)
    )
    await client.aclose()

    assert summary.aborted is True
    assert summary.requests_sent == 1
    assert "429" in (summary.abort_reason or "")


@pytest.mark.anyio
async def test_authz_matrix_requires_credentials():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("no request expected without credentials")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET, [_endpoint(auth_required=True)], strategy="authz_matrix", client=client, delay_ms=(0, 0)
    )
    await client.aclose()

    assert summary.requests_sent == 0
    assert "no auth token" in (summary.outcomes[0].skipped_reason or "")


@pytest.mark.anyio
async def test_authz_matrix_detects_unauthenticated_access():
    def handler(request):
        return httpx.Response(200, json={"users": []})

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_endpoint(auth_required=True)],
        strategy="authz_matrix",
        auth_token="test-token",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.requests_sent == 2
    assert len(summary.findings) == 1
    finding = summary.findings[0]
    assert finding.check == "unauthenticated_access"
    assert finding.severity == "high"
    assert finding.evidence["anonymous_status"] == 200
    # tokens must never leak into evidence
    assert "test-token" not in json.dumps(finding.evidence)


@pytest.mark.anyio
async def test_rate_limit_strategy_reports_missing_headers():
    def handler(request):
        return httpx.Response(200, text="ok")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET, [_endpoint()], strategy="rate_limit", client=client, delay_ms=(0, 0)
    )
    await client.aclose()

    assert summary.requests_sent == 3
    assert [f.check for f in summary.findings] == ["rate_limit_headers_missing"]
    assert summary.findings[0].severity == "info"


def test_endpoint_url_uses_endpoint_host():
    url = fuzzing.endpoint_url(
        "https://api.example.com:8443", {"path": "/api/users", "host": "other.example.com"}
    )
    assert url == "https://other.example.com/api/users"
