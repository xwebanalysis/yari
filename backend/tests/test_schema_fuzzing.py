"""OpenAPI-schema-driven payload generation tests.

Covers the inline OpenAPI fixture parsing (type/enum/required extraction,
requestBody properties) and the fuzzer integration (benign typed payloads fed
through the budgeted engine with all safety guarantees intact).
"""

import httpx
import pytest

from app import discovery, fuzzing
from tests.conftest import mock_client

TARGET = "http://127.0.0.1:9999"

SCHEMA_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Schema API", "version": "1.2.0"},
    "paths": {
        "/items": {
            "get": {
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1},
                    },
                    {
                        "name": "status",
                        "in": "query",
                        "schema": {"type": "string", "enum": ["active", "pending", "done"]},
                    },
                    {
                        "name": "verbose",
                        "in": "query",
                        "schema": {"type": "boolean"},
                    },
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "count": {"type": "integer"},
                                    "enabled": {"type": "boolean"},
                                    "tags": {"type": "array", "items": {"type": "string"}},
                                },
                            }
                        }
                    }
                }
            },
        }
    },
}


# ── payload derivation unit tests ───────────────────────────────────────────


def test_benign_values_for_integer():
    values = fuzzing.benign_values_for_param({"type": "integer"})
    assert values == [-1, 0, 1]


def test_benign_values_for_boolean():
    values = fuzzing.benign_values_for_param({"type": "boolean"})
    assert values == [False, True]


def test_benign_values_for_enum_prefers_declared_values():
    values = fuzzing.benign_values_for_param({"type": "string", "enum": ["active", "pending"]})
    assert values == ["active", "pending"]


def test_benign_values_for_enum_caps_long_lists():
    enum = [f"v{i}" for i in range(8)]
    values = fuzzing.benign_values_for_param({"type": "string", "enum": enum})
    assert values == enum[: fuzzing.MAX_SCHEMA_PAYLOADS]


def test_benign_values_for_string_is_a_canary():
    values = fuzzing.benign_values_for_param({"type": "string"})
    assert len(values) == 1
    assert values[0].startswith(fuzzing.CANARY_PREFIX)


def test_benign_values_for_array():
    values = fuzzing.benign_values_for_param({"type": "array<string>"})
    assert values == [[], [1]]


def test_benign_values_for_unknown_falls_back_to_error_payloads():
    values = fuzzing.benign_values_for_param({"type": None})
    assert values == list(fuzzing.ERROR_PAYLOADS)
    values = fuzzing.benign_values_for_param({})
    assert values == list(fuzzing.ERROR_PAYLOADS)


def test_baseline_values_are_typed():
    assert fuzzing.baseline_value_for_param({"type": "integer"}) == 1
    assert fuzzing.baseline_value_for_param({"type": "boolean"}) is True
    assert fuzzing.baseline_value_for_param({"type": "string"}) == fuzzing.BENIGN_STRING_VALUE
    assert fuzzing.baseline_value_for_param({"type": "string", "enum": ["active"]}) == "active"
    assert fuzzing.baseline_value_for_param({"type": None}) == "1"


def test_param_has_schema_detection():
    assert fuzzing.param_has_schema({"type": "integer"})
    assert fuzzing.param_has_schema({"enum": ["a"]})
    assert not fuzzing.param_has_schema({"name": "q", "in": "query"})
    assert not fuzzing.param_has_schema(None)


# ── OpenAPI fixture parsing tests ────────────────────────────────────────────


def test_parse_openapi_extracts_schema_metadata():
    endpoints = discovery.parse_openapi_spec(SCHEMA_SPEC, "https://api.example.com")
    get_items = next(e for e in endpoints if e.method == "GET")

    by_name = {p["name"]: p for p in get_items.params}
    assert by_name["limit"]["type"] == "integer"
    assert by_name["limit"]["required"] is True
    assert by_name["status"]["type"] == "string"
    assert by_name["status"]["enum"] == ["active", "pending", "done"]
    assert by_name["status"]["required"] is False
    assert by_name["verbose"]["type"] == "boolean"


def test_parse_openapi_extracts_typed_body_params():
    endpoints = discovery.parse_openapi_spec(SCHEMA_SPEC, "https://api.example.com")
    post_items = next(e for e in endpoints if e.method == "POST")

    body_params = {p["name"]: p for p in post_items.params if p["in"] == "body"}
    assert body_params["name"]["required"] is True
    assert body_params["name"]["type"] == "string"
    assert body_params["count"]["required"] is False
    assert body_params["count"]["type"] == "integer"
    assert body_params["enabled"]["type"] == "boolean"
    assert body_params["tags"]["type"] == "array<string>"


def _schema_endpoint(**overrides) -> dict:
    endpoint = {
        "id": 1,
        "protocol": "rest",
        "method": "GET",
        "path": "/items",
        "host": "127.0.0.1",
        "params": [
            {"name": "limit", "in": "query", "required": True, "type": "integer"},
            {"name": "status", "in": "query", "required": False, "type": "string",
             "enum": ["active", "pending", "done"]},
        ],
        "auth_required": None,
    }
    endpoint.update(overrides)
    return endpoint


# ── fuzzer integration tests ─────────────────────────────────────────────────


@pytest.mark.anyio
async def test_schema_strategy_uses_typed_baseline():
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, text="ok")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_schema_endpoint()],
        strategy="schema",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    # baseline: required int param typed as "1", optional enum param omitted
    assert summary.requests_sent >= 1
    assert seen[0] == {"limit": "1"}


@pytest.mark.anyio
async def test_schema_strategy_reports_typed_anomaly():
    def handler(request):
        params = request.url.params
        if params.get("status") == "pending":
            return httpx.Response(500, text="Traceback: enum handling failure")
        return httpx.Response(200, text="ok")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_schema_endpoint()],
        strategy="schema",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    checks = [f.check for f in summary.findings]
    assert "schema_driven_anomaly" in checks
    anomaly = next(f for f in summary.findings if f.check == "schema_driven_anomaly")
    assert anomaly.evidence["poc_payload"] == "pending"
    assert anomaly.evidence["param"] == "status"
    assert anomaly.evidence["param_type"] == "string"
    assert anomaly.evidence["baseline"]["status_code"] == 200
    assert anomaly.evidence["observed"]["status_code"] == 500


@pytest.mark.anyio
async def test_schema_strategy_skips_endpoints_without_schema_info():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("no schema info: nothing to send")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [{"id": 2, "protocol": "rest", "method": "GET", "path": "/legacy",
          "host": "127.0.0.1", "params": [{"name": "q", "in": "query"}]}],
        strategy="schema",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.requests_sent == 0
    assert "no OpenAPI schema info" in (summary.outcomes[0].skipped_reason or "")


@pytest.mark.anyio
async def test_schema_payloads_respect_global_budget():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        return httpx.Response(200, text="ok")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_schema_endpoint(id=i, path=f"/items{i}") for i in range(4)],
        strategy="schema",
        max_requests=5,
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert calls["count"] == summary.requests_sent == 5
    assert summary.requests_sent <= fuzzing.SAFE_MAX_REQUESTS


@pytest.mark.anyio
async def test_schema_payloads_abort_on_429():
    def handler(request):
        return httpx.Response(429, text="rate limited")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_schema_endpoint()],
        strategy="schema",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.aborted is True
    assert "429" in (summary.abort_reason or "")


@pytest.mark.anyio
async def test_schema_payloads_never_touch_mutating_methods_without_optin():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("POST must not be contacted in safe mode")

    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [_schema_endpoint(method="POST")],
        strategy="schema",
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    assert summary.requests_sent == 0
    assert summary.outcomes[0].status == "SKIPPED"
    assert "mutating" in (summary.outcomes[0].skipped_reason or "")


@pytest.mark.anyio
async def test_schema_strategy_typed_body_with_allow_mutations():
    seen = []

    def handler(request):
        seen.append(request.content)
        return httpx.Response(200, text="ok")

    endpoint = _schema_endpoint(
        method="POST",
        params=[
            {"name": "count", "in": "body", "required": True, "type": "integer"},
        ],
    )
    client = mock_client(handler)
    summary = await fuzzing.run_fuzz(
        TARGET,
        [endpoint],
        strategy="schema",
        allow_mutations=True,
        client=client,
        delay_ms=(0, 0),
    )
    await client.aclose()

    # baseline body keeps the JSON int type (not a stringified "1")
    import json

    assert json.loads(seen[0])["count"] == 1
    assert summary.requests_sent >= 1
