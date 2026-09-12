"""Authentication testing tests: JWT, cookies, API keys and comparative authz."""

import base64
import json
import time

import httpx
import pytest

from app import auth_testing
from tests.conftest import mock_client

TARGET = "http://127.0.0.1:9999"


def make_jwt(header: dict, payload: dict, signature: str = "signature") -> str:
    def encode(data: dict) -> str:
        raw = json.dumps(data).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{encode(header)}.{encode(payload)}.{signature}"


def test_decode_jwt_reads_header_and_payload():
    token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "42", "exp": int(time.time()) + 60})
    decoded = auth_testing.decode_jwt(token)
    assert decoded is not None
    header, payload = decoded
    assert header["alg"] == "HS256"
    assert payload["sub"] == "42"

    assert auth_testing.decode_jwt("not-a-jwt") is None
    assert auth_testing.decode_jwt("a.b") is None


def test_jwt_alg_none_is_critical():
    token = make_jwt({"alg": "none"}, {"sub": "1", "exp": int(time.time()) + 60})
    results = auth_testing.analyze_jwt(token)
    checks = {result.check: result for result in results}
    assert checks["jwt_alg_none"].result == "critical"
    assert checks["jwt_alg_none"].confidence == "high"


def test_jwt_missing_exp_and_claims():
    token = make_jwt({"alg": "HS256"}, {"sub": "1"})
    results = auth_testing.analyze_jwt(token)
    checks = {result.check for result in results}
    assert "jwt_missing_exp" in checks
    assert "jwt_missing_aud" in checks
    assert "jwt_missing_iss" in checks
    # no token material leaks into details
    assert all("eyJ" not in json.dumps(result.details) for result in results)


def test_jwt_long_expiry_and_hmac_kid():
    payload = {
        "sub": "1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 30 * 86400,
        "aud": "api",
        "iss": "https://issuer.example",
        "nbf": int(time.time()),
    }
    token = make_jwt({"alg": "HS256", "kid": "key-1"}, payload)
    results = auth_testing.analyze_jwt(token)
    checks = {result.check: result for result in results}
    assert checks["jwt_long_expiry"].result == "medium"
    assert checks["jwt_hmac_with_kid"].result == "medium"


def test_jwt_bounded_expiry_passes():
    payload = {
        "sub": "1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 900,
        "aud": "api",
        "iss": "https://issuer.example",
        "nbf": int(time.time()),
    }
    token = make_jwt({"alg": "RS256"}, payload)
    results = auth_testing.analyze_jwt(token)
    assert any(result.check == "jwt_expiry_present" and result.result == "pass" for result in results)
    assert not any(result.result == "critical" for result in results)


def test_cookie_flag_analysis():
    results = auth_testing.analyze_cookie("sessionid=abc123; Path=/")
    checks = {result.check for result in results}
    assert "cookie_httponly_missing" in checks
    assert "cookie_secure_missing" in checks
    assert "cookie_samesite_missing" in checks

    hardened = auth_testing.analyze_cookie(
        "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
    assert hardened == []

    # non-session cookies are ignored
    assert auth_testing.analyze_cookie("theme=dark; Path=/") == []


def test_api_key_in_url_detection():
    results = auth_testing.analyze_api_key_in_url("https://api.example.com/v1/x?api_key=SECRET")
    assert len(results) == 1
    assert results[0].check == "api_key_in_url"
    assert results[0].result == "medium"
    assert "SECRET" not in json.dumps(results[0].details)
    assert auth_testing.analyze_api_key_in_url("https://api.example.com/v1/x?page=1") == []


@pytest.mark.anyio
async def test_run_auth_tests_without_credentials_makes_no_requests():
    def handler(request):  # pragma: no cover - must never run
        raise AssertionError("no requests without credentials")

    client = mock_client(handler)
    summary = await auth_testing.run_auth_tests(
        TARGET,
        [{"id": 1, "method": "GET", "path": "/api/users", "params": [{"name": "api_key", "in": "query"}]}],
        client=client,
    )
    await client.aclose()

    assert summary.requests_sent == 0
    assert any(result.check == "api_key_in_url" for result in summary.results)


@pytest.mark.anyio
async def test_run_auth_tests_comparative_request():
    def handler(request):
        return httpx.Response(200, json={"items": [1, 2, 3]})

    token = make_jwt(
        {"alg": "HS256"},
        {
            "sub": "1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,
            "aud": "api",
            "iss": "issuer",
            "nbf": int(time.time()),
        },
    )
    client = mock_client(handler)
    summary = await auth_testing.run_auth_tests(
        TARGET,
        [
            {
                "id": 1,
                "method": "GET",
                "path": "/api/users",
                "host": "127.0.0.1",
                "params": None,
                "auth_required": True,
            }
        ],
        token=token,
        client=client,
    )
    await client.aclose()

    assert summary.requests_sent == 2
    assert any(result.check == "authz_unauthorized_success" for result in summary.results)
