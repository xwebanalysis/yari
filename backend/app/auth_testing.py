"""Passive authentication testing: JWT, session cookies and API keys.

This module never brute-forces credentials and never sends a request unless the
caller already provided a token/cookie for a small comparative check
(``2 requests per endpoint``, hard-capped). JWT inspection is purely local
(base64url decode, no signature verification attempts).
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

import httpx

from .analyzer import new_client
from .fuzzing import endpoint_url

MAX_COMPARE_ENDPOINTS = 2
MAX_COMPARE_REQUESTS = 4
DEFAULT_TIMEOUT = 10.0

SESSIONISH = ("session", "sid", "jwt", "token", "auth", "access", "refresh", "id")
API_KEY_PARAMS = ("api_key", "apikey", "api-key", "access_token", "key", "auth_token")


@dataclass
class AuthTestResult:
    mechanism: str  # jwt | session | apikey
    check: str
    result: str  # pass | info | low | medium | high | critical
    title: str
    description: str
    details: dict = field(default_factory=dict)
    target_url: Optional[str] = None
    confidence: str = "medium"


@dataclass
class AuthTestSummary:
    results: list[AuthTestResult] = field(default_factory=list)
    requests_sent: int = 0

    @property
    def findings(self) -> list[AuthTestResult]:
        return [r for r in self.results if r.result != "pass"]


# ── JWT (local, passive) ────────────────────────────────────────────────────


def _b64url_decode(segment: str) -> Optional[bytes]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def decode_jwt(token: str) -> Optional[tuple[dict, dict]]:
    """Decode header/payload without verifying the signature (analysis only)."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        return None
    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    if not header_raw or not payload_raw:
        return None
    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except ValueError:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def analyze_jwt(token: str) -> list[AuthTestResult]:
    decoded = decode_jwt(token)
    if decoded is None:
        return [
            AuthTestResult(
                mechanism="jwt",
                check="jwt_parse",
                result="info",
                title="Token is not a decodable JWT",
                description=(
                    "The supplied token does not have three base64url segments, so it was "
                    "not analyzed as a JWT."
                ),
            )
        ]

    header, payload = decoded
    alg = str(header.get("alg") or "")
    results: list[AuthTestResult] = []
    now = int(time.time())

    if alg.lower() == "none":
        results.append(
            AuthTestResult(
                mechanism="jwt",
                check="jwt_alg_none",
                result="critical",
                title="JWT accepts the 'none' algorithm",
                description=(
                    "The token header declares alg=none. If the server honours it, signatures "
                    "become optional and any token can be forged."
                ),
                details={"alg": alg, "header_keys": sorted(header.keys())},
                confidence="high",
            )
        )

    if alg.upper().startswith("HS") and "kid" in header:
        results.append(
            AuthTestResult(
                mechanism="jwt",
                check="jwt_hmac_with_kid",
                result="medium",
                title="HMAC JWT uses a 'kid' header",
                description=(
                    "An HS* token with a kid is a classic key-confusion setup. Verify the "
                    "server never accepts asymmetric public keys as HMAC secrets."
                ),
                details={"alg": alg, "kid_present": True},
                confidence="medium",
            )
        )

    if "exp" not in payload:
        results.append(
            AuthTestResult(
                mechanism="jwt",
                check="jwt_missing_exp",
                result="medium",
                title="JWT has no expiration (exp)",
                description="Tokens without exp never expire, widening the replay window.",
                details={"claims": sorted(payload.keys())},
                confidence="high",
            )
        )
    else:
        try:
            exp = int(payload["exp"])
            ttl = exp - now
            if ttl > 7 * 24 * 3600:
                results.append(
                    AuthTestResult(
                        mechanism="jwt",
                        check="jwt_long_expiry",
                        result="medium",
                        title="JWT expiration is unusually long",
                        description=(
                            f"The token is valid for roughly {ttl // 86400} day(s). Long-lived "
                            "tokens increase the impact of leakage; prefer short access tokens "
                            "with rotation."
                        ),
                        details={"ttl_days": ttl // 86400},
                        confidence="high",
                    )
                )
            else:
                results.append(
                    AuthTestResult(
                        mechanism="jwt",
                        check="jwt_expiry_present",
                        result="pass",
                        title="JWT declares a bounded expiration",
                        description=f"Token expires in about {max(ttl, 0) // 60} minute(s).",
                        details={"ttl_seconds": max(ttl, 0)},
                    )
                )
        except (TypeError, ValueError):
            results.append(
                AuthTestResult(
                    mechanism="jwt",
                    check="jwt_exp_not_numeric",
                    result="low",
                    title="JWT exp claim is not numeric",
                    description="exp must be a NumericDate; parsers may fail open or closed.",
                    details={"exp_type": type(payload.get("exp")).__name__},
                )
            )

    for claim, severity in (("nbf", "info"), ("aud", "low"), ("iss", "low"), ("iat", "info")):
        if claim not in payload:
            results.append(
                AuthTestResult(
                    mechanism="jwt",
                    check=f"jwt_missing_{claim}",
                    result=severity,
                    title=f"JWT is missing the '{claim}' claim",
                    description=(
                        f"The '{claim}' claim is absent, which weakens audience/issuer/time "
                        "validation. Confirm the server enforces it another way."
                    ),
                    details={"claims": sorted(payload.keys())},
                    confidence="medium",
                )
            )

    if results:
        return results
    return [
        AuthTestResult(
            mechanism="jwt",
            check="jwt_baseline",
            result="pass",
            title="JWT passed the passive checks",
            description=(
                "The token decodes, declares an algorithm and carries standard time claims. "
                "Signature validation is out of scope for passive analysis."
            ),
            details={"alg": alg, "claims": sorted(payload.keys())},
        )
    ]


# ── Cookies / sessions ──────────────────────────────────────────────────────


def analyze_cookie(cookie_header: str) -> list[AuthTestResult]:
    """Inspect a Cookie header for session hygiene flags (no requests)."""
    results: list[AuthTestResult] = []
    for chunk in (cookie_header or "").split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, _value = chunk.partition("=")
        name = name.strip()
        if not any(hint in name.lower() for hint in SESSIONISH):
            continue
        flags = {part.strip().split("=")[0].lower() for part in cookie_header.split(";")}
        if "httponly" not in flags:
            results.append(
                AuthTestResult(
                    mechanism="session",
                    check="cookie_httponly_missing",
                    result="medium",
                    title=f"Session cookie '{name}' lacks HttpOnly",
                    description=(
                        "Without HttpOnly, JavaScript can read the cookie, so any XSS becomes "
                        "session theft."
                    ),
                    details={"cookie": name},
                    confidence="high",
                )
            )
        if "secure" not in flags:
            results.append(
                AuthTestResult(
                    mechanism="session",
                    check="cookie_secure_missing",
                    result="medium",
                    title=f"Session cookie '{name}' lacks Secure",
                    description="Without Secure the cookie can leak over plaintext HTTP.",
                    details={"cookie": name},
                    confidence="high",
                )
            )
        if "samesite" not in flags:
            results.append(
                AuthTestResult(
                    mechanism="session",
                    check="cookie_samesite_missing",
                    result="low",
                    title=f"Session cookie '{name}' lacks SameSite",
                    description="A missing SameSite attribute enables cross-site request forgery.",
                    details={"cookie": name},
                    confidence="medium",
                )
            )
        elif "samesite=none" in flags and "secure" not in flags:
            results.append(
                AuthTestResult(
                    mechanism="session",
                    check="cookie_samesite_none_insecure",
                    result="medium",
                    title=f"Session cookie '{name}' is SameSite=None without Secure",
                    description="Browsers reject or downgrade this combination; set Secure.",
                    details={"cookie": name},
                    confidence="high",
                )
            )
    return results


def analyze_api_key_in_url(url: str) -> list[AuthTestResult]:
    """Flag API keys/tokens passed as query parameters (no requests)."""
    try:
        query = httpx.URL(url).params
    except (httpx.InvalidURL, ValueError):
        return []
    results: list[AuthTestResult] = []
    for name in query.keys():
        if name.lower() in API_KEY_PARAMS:
            results.append(
                AuthTestResult(
                    mechanism="apikey",
                    check="api_key_in_url",
                    result="medium",
                    title=f"API key/token passed as URL parameter '{name}'",
                    description=(
                        "Credentials in query strings end up in logs, proxies and referrers. "
                        "Prefer the Authorization header."
                    ),
                    details={"param": name},
                    target_url=url.split("?")[0],
                    confidence="high",
                )
            )
    return results


# ── Optional comparative request (few, explicit credentials only) ──────────


def _analysis_url(target: str, endpoint: dict) -> str:
    """URL with neutral query values so parameter-name checks can run locally."""
    url = endpoint_url(target, endpoint)
    query = {
        str(param["name"]): "1"
        for param in (endpoint.get("params") or [])
        if isinstance(param, dict)
        and param.get("name")
        and param.get("in") == "query"
    }
    if query:
        url = str(httpx.URL(url).copy_with(params=query))
    return url


async def run_auth_tests(
    target: str,
    endpoints: Iterable[dict] = (),
    token: Optional[str] = None,
    cookie: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AuthTestSummary:
    """Run the passive checks plus a hard-capped auth/no-auth comparison."""
    summary = AuthTestSummary()
    if token:
        summary.results.extend(analyze_jwt(token))
    if cookie:
        summary.results.extend(analyze_cookie(cookie))

    for endpoint in endpoints:
        summary.results.extend(analyze_api_key_in_url(_analysis_url(target, endpoint)))

    if not (token or cookie) or not endpoints:
        return summary

    owns_client = client is None
    if client is None:
        client = new_client(timeout=timeout)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    mechanism = "jwt" if token else "session"

    try:
        sent = 0
        for endpoint in list(endpoints)[:MAX_COMPARE_ENDPOINTS]:
            method = (endpoint.get("method") or "GET").upper()
            if method not in ("GET", "HEAD"):
                continue
            if sent + 2 > MAX_COMPARE_REQUESTS:
                break
            url = endpoint_url(target, endpoint)
            try:
                anonymous = await client.request(method, url, timeout=timeout)
                sent += 1
                authenticated = await client.request(method, url, timeout=timeout, headers=headers)
                sent += 1
            except httpx.HTTPError:
                break
            if endpoint.get("auth_required") is True and 200 <= anonymous.status_code < 300:
                summary.results.append(
                    AuthTestResult(
                        mechanism=mechanism,
                        check="authz_unauthorized_success",
                        result="high",
                        title="Protected endpoint answers without credentials",
                        description=(
                            "The endpoint advertises authentication but returned a success "
                            "status to the unauthenticated request."
                        ),
                        details={
                            "anonymous_status": anonymous.status_code,
                            "authenticated_status": authenticated.status_code,
                        },
                        target_url=url,
                        confidence="medium",
                    )
                )
        summary.requests_sent = sent
    finally:
        if owns_client:
            await client.aclose()
    return summary
