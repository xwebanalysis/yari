"""Safe-by-default request fuzzing engine.

Design goals (user requirement: never get blocked or blacklisted):

- ``safe`` mode is the default and has a hard global budget of 20 requests.
- Only ``GET``/``HEAD``/``OPTIONS`` are contacted unless ``allow_mutations`` is
  explicitly enabled by the caller; mutating methods are skipped otherwise.
- Every request is separated by a 300–1000 ms jitter delay (except the small
  rate-limit probe burst, which is 3 requests).
- The engine aborts immediately when the target answers ``429`` or ``503``.
- Payloads are benign canaries/error triggers (``'``, ``"``, ``%00``, ``{}``,
  ``-1``); no exploitation payloads, no credential fuzzing, no injection of
  destructive values.
"""

from __future__ import annotations

import asyncio
import random
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import httpx

from .analyzer import new_client, normalize_target

SAFE_MAX_REQUESTS = 20
DEFAULT_DELAY_MS = (300, 1000)
RATE_LIMIT_BURST_DELAY_MS = 50
DEFAULT_TIMEOUT = 10.0
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ABORT_STATUS = {429, 503}
ERROR_PAYLOADS = ("'", '"', "%00", "{}", "-1")
CANARY_PREFIX = "xwa-canary-"
STRATEGIES = ("safe", "reflect", "error_based", "authz_matrix", "rate_limit")
RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-rate-limit-limit",
    "ratelimit-limit",
    "retry-after",
)


class FuzzBudgetExceeded(Exception):
    """Raised internally when the global request budget is exhausted."""


@dataclass
class FuzzFinding:
    severity: str
    category: str
    check: str
    title: str
    description: str
    target_url: str
    evidence: dict = field(default_factory=dict)
    confidence: str = "medium"


@dataclass
class FuzzOutcome:
    strategy: str
    requests_sent: int = 0
    findings: list[FuzzFinding] = field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None
    skipped_reason: Optional[str] = None
    endpoint: Optional[dict] = None

    @property
    def status(self) -> str:
        if self.skipped_reason:
            return "SKIPPED"
        if self.aborted:
            return "ABORTED"
        return "COMPLETED"


@dataclass
class FuzzSummary:
    strategy: str
    requests_sent: int
    findings: list[FuzzFinding] = field(default_factory=list)
    outcomes: list[FuzzOutcome] = field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None


def endpoint_url(target: str, endpoint: dict) -> str:
    """Build the absolute URL for an endpoint (host override aware)."""
    base = httpx.URL(normalize_target(target))
    host = endpoint.get("host") or base.host
    path = endpoint.get("path") or "/"
    if host == base.host:
        origin = httpx.URL(f"{base.scheme}://{base.host}:{base.port or (443 if base.scheme == 'https' else 80)}/")
    else:
        origin = httpx.URL(f"{base.scheme}://{host}/")
    return str(origin.join(path if path.startswith("/") else "/" + path))


def _fill_path(template: str, params: list[dict], inject: Optional[dict]) -> str:
    """Substitute ``{name}`` placeholders; unknown templates become ``1``."""
    result = template or "/"
    for param in params:
        name = param.get("name")
        if param.get("in") == "path" and name:
            value = inject.get("value") if inject and inject.get("name") == name else "1"
            result = result.replace("{" + str(name) + "}", str(value))
    return re.sub(r"\{[^}]+\}", "1", result)


class SafeFuzzer:
    """Budgeted, rate-limited request mutator for one target."""

    def __init__(
        self,
        target: str,
        client: httpx.AsyncClient,
        max_requests: int = SAFE_MAX_REQUESTS,
        delay_ms: tuple[int, int] = DEFAULT_DELAY_MS,
        timeout: float = DEFAULT_TIMEOUT,
        allow_mutations: bool = False,
        auth_token: Optional[str] = None,
        auth_cookie: Optional[str] = None,
    ) -> None:
        self.target = normalize_target(target)
        self.client = client
        self.max_requests = max(1, min(max_requests, SAFE_MAX_REQUESTS))
        self.delay_ms = delay_ms
        self.timeout = timeout
        self.allow_mutations = allow_mutations
        self.sent = 0
        self.aborted = False
        self.abort_reason: Optional[str] = None
        self.auth_headers: dict[str, str] = {}
        if auth_token:
            self.auth_headers["Authorization"] = f"Bearer {auth_token}"
        if auth_cookie:
            self.auth_headers["Cookie"] = auth_cookie

    # ── request plumbing ────────────────────────────────────────────────

    def _ensure_budget(self) -> None:
        if self.aborted:
            raise FuzzBudgetExceeded(self.abort_reason or "run aborted")
        if self.sent >= self.max_requests:
            raise FuzzBudgetExceeded("global request budget exhausted")

    async def _delay(self, fast: bool = False) -> None:
        low, high = self.delay_ms
        if low <= 0 and high <= 0:
            return
        wait = RATE_LIMIT_BURST_DELAY_MS if fast else random.uniform(low, high)
        await asyncio.sleep(wait / 1000.0)

    async def _send(
        self,
        method: str,
        url: str,
        fast: bool = False,
        headers: Optional[dict] = None,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        self._ensure_budget()
        await self._delay(fast)
        self.sent += 1
        request_headers = dict(headers or {})
        try:
            response = await self.client.request(
                method, url, timeout=self.timeout, headers=request_headers or None, **kwargs
            )
        except httpx.HTTPError:
            return None
        if response.status_code in ABORT_STATUS:
            self.aborted = True
            self.abort_reason = (
                f"Target answered HTTP {response.status_code}; aborting to avoid "
                "triggering blocks or blacklists."
            )
        return response

    def _build(
        self,
        endpoint: dict,
        inject: Optional[dict] = None,
    ) -> tuple[str, dict]:
        """Return (url, kwargs) for a request, optionally injecting one param."""
        params = [p for p in (endpoint.get("params") or []) if isinstance(p, dict)]
        path = _fill_path(endpoint.get("path") or "/", params, inject)
        url = endpoint_url(self.target, {**endpoint, "path": path})

        query: dict[str, str] = {}
        body: dict[str, str] = {}
        for param in params:
            name = param.get("name")
            if not name:
                continue
            location = param.get("in")
            if location == "query":
                query[str(name)] = str(inject.get("value")) if inject and inject.get("name") == name else "1"
            elif location == "body" and self.allow_mutations:
                body[str(name)] = str(inject.get("value")) if inject and inject.get("name") == name else "1"

        kwargs: dict[str, Any] = {}
        if query:
            kwargs["params"] = query
        if body:
            kwargs["json"] = body
        return url, kwargs

    def _injectable(self, endpoint: dict) -> list[dict]:
        return [
            p
            for p in (endpoint.get("params") or [])
            if isinstance(p, dict) and p.get("name") and p.get("in") in ("query", "path", "body")
        ]

    # ── strategies ──────────────────────────────────────────────────────

    async def _strategy_reflect(self, endpoint: dict, outcome: FuzzOutcome) -> None:
        canary = f"{CANARY_PREFIX}{secrets.token_hex(4)}"
        for param in self._injectable(endpoint)[:3]:
            url, kwargs = self._build(endpoint, {"name": param["name"], "value": canary})
            response = await self._send(
                endpoint.get("method") or "GET", url, **kwargs
            )
            if response is None:
                continue
            if canary in (response.text or ""):
                outcome.findings.append(
                    FuzzFinding(
                        severity="low",
                        category="injection",
                        check="reflected_input",
                        title="User input is reflected verbatim in the response",
                        description=(
                            f"Parameter '{param['name']}' reflects a unique canary value in the "
                            "response body without encoding. Encoded reflection can still be "
                            "safe; verify the output context before treating it as a bug."
                        ),
                        target_url=url,
                        evidence={
                            "poc_payload": canary,
                            "param": str(param["name"]),
                            "location": param.get("in"),
                            "status_code": response.status_code,
                        },
                        confidence="high",
                    )
                )

    async def _strategy_error_based(self, endpoint: dict, outcome: FuzzOutcome) -> None:
        method = endpoint.get("method") or "GET"
        baseline_url, baseline_kwargs = self._build(endpoint)
        baseline = await self._send(method, baseline_url, **baseline_kwargs)
        if baseline is None:
            return
        baseline_sig = (baseline.status_code, len(baseline.content or b""))
        recorded = 0

        for payload in ERROR_PAYLOADS:
            if recorded >= 3 or self.aborted:
                break
            for param in self._injectable(endpoint)[:2]:
                url, kwargs = self._build(endpoint, {"name": param["name"], "value": payload})
                response = await self._send(method, url, **kwargs)
                if response is None:
                    continue
                signature = (response.status_code, len(response.content or b""))
                if signature != baseline_sig:
                    recorded += 1
                    outcome.findings.append(
                        FuzzFinding(
                            severity="low" if response.status_code >= 500 else "info",
                            category="disclosure",
                            check="error_based_anomaly",
                            title="Benign payload changes the response signature",
                            description=(
                                f"Parameter '{param['name']}' with payload {payload!r} produced "
                                f"HTTP {signature[0]} / {signature[1]} bytes, while the baseline "
                                f"was HTTP {baseline_sig[0]} / {baseline_sig[1]} bytes. Review "
                                "whether error output leaks internal details."
                            ),
                            target_url=url,
                            evidence={
                                "poc_payload": payload,
                                "param": str(param["name"]),
                                "location": param.get("in"),
                                "baseline": {"status_code": baseline_sig[0], "length": baseline_sig[1]},
                                "observed": {"status_code": signature[0], "length": signature[1]},
                            },
                            confidence="medium",
                        )
                    )
                if self.aborted:
                    break

    async def _strategy_authz_matrix(self, endpoint: dict, outcome: FuzzOutcome) -> None:
        if not self.auth_headers:
            outcome.skipped_reason = "no auth token/cookie provided"
            return
        method = endpoint.get("method") or "GET"
        url, kwargs = self._build(endpoint)

        anonymous = await self._send(method, url, **kwargs)
        if anonymous is None:
            return
        authenticated = await self._send(method, url, headers=self.auth_headers, **kwargs)
        if authenticated is None:
            return

        auth_required = endpoint.get("auth_required")
        if auth_required is True and 200 <= anonymous.status_code < 300:
            outcome.findings.append(
                FuzzFinding(
                    severity="high",
                    category="authz",
                    check="unauthenticated_access",
                    title="Protected endpoint answers without credentials",
                    description=(
                        "An endpoint marked as requiring authentication returned a success "
                        "status to an unauthenticated request."
                    ),
                    target_url=url,
                    evidence={
                        "poc_payload": None,
                        "anonymous_status": anonymous.status_code,
                        "authenticated_status": authenticated.status_code,
                        "auth_required": True,
                    },
                    confidence="medium",
                )
            )
        elif 200 <= anonymous.status_code < 300 and authenticated.status_code in (401, 403):
            outcome.findings.append(
                FuzzFinding(
                    severity="medium",
                    category="auth",
                    check="auth_inverted",
                    title="Credentials are rejected while anonymous access succeeds",
                    description=(
                        "The endpoint accepts unauthenticated traffic but rejects the provided "
                        "credentials, which may indicate broken authorization logic."
                    ),
                    target_url=url,
                    evidence={
                        "poc_payload": None,
                        "anonymous_status": anonymous.status_code,
                        "authenticated_status": authenticated.status_code,
                    },
                    confidence="low",
                )
            )

    async def _strategy_rate_limit(self, endpoint: dict, outcome: FuzzOutcome) -> None:
        method = endpoint.get("method") or "GET"
        url, kwargs = self._build(endpoint)
        responses: list[httpx.Response] = []
        for _ in range(3):
            response = await self._send(method, url, fast=True, **kwargs)
            if response is None:
                break
            responses.append(response)
            if self.aborted:
                break

        if not responses:
            return
        if any(r.status_code == 429 for r in responses):
            return  # rate limiting is enforced: nothing to report
        headers = {k.lower() for response in responses for k in response.headers.keys()}
        if not any(header in headers for header in RATE_LIMIT_HEADERS):
            outcome.findings.append(
                FuzzFinding(
                    severity="info",
                    category="misconfig",
                    check="rate_limit_headers_missing",
                    title="No rate-limit headers observed",
                    description=(
                        "Three rapid requests returned no rate-limit headers (and no HTTP 429). "
                        "Confirm that abuse protection exists in front of the API."
                    ),
                    target_url=url,
                    evidence={
                        "poc_payload": None,
                        "requests": len(responses),
                        "status_codes": [r.status_code for r in responses],
                    },
                    confidence="low",
                )
            )

    # ── public entrypoint ───────────────────────────────────────────────

    async def fuzz_endpoint(self, endpoint: dict, strategy: str) -> FuzzOutcome:
        outcome = FuzzOutcome(strategy=strategy, endpoint=dict(endpoint))
        method = (endpoint.get("method") or "GET").upper()
        if method not in SAFE_METHODS and not self.allow_mutations:
            outcome.skipped_reason = (
                f"{method} is a mutating method; safe mode only touches "
                "GET/HEAD/OPTIONS (enable allow_mutations to override)"
            )
            return outcome

        if strategy not in STRATEGIES:
            outcome.skipped_reason = f"unknown strategy '{strategy}'"
            return outcome

        plan = {
            "safe": ["rate_limit", "reflect", "error_based"]
            + (["authz_matrix"] if self.auth_headers else []),
            "reflect": ["reflect"],
            "error_based": ["error_based"],
            "authz_matrix": ["authz_matrix"],
            "rate_limit": ["rate_limit"],
        }[strategy]

        start = self.sent
        try:
            for step in plan:
                if self.aborted:
                    break
                if step == "rate_limit":
                    await self._strategy_rate_limit(endpoint, outcome)
                elif step == "reflect":
                    await self._strategy_reflect(endpoint, outcome)
                elif step == "error_based":
                    await self._strategy_error_based(endpoint, outcome)
                elif step == "authz_matrix":
                    await self._strategy_authz_matrix(endpoint, outcome)
        except FuzzBudgetExceeded as exc:
            outcome.aborted = True
            outcome.abort_reason = str(exc)

        outcome.requests_sent = self.sent - start
        if self.aborted:
            outcome.aborted = True
            outcome.abort_reason = self.abort_reason
        return outcome


async def run_fuzz(
    target: str,
    endpoints: Iterable[dict],
    strategy: str = "safe",
    max_requests: int = SAFE_MAX_REQUESTS,
    allow_mutations: bool = False,
    auth_token: Optional[str] = None,
    auth_cookie: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    delay_ms: tuple[int, int] = DEFAULT_DELAY_MS,
    timeout: float = DEFAULT_TIMEOUT,
) -> FuzzSummary:
    """Run one strategy across endpoints under the shared global budget."""
    owns_client = client is None
    if client is None:
        client = new_client(timeout=timeout)
    summary = FuzzSummary(strategy=strategy, requests_sent=0)
    fuzzer = SafeFuzzer(
        target,
        client,
        max_requests=max_requests,
        delay_ms=delay_ms,
        timeout=timeout,
        allow_mutations=allow_mutations,
        auth_token=auth_token,
        auth_cookie=auth_cookie,
    )
    try:
        for endpoint in endpoints:
            if fuzzer.aborted:
                break
            outcome = await fuzzer.fuzz_endpoint(endpoint, strategy)
            summary.outcomes.append(outcome)
            summary.findings.extend(outcome.findings)
            if outcome.aborted and not fuzzer.aborted:
                summary.aborted = True
                summary.abort_reason = outcome.abort_reason
        summary.requests_sent = fuzzer.sent
        summary.aborted = fuzzer.aborted or summary.aborted
        summary.abort_reason = fuzzer.abort_reason or summary.abort_reason
    finally:
        if owns_client:
            await client.aclose()
    return summary
