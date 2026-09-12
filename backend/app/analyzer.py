"""Shared HTTP plumbing and the discovery orchestration entrypoint.

Every outbound request made by Yari goes through helpers in this module so the
safe-by-default policy is uniform: identifiable User-Agent, explicit timeouts,
bounded redirects and no TLS verification skipping.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx

SERVICE_VERSION = "0.1.0"
DEFAULT_USER_AGENT = (
    f"Yari/{SERVICE_VERSION} (XWA API security testing; +https://github.com/xwebanalysis)"
)
DEFAULT_TIMEOUT = 15.0
MAX_CONCURRENCY = 3


class TargetError(Exception):
    """Raised when the target cannot be reached, parsed or is unsafe to scan."""


def normalize_target(target: str) -> str:
    """Return an absolute http(s) URL for ``target``.

    Bare hostnames default to ``https://``. Non-http(s) schemes are rejected so
    a task can never be pointed at ``file://`` or similar.
    """
    value = (target or "").strip()
    if not value:
        raise TargetError("Target must not be empty.")
    if "://" not in value:
        value = f"https://{value}"
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, ValueError) as exc:
        raise TargetError(f"Invalid target URL: {exc}") from exc
    if url.scheme not in ("http", "https"):
        raise TargetError("Only http:// and https:// targets are supported.")
    if not url.host:
        raise TargetError("Target URL is missing a host.")
    return str(url)


def new_client(
    timeout: float = DEFAULT_TIMEOUT,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> httpx.AsyncClient:
    """Create the shared async HTTP client (tests inject a MockTransport)."""
    return httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=5,
        timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"},
        transport=transport,
    )


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    **kwargs: Any,
) -> httpx.Response:
    """Perform one request, mapping transport errors to ``TargetError``."""
    try:
        return await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        raise TargetError(f"Request to {url} failed: {exc}") from exc


async def discover(
    target: str,
    max_bundles: int = 10,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = DEFAULT_TIMEOUT,
    progress=None,
):
    """Normalize ``target`` and run the full read-only discovery pipeline.

    Returns a :class:`app.discovery.DiscoveryResult`. ``progress`` is an optional
    async callable ``(phase, message, data)`` used by the WebSocket endpoint.
    """
    from . import discovery  # local import avoids a module cycle

    normalized = normalize_target(target)
    owns_client = client is None
    if client is None:
        client = new_client(timeout=timeout)
    try:
        return await discovery.discover_target(
            client, normalized, max_bundles=max_bundles, progress=progress
        )
    finally:
        if owns_client:
            await client.aclose()
