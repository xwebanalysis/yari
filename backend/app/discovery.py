"""Read-only API surface discovery: OpenAPI, GraphQL, gRPC and JS crawling.

Every probe in this module is a plain GET/POST introspection request against
documented paths. No payloads, no mutations, no brute force: the module only
asks the target what it already exposes.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

import httpx
import yaml

from .analyzer import TargetError, fetch

# ── Safety limits ───────────────────────────────────────────────────────────

MAX_SPEC_ENDPOINTS = 200
MAX_GRAPHQL_FIELDS = 100
MAX_JS_ENDPOINTS = 100
MAX_BUNDLE_BYTES = 1024 * 1024  # 1 MB per bundle
MAX_BUNDLES = 10
MAX_SPEC_BYTES = 2 * 1024 * 1024
MAX_BODY_PARAMS = 10
MAX_ENUM_VALUES = 8
GRPC_PROBE_TIMEOUT = 3.0

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/docs",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql")
GRPC_DEFAULT_PORTS = (50051,)

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")

# Common API prefixes used to *classify* crawled URLs (never probed blindly).
COMMON_API_PREFIXES = ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/rpc")

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

ProgressCallback = Optional[Callable[[str, str, dict], Any]]


# ── Result types ────────────────────────────────────────────────────────────


@dataclass
class DiscoveredEndpoint:
    protocol: str  # rest | graphql | grpc
    path: str
    method: Optional[str] = None
    host: Optional[str] = None
    params: Optional[list[dict]] = None
    auth_required: Optional[bool] = None
    source: str = "html"  # openapi | graphql_introspection | grpc_reflection | grpc_passive | js_crawl | html
    content_types: Optional[list[str]] = None
    version: Optional[str] = None


@dataclass
class DiscoveryFinding:
    severity: str
    category: str
    check: str
    title: str
    description: str
    target_url: str
    evidence: dict = field(default_factory=dict)
    confidence: str = "medium"


@dataclass
class DiscoveryResult:
    final_url: str
    title: Optional[str] = None
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    findings: list[DiscoveryFinding] = field(default_factory=list)
    specs_found: list[str] = field(default_factory=list)
    bundles_scanned: int = 0
    grpc_mode: str = "unavailable"  # reflection | passive | unavailable


# ── Helpers ─────────────────────────────────────────────────────────────────


def _host_of(url: str) -> Optional[str]:
    try:
        return httpx.URL(url).host
    except (httpx.InvalidURL, ValueError):
        return None


def _absolute(base_url: str, ref: str) -> Optional[str]:
    ref = (ref or "").strip()
    if not ref or ref.startswith(("data:", "blob:", "javascript:", "mailto:", "about:", "#")):
        return None
    if ref.startswith("//"):
        ref = "https:" + ref
    try:
        return str(httpx.URL(base_url).join(ref))
    except (httpx.InvalidURL, ValueError):
        return None


def _parse_spec_text(raw: str) -> Optional[dict]:
    """Parse a JSON or YAML OpenAPI/Swagger document; return None when it is not one."""
    text = (raw or "").strip()
    if not text or len(text) > MAX_SPEC_BYTES:
        return None
    data: Any = None
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    if not (data.get("paths") or data.get("openapi") or data.get("swagger")):
        return None
    return data


def _type_name(schema: Any) -> Optional[str]:
    if isinstance(schema, str):
        return schema
    if isinstance(schema, dict):
        if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
            return f"array<{_type_name(schema['items']) or 'any'}>"
        if schema.get("type"):
            return str(schema["type"])
        if "$ref" in schema:
            return str(schema["$ref"]).rsplit("/", 1)[-1]
        if "items" in schema and isinstance(schema["items"], dict):
            return f"array<{_type_name(schema['items']) or 'any'}>"
    return None


def _enum_values(schema: Any) -> Optional[list]:
    """Extract a bounded list of scalar enum values from a schema (or None)."""
    if not isinstance(schema, dict):
        return None
    enum = schema.get("enum")
    if not isinstance(enum, list):
        return None
    values = [v for v in enum if isinstance(v, (str, int, float, bool))]
    return values[:MAX_ENUM_VALUES] or None


def _schema_param(name: str, location: str, schema: Any, required: bool = False) -> dict:
    """Build a typed param dict from an OpenAPI parameter/property schema.

    Type + enum metadata is what the fuzzer later uses to derive benign,
    schema-typed payloads (string→canary, integer→-1/0/1, boolean, enums).
    """
    param: dict = {
        "name": name,
        "in": location,
        "required": bool(required),
        "type": _type_name(schema),
    }
    enum = _enum_values(schema)
    if enum is not None:
        param["enum"] = enum
    return param


def _extract_body_params(operation: dict) -> list[dict]:
    """Extract typed ``body`` params from an OpenAPI 3 requestBody.

    Only inline JSON-object schemas are expanded (properties with type/enum);
    ``$ref``-only bodies are skipped so no lookup into ``components`` happens.
    """
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []
    media = next((m for m in content if "json" in str(m).lower()), next(iter(content), None))
    if media is None:
        return []
    schema = content[media].get("schema")
    if not isinstance(schema, dict) or not isinstance(schema.get("properties"), dict):
        return []
    required = set(schema.get("required") or [])
    params: list[dict] = []
    for name, prop_schema in list(schema["properties"].items())[:MAX_BODY_PARAMS]:
        if not isinstance(prop_schema, dict):
            continue
        params.append(_schema_param(str(name), "body", prop_schema, name in required))
    return params


def parse_openapi_spec(spec: dict, base_url: str) -> list[DiscoveredEndpoint]:
    """Extract REST endpoints from a parsed OpenAPI 2/3 document."""
    info = spec.get("info") or {}
    version = str(info.get("version")) if info.get("version") is not None else None

    host = _host_of(base_url)
    base_path = ""
    servers = spec.get("servers") or []
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = str(servers[0].get("url") or "")
        if server_url.startswith(("http://", "https://")):
            parsed_server = httpx.URL(server_url)
            host = parsed_server.host or host
            base_path = parsed_server.path.rstrip("/")
        elif server_url.startswith("/"):
            base_path = server_url.rstrip("/")
    elif spec.get("host"):  # Swagger 2.0
        host = str(spec.get("host"))
        base_path = str(spec.get("basePath") or "").rstrip("/")

    global_security = spec.get("security")
    endpoints: list[DiscoveredEndpoint] = []

    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict) or len(endpoints) >= MAX_SPEC_ENDPOINTS:
            break
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            params: list[dict] = []
            for raw_param in list(path_item.get("parameters") or []) + list(
                operation.get("parameters") or []
            ):
                if not isinstance(raw_param, dict) or "$ref" in raw_param:
                    continue
                name = str(raw_param.get("name") or "")
                if not name:
                    continue
                params.append(
                    _schema_param(
                        name,
                        str(raw_param.get("in") or "query"),
                        raw_param.get("schema") or raw_param.get("type"),
                        raw_param.get("required"),
                    )
                )
            params.extend(_extract_body_params(operation))

            security = operation.get("security", global_security)
            if "security" not in operation and global_security is None:
                auth_required: Optional[bool] = None
            else:
                # An empty requirement object ({}) means "optional auth".
                auth_required = bool(security) and not any(not req for req in security)

            content_types: list[str] = []
            request_body = operation.get("requestBody")
            if isinstance(request_body, dict) and isinstance(request_body.get("content"), dict):
                content_types = list(request_body["content"].keys())
            if operation.get("consumes"):
                content_types = list(operation["consumes"])
            elif spec.get("consumes"):
                content_types = list(spec["consumes"])

            full_path = f"{base_path}{path}" if base_path else path
            endpoints.append(
                DiscoveredEndpoint(
                    protocol="rest",
                    method=method.upper(),
                    path=full_path or "/",
                    host=host,
                    params=params or None,
                    auth_required=auth_required,
                    source="openapi",
                    content_types=content_types or None,
                    version=version,
                )
            )
    return endpoints


def _unwrap_type(type_ref: Any) -> Optional[str]:
    """Follow GraphQL ``ofType`` chains down to a named kind/type."""
    current = type_ref
    for _ in range(8):
        if not isinstance(current, dict):
            return None
        if current.get("name"):
            return str(current["name"])
        current = current.get("ofType")
    return None


def parse_graphql_introspection(
    payload: dict, path: str, base_url: str = ""
) -> tuple[list[DiscoveredEndpoint], list[DiscoveryFinding]]:
    """Parse an introspection response into one endpoint + an info finding."""
    schema = (payload or {}).get("data", {}).get("__schema") if isinstance(payload, dict) else None
    if not isinstance(schema, dict):
        return [], []

    types = {t.get("name"): t for t in schema.get("types") or [] if isinstance(t, dict)}

    def fields_for(operation_name: Optional[str], kind: str) -> list[dict]:
        if not operation_name:
            return []
        type_def = types.get(operation_name) or {}
        fields: list[dict] = []
        for field_def in type_def.get("fields") or []:
            if not isinstance(field_def, dict):
                continue
            fields.append(
                {
                    "name": str(field_def.get("name") or ""),
                    "in": "graphql",
                    "type": _unwrap_type(field_def.get("type")),
                    "operation": kind,
                }
            )
        return fields[:MAX_GRAPHQL_FIELDS]

    query_name = (schema.get("queryType") or {}).get("name")
    mutation_name = (schema.get("mutationType") or {}).get("name")
    params = fields_for(query_name, "query")
    mutation_params = fields_for(mutation_name, "mutation")
    params.extend(mutation_params)

    hint = ""
    if isinstance(schema.get("queryType"), dict):
        hint = str(query_name or "")

    endpoint = DiscoveredEndpoint(
        protocol="graphql",
        method="POST",
        path=path,
        host=_host_of(base_url) if base_url else None,
        params=params[:MAX_GRAPHQL_FIELDS] or None,
        auth_required=None,
        source="graphql_introspection",
        content_types=["application/json"],
        version=hint or None,
    )
    finding = DiscoveryFinding(
        severity="low",
        category="disclosure",
        check="graphql_introspection_enabled",
        title="GraphQL introspection is enabled",
        description=(
            "The GraphQL endpoint answers introspection queries, exposing the full "
            "schema (types, queries and mutations). Consider disabling introspection "
            "in production."
        ),
        target_url=path,
        evidence={
            "endpoint": path,
            "types_exposed": len(types),
            "query_fields": len([p for p in params if p.get("operation") == "query"]),
            "mutation_fields": len(mutation_params),
        },
        confidence="high",
    )
    return [endpoint], [finding]


JS_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"""fetch\(\s*[`'"]([^`'"]+)[`'"]"""),
    re.compile(r"""axios\.(?:get|post|put|patch|delete|head|options)\(\s*[`'"]([^`'"]+)[`'"]"""),
    re.compile(r"""\.open\(\s*['"]([A-Za-z]+)['"]\s*,\s*['"]([^'"]+)['"]"""),
    re.compile(r"""url:\s*[`'"]([^`'"]+)[`'"]"""),
)


def _is_api_like(url: str) -> bool:
    path = httpx.URL(url).path.lower()
    return any(path == prefix or path.startswith(prefix + "/") for prefix in COMMON_API_PREFIXES)


def extract_js_urls(
    text: str, base_url: str, source: str = "js_crawl"
) -> list[tuple[str, str, Optional[str]]]:
    """Extract API-looking URLs from HTML/JS text.

    Returns ``(url, source, method)`` tuples where ``source`` is ``js_crawl`` or
    ``html``. Only explicit calls (fetch/axios/XHR/url:) or common API prefixes
    are kept, so plain marketing links do not pollute the endpoint list.
    """
    found: dict[str, tuple[str, str, Optional[str]]] = {}

    for pattern in JS_PATTERNS:
        is_xhr = pattern.pattern.startswith(r"\.open")
        for match in pattern.finditer(text or ""):
            if is_xhr:
                method, ref = match.group(1).upper(), match.group(2)
            else:
                method, ref = None, match.group(1)
            absolute = _absolute(base_url, ref)
            if absolute and _is_api_like(absolute):
                found.setdefault(absolute, (absolute, source, method))

    for match in re.finditer(r"""["'`](/[A-Za-z0-9._~\-/]*(?:api|graphql|v[123])[A-Za-z0-9._~\-/]*)["'`]""", text or ""):
        absolute = _absolute(base_url, match.group(1))
        if absolute and _is_api_like(absolute):
            found.setdefault(absolute, (absolute, source, None))

    return list(found.values())


def looks_like_http2(data: bytes) -> bool:
    """Heuristic: does a socket reply look like an HTTP/2 frame (SETTINGS/PING/GOAWAY)?"""
    if len(data) < 9 or data.startswith(b"HTTP/") or data[:3] == b"PRI":
        return False
    length = int.from_bytes(data[0:3], "big")
    frame_type = data[3]
    return length < 16384 and frame_type in (0x04, 0x06, 0x07)


# ── Protocol probes ─────────────────────────────────────────────────────────


async def _probe_openapi(
    client: httpx.AsyncClient, target: str, progress: ProgressCallback = None
) -> tuple[list[DiscoveredEndpoint], list[DiscoveryFinding], list[str]]:
    endpoints: list[DiscoveredEndpoint] = []
    findings: list[DiscoveryFinding] = []
    specs_found: list[str] = []

    for path in OPENAPI_PATHS:
        if progress:
            await progress("openapi", f"Probing {path}", {"path": path})
        try:
            response = await fetch(client, target.rstrip("/") + path)
        except TargetError:
            continue

        if path == "/docs" and response.status_code < 400:
            # Swagger UI page: look for the spec URL it loads.
            match = re.search(r"""url:\s*["']([^"']+)["']""", response.text or "")
            if match:
                spec_url = _absolute(str(response.url), match.group(1))
                if spec_url:
                    if progress:
                        await progress("openapi", f"Fetching spec referenced by /docs", {"path": spec_url})
                    try:
                        response = await fetch(client, spec_url)
                    except TargetError:
                        continue

        spec = _parse_spec_text(response.text or "")
        if not spec:
            continue

        specs_found.append(str(response.url))
        parsed = parse_openapi_spec(spec, str(response.url))
        endpoints.extend(parsed)
        if progress:
            await progress(
                "openapi",
                f"Parsed {len(parsed)} endpoint(s) from {path}",
                {"path": str(response.url), "endpoints": len(parsed)},
            )
        break

    if specs_found:
        findings.append(
            DiscoveryFinding(
                severity="info",
                category="disclosure",
                check="openapi_spec_public",
                title="OpenAPI/Swagger specification is publicly reachable",
                description=(
                    "A machine-readable API specification is exposed without "
                    "authentication. Review whether public schema exposure is intended."
                ),
                target_url=specs_found[0],
                evidence={"spec_url": specs_found[0], "endpoints": len(endpoints)},
                confidence="high",
            )
        )
    return endpoints, findings, specs_found


async def _probe_graphql(
    client: httpx.AsyncClient, target: str, progress: ProgressCallback = None
) -> tuple[list[DiscoveredEndpoint], list[DiscoveryFinding]]:
    query = (
        "query YariIntrospection { __schema { queryType { name } "
        "mutationType { name } types { name kind "
        "fields { name type { name kind ofType { name kind ofType { name kind } } } } } } }"
    )
    endpoints: list[DiscoveredEndpoint] = []
    findings: list[DiscoveryFinding] = []

    for path in GRAPHQL_PATHS:
        if progress:
            await progress("graphql", f"Probing {path}", {"path": path})
        try:
            response = await fetch(
                client,
                target.rstrip("/") + path,
                method="POST",
                json={"query": query, "operationName": "YariIntrospection"},
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except TargetError:
            continue
        if response.status_code >= 500:
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        probe_endpoints, probe_findings = parse_graphql_introspection(
            payload, path, str(response.url)
        )
        if probe_endpoints:
            endpoints.extend(probe_endpoints)
            findings.extend(probe_findings)
            break
    return endpoints, findings


async def _probe_landing(
    client: httpx.AsyncClient, target: str, progress: ProgressCallback = None
) -> tuple[str, Optional[str], str, list[str], str]:
    """Fetch the landing page; return (final_url, title, html, scripts, header_blob)."""
    if progress:
        await progress("crawl", f"Fetching {target}", {"target": target})
    response = await fetch(client, target)
    html = response.text or ""
    title = None
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip() or None

    scripts: list[str] = []
    for match in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", html, re.IGNORECASE):
        absolute = _absolute(str(response.url), match.group(1))
        if absolute and absolute.endswith((".js", ".mjs", ".jsx", ".ts")) and absolute not in scripts:
            scripts.append(absolute)
    header_blob = " ".join(f"{key}:{value}" for key, value in response.headers.items()).lower()
    return str(response.url), title, html, scripts[:MAX_BUNDLES], header_blob


async def _crawl_js(
    client: httpx.AsyncClient,
    html: str,
    scripts: list[str],
    base_url: str,
    max_bundles: int,
    progress: ProgressCallback = None,
) -> tuple[list[DiscoveredEndpoint], int]:
    endpoints: list[DiscoveredEndpoint] = []
    seen: set[str] = set()
    bundles_scanned = 0

    for url, source, method in extract_js_urls(html, base_url, source="html"):
        if url not in seen:
            seen.add(url)
            endpoints.append(
                DiscoveredEndpoint(
                    protocol="rest",
                    method=method,
                    path=httpx.URL(url).path or "/",
                    host=_host_of(url),
                    params=None,
                    auth_required=None,
                    source=source,
                )
            )

    for script_url in scripts[: min(max_bundles, MAX_BUNDLES)]:
        if len(endpoints) >= MAX_JS_ENDPOINTS:
            break
        if progress:
            await progress("crawl", f"Scanning bundle {script_url}", {"bundle": script_url})
        try:
            response = await fetch(client, script_url)
        except TargetError:
            continue
        content = response.content or b""
        bundles_scanned += 1
        if len(content) > MAX_BUNDLE_BYTES:
            continue
        for url, source, method in extract_js_urls(
            content.decode("utf-8", errors="ignore"), base_url
        ):
            if url not in seen and len(endpoints) < MAX_JS_ENDPOINTS:
                seen.add(url)
                endpoints.append(
                    DiscoveredEndpoint(
                        protocol="rest",
                        method=method,
                        path=httpx.URL(url).path or "/",
                        host=_host_of(url),
                        params=None,
                        auth_required=None,
                        source=source,
                    )
                )
    return endpoints[:MAX_JS_ENDPOINTS], bundles_scanned


async def _probe_http2(host: str, port: int, timeout: float = GRPC_PROBE_TIMEOUT) -> bool:
    """Send the HTTP/2 client preface and inspect the first server frame."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(HTTP2_PREFACE)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(64), timeout=timeout)
        return looks_like_http2(data)
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _grpc_reflection_services(host: str, port: int, timeout: float = 5.0) -> Optional[list[str]]:
    """Optional gRPC server reflection probe (requires grpcio + grpcio-reflection).

    Returns ``None`` when the optional packages are not installed or the server
    does not expose reflection. Blocking: call through ``asyncio.to_thread``.
    """
    try:  # pragma: no cover - optional dependency path
        import grpc
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    except ImportError:
        return None

    channel = None
    try:  # pragma: no cover - network path
        channel = grpc.insecure_channel(f"{host}:{port}")
        grpc.channel_ready_future(channel).result(timeout=timeout)
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(list_services="")
        services: list[str] = []
        for response in stub.ServerReflectionInfo(iter([request]), timeout=timeout):
            listing = response.list_services_response
            if listing is None:
                continue
            for service in listing.service:
                if service.name:
                    services.append(service.name)
        return services or None
    except Exception:
        return None
    finally:
        if channel is not None:
            channel.close()


async def _probe_grpc(
    target: str,
    base_url: str,
    header_blob: str = "",
    progress: ProgressCallback = None,
) -> tuple[list[DiscoveredEndpoint], str]:
    """Passive gRPC detection: headers, HTTP/2 preface, optional reflection."""
    host = _host_of(target)
    if not host:
        return [], "unavailable"

    header_hint = "application/grpc" in header_blob or "grpc-status" in header_blob

    url = httpx.URL(target)
    ports: list[int] = []
    if url.port:
        ports.append(url.port)
    ports.extend(GRPC_DEFAULT_PORTS)
    ports = list(dict.fromkeys(ports))

    h2_port: Optional[int] = None
    for port in ports:
        if progress:
            await progress("grpc", f"Checking HTTP/2 on {host}:{port}", {"host": host, "port": port})
        if await _probe_http2(host, port):
            h2_port = port
            break

    if h2_port is None and not header_hint:
        return [], "unavailable"

    services: Optional[list[str]] = None
    if h2_port is not None:
        services = await asyncio.to_thread(_grpc_reflection_services, host, h2_port)
    if services:
        endpoints = [
            DiscoveredEndpoint(
                protocol="grpc",
                method=None,
                path=f"/{service}",
                host=host,
                params=[{"name": service, "in": "service", "type": "service"}],
                auth_required=None,
                source="grpc_reflection",
            )
            for service in services
        ]
        if progress:
            await progress(
                "grpc",
                f"gRPC reflection exposed {len(services)} service(s)",
                {"services": services},
            )
        return endpoints, "reflection"

    # HTTP/2 (or gRPC headers) confirmed but reflection unavailable: passive hint.
    detail = (
        f"HTTP/2 confirmed on port {h2_port}"
        if h2_port is not None
        else "gRPC content-type detected in response headers"
    )
    endpoint = DiscoveredEndpoint(
        protocol="grpc",
        method=None,
        path="*",
        host=host,
        params=[
            {
                "name": "server-reflection",
                "in": "service",
                "type": "unknown",
                "note": f"{detail}; server reflection not advertised",
            }
        ],
        auth_required=None,
        source="grpc_passive",
    )
    if progress:
        await progress("grpc", f"{detail} (passive)", {"port": h2_port})
    return [endpoint], "passive"


# ── Pipeline ────────────────────────────────────────────────────────────────


def _dedupe(endpoints: Iterable[DiscoveredEndpoint]) -> list[DiscoveredEndpoint]:
    unique: dict[tuple, DiscoveredEndpoint] = {}
    for endpoint in endpoints:
        key = (endpoint.protocol, endpoint.method or "", endpoint.path, endpoint.host or "")
        unique.setdefault(key, endpoint)
    order = {"rest": 0, "graphql": 1, "grpc": 2}
    return sorted(unique.values(), key=lambda e: (order.get(e.protocol, 9), e.path, e.method or ""))


async def discover_target(
    client: httpx.AsyncClient,
    target: str,
    max_bundles: int = MAX_BUNDLES,
    progress: ProgressCallback = None,
) -> DiscoveryResult:
    """Run the whole read-only pipeline. ``target`` must already be normalized."""
    result = DiscoveryResult(final_url=target)

    result.final_url, result.title, html, scripts, header_blob = await _probe_landing(
        client, target, progress
    )

    openapi_endpoints, openapi_findings, specs = await _probe_openapi(
        client, target, progress
    )
    graphql_endpoints, graphql_findings = await _probe_graphql(client, target, progress)

    js_endpoints, bundles_scanned = await _crawl_js(
        client, html, scripts, result.final_url, max_bundles, progress
    )

    grpc_endpoints, grpc_mode = await _probe_grpc(
        target, result.final_url, header_blob, progress
    )

    result.endpoints = _dedupe(
        openapi_endpoints + graphql_endpoints + js_endpoints + grpc_endpoints
    )
    result.findings = openapi_findings + graphql_findings
    result.specs_found = specs
    result.bundles_scanned = bundles_scanned
    result.grpc_mode = grpc_mode
    return result
