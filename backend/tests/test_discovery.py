"""Discovery unit/integration tests (OpenAPI, GraphQL, JS crawl, gRPC heuristics)."""

import json

import pytest

from app import discovery


OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Example API", "version": "2.1.0"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users": {
            "get": {
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "required": True, "schema": {"type": "integer"}},
                ],
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
            },
            "post": {
                "requestBody": {"content": {"application/json": {}}},
                "security": [],
            },
        },
        "/users/{id}": {
            "delete": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ]
            }
        },
    },
}

GRAPHQL_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "user", "type": {"name": "User", "kind": "OBJECT"}},
                        {
                            "name": "users",
                            "type": {
                                "kind": "LIST",
                                "ofType": {"name": "User", "kind": "OBJECT"},
                            },
                        },
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "createUser", "type": {"name": "User", "kind": "OBJECT"}}
                    ],
                },
            ],
        }
    }
}


def test_parse_openapi_spec_extracts_endpoints():
    endpoints = discovery.parse_openapi_spec(OPENAPI_SPEC, "https://api.example.com/v2")
    by_key = {(e.method, e.path): e for e in endpoints}

    assert ("GET", "/v2/users") in by_key
    assert ("POST", "/v2/users") in by_key
    assert ("DELETE", "/v2/users/{id}") in by_key

    get_users = by_key[("GET", "/v2/users")]
    assert get_users.protocol == "rest"
    assert get_users.host == "api.example.com"
    assert get_users.source == "openapi"
    assert get_users.version == "2.1.0"
    assert get_users.auth_required is True
    assert get_users.content_types == ["application/json"]

    param_names = {p["name"]: p for p in get_users.params}
    assert param_names["page"]["in"] == "query"
    assert param_names["limit"]["required"] is True
    assert param_names["limit"]["type"] == "integer"

    # operation-level security: [] disables the global requirement
    assert by_key[("POST", "/v2/users")].auth_required is False


def test_parse_spec_text_accepts_json_and_yaml():
    yaml_spec = """
openapi: 3.0.0
info: {title: Mini, version: "1"}
paths:
  /ping:
    get: {}
"""
    parsed_yaml = discovery._parse_spec_text(yaml_spec)
    assert parsed_yaml is not None
    assert "/ping" in parsed_yaml["paths"]

    parsed_json = discovery._parse_spec_text(json.dumps(OPENAPI_SPEC))
    assert parsed_json is not None
    assert parsed_json["openapi"] == "3.0.3"

    assert discovery._parse_spec_text("<html>not a spec</html>") is None


def test_parse_graphql_introspection_builds_endpoint_and_finding():
    endpoints, findings = discovery.parse_graphql_introspection(
        GRAPHQL_INTROSPECTION, "/graphql", "https://api.example.com/graphql"
    )
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.protocol == "graphql"
    assert endpoint.method == "POST"
    assert endpoint.source == "graphql_introspection"
    operations = {p["name"]: p["operation"] for p in endpoint.params}
    assert operations == {"user": "query", "users": "query", "createUser": "mutation"}

    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].check == "graphql_introspection_enabled"


def test_parse_graphql_introspection_tolerates_null_mutation_type():
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [{"name": "ping", "type": {"name": "String", "kind": "SCALAR"}}],
                    }
                ],
            }
        }
    }
    endpoints, findings = discovery.parse_graphql_introspection(payload, "/graphql")
    assert len(endpoints) == 1
    assert endpoints[0].params == [
        {"name": "ping", "in": "graphql", "type": "String", "operation": "query"}
    ]
    assert findings[0].check == "graphql_introspection_enabled"


@pytest.mark.anyio
async def test_discover_openapi_over_mock_transport():
    from tests.conftest import mock_client

    def handler(request):
        path = request.url.path
        if path == "/openapi.json":
            return httpx_response(200, json.dumps(OPENAPI_SPEC), "application/json")
        if path == "/graphql" and request.method == "POST":
            return httpx_response(200, json.dumps({"errors": [{"message": "no"}]}), "application/json")
        if path == "/":
            return httpx_response(200, "<html><title>Example</title></html>", "text/html")
        return httpx_response(404, "not found", "text/plain")

    client = mock_client(handler)
    result = await discovery.discover_target(client, "http://127.0.0.1:9999")
    await client.aclose()

    assert result.title == "Example"
    assert result.specs_found == ["http://127.0.0.1:9999/openapi.json"]
    paths = {(e.method, e.path) for e in result.endpoints if e.protocol == "rest"}
    assert ("GET", "/v2/users") in paths
    assert any(f.check == "openapi_spec_public" for f in result.findings)


@pytest.mark.anyio
async def test_discover_graphql_over_mock_transport():
    from tests.conftest import mock_client

    def handler(request):
        if request.url.path == "/graphql" and request.method == "POST":
            body = json.loads(request.content)
            assert "__schema" in body["query"]
            return httpx_response(200, json.dumps(GRAPHQL_INTROSPECTION), "application/json")
        if request.url.path == "/openapi.json":
            return httpx_response(404, "nope", "text/plain")
        return httpx_response(200, "<html><title>GQL</title></html>", "text/html")

    client = mock_client(handler)
    result = await discovery.discover_target(client, "http://127.0.0.1:9999")
    await client.aclose()

    graphql = [e for e in result.endpoints if e.protocol == "graphql"]
    assert graphql and graphql[0].path == "/graphql"
    assert any(f.check == "graphql_introspection_enabled" for f in result.findings)


def test_extract_js_urls_classifies_and_filters():
    text = """
    <html><body><script>
      fetch('/api/v1/users?page=1');
      axios.post('/v1/orders', {});
      const x = new XMLHttpRequest(); x.open('DELETE', '/api/items/7');
      const cfg = { url: '/api/config' };
      const ext = 'https://cdn.example.com/lib.js';
      const link = '/about/team';
    </script></body></html>
    """
    urls = {url: (source, method) for url, source, method in discovery.extract_js_urls(text, "https://app.example.com")}

    assert "https://app.example.com/api/v1/users?page=1" in urls
    assert urls["https://app.example.com/v1/orders"] == ("js_crawl", None)
    assert urls["https://app.example.com/api/items/7"] == ("js_crawl", "DELETE")
    assert "https://app.example.com/api/config" in urls
    # non-API marketing links and non-same-host scripts are not endpoints
    assert "https://app.example.com/about/team" not in urls
    assert "https://cdn.example.com/lib.js" not in urls

    html_urls = discovery.extract_js_urls(
        '<a href="/api/docs">docs</a>', "https://app.example.com", source="html"
    )
    assert html_urls[0][1] == "html"


def test_looks_like_http2_heuristic():
    # SETTINGS frame: length 0, type 0x04, flags 0, stream 0
    assert discovery.looks_like_http2(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00") is True
    assert discovery.looks_like_http2(b"HTTP/1.1 200 OK\r\n") is False
    assert discovery.looks_like_http2(discovery.HTTP2_PREFACE) is False
    assert discovery.looks_like_http2(b"\x00") is False


def httpx_response(status: int, body: str, content_type: str):
    import httpx

    return httpx.Response(
        status_code=status,
        content=body.encode("utf-8"),
        headers={"content-type": content_type},
    )
