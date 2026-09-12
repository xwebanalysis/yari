#!/usr/bin/env python3
"""Deterministic HTTP fixture for Yari browser E2E.

Serves:
  * `/openapi.json` with three documented paths
  * `/graphql` answering schema introspection over POST
  * `/` + `/app.js` with `fetch("/api/v1/users")` (JS crawl source)
  * `/api/v1/users` and `/api/echo` (reflectable/error-variant echo)

Run standalone:  python fixture_server.py [port]
Default port: 8105
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8105

INDEX_HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Yari Fixture API</title></head>
<body>
  <h1>Fixture API</h1>
  <p>Demo service used by the Yari E2E suite.</p>
  <script src="/app.js"></script>
</body>
</html>
"""

APP_JS = """// Fixture client bundle
async function loadUsers() {
  const response = await fetch("/api/v1/users");
  return response.json();
}
function pingEcho() {
  return fetch("/api/echo?q=demo");
}
loadUsers().then((users) => console.log("users", users.length));
"""

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Yari Fixture API", "version": "1.4.0"},
    "servers": [{"url": "http://127.0.0.1:8105"}],
    "paths": {
        "/api/v1/users": {
            "get": {
                "summary": "List users",
                "parameters": [
                    {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}},
                    {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/v1/users/{user_id}": {
            "get": {
                "summary": "Fetch one user",
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/echo": {
            "get": {
                "summary": "Echo a query value",
                "parameters": [
                    {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}
                ],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "summary": "Echo a JSON body",
                "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "ok"}},
            },
        },
    },
    "security": [{"bearerAuth": []}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

GRAPHQL_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "users",
                            "type": {
                                "name": None,
                                "kind": "LIST",
                                "ofType": {"name": "User", "kind": "OBJECT", "ofType": None},
                            },
                        },
                        {"name": "user", "type": {"name": "User", "kind": "OBJECT", "ofType": None}},
                    ],
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "createUser",
                            "type": {"name": "User", "kind": "OBJECT", "ofType": None},
                        }
                    ],
                },
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
                        {
                            "name": "email",
                            "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                        },
                    ],
                },
            ],
        }
    }
}


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "XwaFixture/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        print(f"[yari-fixture] {fmt % args}", flush=True)

    def _send(
        self,
        status: int,
        body: str | bytes,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/app.js":
            self._send(200, APP_JS, "application/javascript; charset=utf-8")
        elif path == "/openapi.json":
            self._send_json(200, OPENAPI_SPEC)
        elif path == "/api/v1/users":
            limit = query.get("limit", ["10"])[0]
            self._send_json(200, {"users": [{"id": 1, "email": "a@example.com"}], "limit": limit})
        elif path.startswith("/api/v1/users/"):
            self._send_json(200, {"id": path.rsplit("/", 1)[-1], "email": "a@example.com"})
        elif path == "/api/echo":
            # Reflects `q` verbatim so the reflect strategy has a deterministic hit.
            q = query.get("q", [""])[0]
            self._send_json(200, {"echo": q, "length": len(q)})
        else:
            self._send(404, "not found")

    do_HEAD = do_GET

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        path = urlparse(self.path).path

        if path == "/graphql":
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            query = str(body.get("query") or "")
            if "__schema" in query:
                self._send_json(200, GRAPHQL_SCHEMA)
            else:
                self._send_json(200, {"data": {}})
        elif path == "/api/echo":
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {"raw": raw.decode("utf-8", errors="replace")}
            self._send_json(200, {"echo": body})
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), FixtureHandler)
    print(f"[yari-fixture] listening on http://127.0.0.1:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
