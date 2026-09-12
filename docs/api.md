# Yari API Reference

Base URL: `http://localhost:8050` (frontend uses `environment.apiBaseUrl`).

All errors use the envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "detail": {"errors": []},
    "retryable": false
  }
}
```

Codes: `BAD_REQUEST` 400, `UNAUTHORIZED` 401, `FORBIDDEN` 403, `NOT_FOUND` 404,
`CONFLICT` 409, `VALIDATION_ERROR` 422, `RATE_LIMITED` 429, `INTERNAL` 500,
`UPSTREAM_ERROR` 502, `SERVICE_UNAVAILABLE` 503.

## Service

### `GET /`

```json
{"status": "ok", "service": "yari", "version": "0.1.0"}
```

### `GET /api/health`

```json
{"status": "ok", "database": "ok", "version": "0.1.0", "tool": "yari"}
```

Returns 503 with `status: "error"` when the database does not answer.

### `POST /api/auth/token`

Only when `YARI_JWT_SECRET` is set (otherwise 403).

```json
// request
{"password": "…"}
// response
{"token": "eyJ…", "expires_in": 86400}
```

When enabled, all non-exempt routes require `Authorization: Bearer <token>`.
`/`, `/api/health`, `/docs`, `/redoc`, `/openapi.json` and `/api/auth/token`
are exempt. WebSockets accept `?token=`.

## Discovery

### `POST /api/endpoints/discover`

```json
// request
{"target": "https://api.example.com", "max_bundles": 10}
```

```json
// 200 response
{
  "analysis": {
    "id": 7,
    "target": "https://api.example.com",
    "status": "COMPLETED",
    "analysis_type": "api_scan",
    "created_at": "2026-09-12T10:00:00",
    "started_at": "2026-09-12T10:00:00",
    "finished_at": "2026-09-12T10:00:02",
    "error_message": null,
    "endpoints": [
      {
        "id": 21,
        "protocol": "rest",
        "method": "GET",
        "path": "/v2/users",
        "host": "api.example.com",
        "params": [{"name": "page", "in": "query", "required": false, "type": "integer"}],
        "auth_required": true,
        "source": "openapi",
        "content_types": ["application/json"],
        "version": "2.1.0"
      }
    ],
    "findings": [
      {
        "id": 3,
        "tool": "yari",
        "severity": "low",
        "category": "disclosure",
        "check": "graphql_introspection_enabled",
        "title": "GraphQL introspection is enabled",
        "description": "…",
        "target_url": "/graphql",
        "evidence": {"endpoint": "/graphql", "types_exposed": 12},
        "cvss_score": 3.0,
        "confidence": "high",
        "detected_at": "2026-09-12T10:00:02"
      }
    ],
    "fuzz_runs": [],
    "auth_tests": []
  },
  "endpoint_count": 1,
  "finding_count": 1,
  "by_protocol": {"rest": 1}
}
```

`max_bundles` is clamped to 0–20. Unreachable targets return 502
`UPSTREAM_ERROR` and persist the analysis as `ERROR`.

## History / export / delete

- `GET /api/analyses` → list of summaries (last 50, newest first):
  `{id, target, status, analysis_type, created_at, finished_at, endpoint_count, finding_count, high_count, fuzz_run_count, auth_test_count}`
- `GET /api/analyses/{id}` → full analysis (as above).
- `GET /api/analyses/{id}/export?format=json` → downloadable JSON
  (`Content-Disposition: attachment; filename="yari-analysis-{id}.json"`)
  with `endpoints`, `findings`, `fuzz_runs`, `auth_tests` and `summary`.
- `GET /api/analyses/{id}/export?format=csv` → findings CSV with the same
  filename pattern (`.csv`).
- `DELETE /api/analyses/{id}` → 204 (404 when missing).
- `DELETE /api/analyses` → 204, deletes all analyses (cascades).

## Fuzzing

### `POST /api/analyses/{id}/fuzz`

```json
// request
{
  "endpoint_ids": [21, 22],
  "strategy": "safe",
  "allow_mutations": false,
  "auth_token": "eyJ…",
  "auth_cookie": "sessionid=…"
}
```

`strategy`: `safe` (default) | `reflect` | `error_based` | `authz_matrix` | `rate_limit`.

```json
// 200 response
{
  "analysis_id": 7,
  "strategy": "safe",
  "requests_sent": 2,
  "aborted": false,
  "abort_reason": null,
  "runs": [
    {
      "id": 1, "endpoint_id": 21, "strategy": "safe", "requests_sent": 2,
      "findings_count": 1, "status": "COMPLETED", "abort_reason": null,
      "started_at": "…", "finished_at": "…"
    }
  ],
  "findings": [
    {
      "id": 9, "severity": "low", "category": "injection", "check": "reflected_input",
      "title": "User input is reflected verbatim in the response",
      "description": "…", "target_url": "https://api.example.com/v2/users?q=xwa-canary-…",
      "evidence": {"poc_payload": "xwa-canary-bcc77655", "param": "q"},
      "confidence": "high"
    }
  ]
}
```

Safety guarantees: ≤ 20 requests (global), ≤ 10 endpoints per call, jittered
300–1000 ms, aborts on 429/503, and mutating methods are skipped unless
`allow_mutations: true`. `authz_matrix` without credentials is skipped.

## Authentication testing

### `POST /api/analyses/{id}/auth-test`

```json
// request
{"token": "eyJ…", "cookie": "sessionid=abc; Path=/"}
```

```json
// 200 response
{
  "analysis_id": 7,
  "requests_sent": 4,
  "tests": [
    {"id": 1, "mechanism": "jwt", "check": "jwt_alg_none", "result": "critical",
     "details": {"alg": "none", "title": "JWT accepts the 'none' algorithm"}, "created_at": "…"}
  ],
  "findings": [
    {"id": 12, "severity": "critical", "category": "auth", "check": "jwt_alg_none",
     "title": "JWT accepts the 'none' algorithm", "description": "…",
     "target_url": null, "evidence": {"details": {"alg": "none"}}, "confidence": "high"}
  ]
}
```

JWT and cookie checks run locally without any request. The comparative
auth/no-auth requests only run when a token/cookie is supplied, capped at
2 endpoints (2 requests each, 4 total). Without credentials, `requests_sent` is 0.

## WebSocket

### `WS /api/apis/live`

Query parameters:

| Param | Default | Meaning |
|---|---|---|
| `target` | required | target URL |
| `token` | — | JWT when `YARI_JWT_SECRET` is set |
| `fuzz` | `false` | run a safe fuzz pass after discovery |
| `strategy` | `safe` | fuzzing strategy |
| `max_bundles` | `10` | JS bundles to scan |
| `allow_mutations` | `false` | opt-in for non-read-only methods |
| `auth_token` / `auth_cookie` | — | enable the comparative auth checks |

Every frame is one xwa-sdk `Event`:

```json
{
  "seq": 1,
  "type": "analysis_started",
  "tool": "yari",
  "analysis_id": "7",
  "ts": "2026-09-12T10:00:00.000Z",
  "payload": {"target": "https://api.example.com"}
}
```

Types: `analysis_started`, `analysis_progress` (`payload.phase` ∈
`openapi|graphql|crawl|grpc|fuzz|auth`), `item_found` (`payload.kind` =
`endpoint` | `finding`), `analysis_completed` (counts, `requests_sent`,
`grpc_mode`, `bundles_scanned`, `specs_found`), `analysis_error`
(`{code, message, retryable}`), `log`.

`analysis_id` is the persisted row id serialized as a string (never the target).
