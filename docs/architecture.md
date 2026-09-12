# Yari Architecture

## Overview

Yari is an API security testing module. It performs three activities against a
target API, all safe-by-default:

1. **Discovery** — read-only enumeration of the API surface (OpenAPI, GraphQL,
   gRPC, JS bundles/pages).
2. **Fuzzing** — budgeted, jittered requests with benign payloads and strict
   abort rules.
3. **Authentication testing** — passive JWT/session/API-key analysis plus a
   hard-capped auth/no-auth comparison when credentials are supplied.

```
Angular 22 (:4250) ──HTTP/WS──▶ FastAPI (:8050)
                                     │
             ┌───────────────────────┼────────────────────────┐
             ▼                       ▼                        ▼
        discovery.py            fuzzing.py             auth_testing.py
   (openapi/graphql/grpc/js)  (SafeFuzzer engine)    (jwt/cookie/apikey)
             │                       │                        │
             └───────────────┬───────┴────────────────────────┘
                             ▼
                    SQLAlchemy 2 → SQLite (WAL)
                    analyses / api_endpoints / findings
                    fuzz_runs / auth_tests
```

## Project layout

```
yari/
  backend/
    app/
      main.py          FastAPI routes, persistence, WebSocket pipeline
      analyzer.py      target normalization, HTTP client, discover() entrypoint
      discovery.py     openapi.py-equivalent probes + parsers (read-only)
      fuzzing.py       SafeFuzzer: template engine + safe strategies
      auth_testing.py  passive JWT/cookie/API-key checks + capped comparison
      events.py        xwa-sdk EventStream (SDK with local fallback)
      security.py      optional JWT auth, rate limit, CORS (YARI_* env)
      models.py        SQLAlchemy models
      schemas.py       Pydantic request/response schemas
      database.py      engine/session (SQLite/PostgreSQL)
    tests/             42 pytest tests (MockTransport based)
  frontend/
    src/app/core/      api.service, theme, i18n, workspace state, PDF report
    src/app/shared/    terminal, metric-card, status-badge, severity-tag, export-actions, finding-list
    src/app/features/  discover, endpoints, fuzzing, auth, history
    public/fonts/      self-hosted Doto + Space Grotesk + Space Mono woff2
  yari.sh              local (default) / docker launcher
  docker-compose.yml   frontend + backend + PostgreSQL 17
```

## Data model

| Table | Purpose | Key columns |
|---|---|---|
| `analyses` | one scan session | `target`, `status` (PENDING/RUNNING/COMPLETED/ERROR/CANCELLED), `analysis_type=api_scan`, timestamps, `error_message` |
| `api_endpoints` | discovered surface | `protocol` (rest/graphql/grpc), `method`, `path`, `host`, `params` JSON, `auth_required`, `source` (openapi/graphql_introspection/grpc_reflection/grpc_passive/js_crawl/html), `content_types` JSON, `version` |
| `findings` | security findings | `tool=yari`, unified `severity`, `category` (injection/auth/authz/session/disclosure/misconfig), `check`, `title`, `description`, `target_url`, `evidence` JSON (incl. `poc_payload`), `cvss_score`, `confidence` |
| `fuzz_runs` | one endpoint × strategy pass | `strategy`, `requests_sent`, `findings_count`, `status`, `abort_reason`, timestamps |
| `auth_tests` | one mechanism check | `mechanism` (jwt/session/apikey), `check`, `result`, `details` JSON |

Deletes cascade from `analyses`; findings reference endpoints with `ON DELETE SET NULL`.

## Discovery pipeline (`discovery.py`)

Sequential probes, all GET except GraphQL introspection POST:

1. **Landing page** — fetch target, extract `<title>` and up to 10 JS bundle URLs.
2. **OpenAPI/Swagger** — probe `/openapi.json`, `/swagger.json`, `/api-docs`,
   `/v3/api-docs`, `/swagger/v1/swagger.json`, `/docs` (parses the spec URL from
   the Swagger UI HTML). JSON and YAML are supported (PyYAML). Extracts paths,
   methods, parameters, request-body content types, security requirements
   (`auth_required`) and `info.version`. Finds public specs (`info` severity).
3. **GraphQL** — POSTs the standard introspection query to `/graphql`,
   `/api/graphql`, `/v1/graphql`; parses query/mutation fields and emits a
   `low` finding when introspection is enabled.
4. **JS crawl** — regex extraction of `fetch(...)`, `axios.*(...)`,
   `XMLHttpRequest.open(...)`, `url: ...` and common API string literals from the
   HTML plus up to 10 bundles (1 MB each). Only API-looking URLs are kept.
5. **gRPC** — see below.

Limits: 200 spec endpoints, 100 GraphQL fields, 100 crawled endpoints, 2 MB specs.

### gRPC decision

`grpcio` + `grpcio-reflection` were tested on Python 3.13 (venv apart,
grpcio 1.83.1) and work, but they are heavy C extensions, so they are **not**
installed by default:

- **Default (passive)**: HTTP/2 client-preface probe on the target port(s) and
  `50051`, plus header inspection (`application/grpc`, `grpc-status`). When
  HTTP/2 is confirmed but reflection is unavailable, Yari stores one
  `grpc_passive` endpoint hint and reports `grpc_mode: "passive"`.
- **Optional (reflection)**: with `YARI_GRPC=1`, `_grpc_reflection_services()`
  lists exposed services and stores one endpoint per service with
  `source="grpc_reflection"` and `grpc_mode: "reflection"`.

The limitation is intentional and documented in the UI/API: without the extras,
Yari reports "HTTP/2 present, reflection not advertised" instead of pretending a
full gRPC enumeration happened.

## Safe fuzzing engine (`fuzzing.py`)

`SafeFuzzer` builds requests from endpoint templates
(`path` with `{param}` placeholders + `params[]` entries with `in: query|path|body`).

| Strategy | Requests per endpoint | Checks |
|---|---|---|
| `rate_limit` | 3 (50 ms burst) | `429` or rate-limit headers present |
| `reflect` | ≤ 3 params | unique `xwa-canary-*` echoed in the body |
| `error_based` | 1 baseline + ≤ 10 | benign payload changes status/length vs baseline |
| `authz_matrix` | 2 (only with credentials) | success without credentials on `auth_required` endpoints |
| `safe` | union of the above | default strategy |

Hard rules:

- global budget `SAFE_MAX_REQUESTS = 20` (callers can lower it, never raise it);
- `GET`/`HEAD`/`OPTIONS` only, unless `allow_mutations=true` (explicit opt-in);
- 300–1000 ms random jitter between requests;
- abort immediately on `HTTP 429`/`503` with `status=ABORTED` + reason;
- `poc_payload` is always the benign canary/payload actually sent; supplied
  credentials never appear in evidence.

## Authentication testing (`auth_testing.py`)

- **JWT (local, no network)**: base64url-decodes header/payload without
  verifying signatures; flags `alg=none` (critical), HS* + `kid` (medium),
  missing/long `exp` (medium), missing `aud`/`iss`/`nbf`/`iat`.
- **Session cookies (local)**: HttpOnly/Secure/SameSite flags for
  session-ish cookie names.
- **API keys (local)**: key-like query parameters in discovered paths.
- **Comparative requests (opt-in)**: only when a token/cookie is provided;
  max 2 endpoints (2 requests each) and never any credential guessing.

## WebSocket pipeline

`/api/apis/live` persists the analysis first and streams xwa-sdk `Event`
envelopes with a monotonic `seq`. Discovery is always run; `fuzz=true` adds a
safe pass and `auth_token`/`auth_cookie` add the auth checks. Progress events
carry `phase: openapi|graphql|crawl|grpc|fuzz|auth`. `analysis_id` is always the
persisted row id as a string.

## Security posture (Yari itself)

- Optional JWT auth (`YARI_JWT_SECRET`, HS256), CORS limited to
  localhost/private LAN (`XWA_CORS_ORIGINS` override), in-process rate limit
  120 req/min (`XWA_RATE_LIMIT_MAX`), health exempt.
- SQLite with `foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000`.
- Error envelope `{error:{code,message,detail,retryable}}` for 400/401/403/404/422/429/502/503 plus a last-resort 500.
