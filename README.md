<h1 align="center">Yari</h1>

<div align="center">
<p><em>API security testing — part of the <a href="https://github.com/xwebanalysis">XWA ecosystem</a></em></p>
</div>

<hr>

<p><strong>Status: <em>In development v0.1.0</em></strong></p>

<p>Security testing for REST, GraphQL and gRPC APIs: read-only endpoint discovery, safe request fuzzing and authentication/session analysis.</p>

## Features

- **Endpoint discovery** — OpenAPI/Swagger specs (JSON + YAML), GraphQL introspection, gRPC (server reflection when the optional extras are installed, passive HTTP/2 detection otherwise), and JS bundle/page crawling.
- **Safe fuzzing** — budgeted request templates with `reflect`, `error_based`, `authz_matrix` and `rate_limit` strategies. Safe mode is the default: max 20 requests, 300–1000 ms jitter, aborts on 429/503, read-only methods only unless `allow_mutations` is explicitly enabled.
- **Authentication testing** — passive JWT claims/algorithm analysis (`alg=none`, HMAC+kid, missing `exp`/`aud`/`iss`, long expiry), session cookie flags, API keys in URLs, and a hard-capped auth/no-auth comparison.
- **Findings on the unified xwa-sdk scale** (`pass`→`critical`) with categories `injection | auth | authz | session | disclosure | misconfig`, evidence including the concrete benign `poc_payload`.
- **Persistence & history** — SQLite by default (PostgreSQL optional), JSON/CSV export and client-side PDF reports.
- **Live streaming** — WebSocket pipeline emitting xwa-sdk `Event` envelopes (`analysis_started → analysis_progress → item_found* → analysis_completed | analysis_error`).
- **Nothing Design UI** — Angular 22, dark/light, self-hosted Doto/Space Grotesk/Space Mono fonts, zero emojis or shadows.

## Quick start (local, SQLite)

```bash
./yari.sh                 # backend :8050 + frontend :4250
# or separately:
./yari.sh backend
./yari.sh frontend
```

The script creates the Python 3.13 venv with `uv`, installs the local `xwa-sdk`
binding when the sibling repo exists, and starts `uvicorn` + `ng serve`.
Open http://localhost:4250.

### gRPC reflection (optional)

```bash
YARI_GRPC=1 ./yari.sh backend   # installs grpcio + grpcio-reflection
```

Without the extras, gRPC discovery falls back to passive detection
(HTTP/2 preface probe + `application/grpc`/`grpc-status` header inspection) and
reports a `grpc_passive` service hint when HTTP/2 is confirmed.

### Docker (PostgreSQL)

```bash
./yari.sh docker
```

## Ports

| Component | Port |
|---|---|
| Frontend | 4250 |
| Backend | 8050 |
| PostgreSQL (docker) | 5447 |

## Contract (xwa-sdk)

- `GET /` → `{"status":"ok","service":"yari","version":"0.1.0"}`
- `GET /api/health` → `{"status":"ok","database":"ok","version":"0.1.0","tool":"yari"}`
- `POST /api/endpoints/discover` `{target, max_bundles?}`
- `GET /api/analyses`, `GET /api/analyses/{id}`, `DELETE /api/analyses/{id}`
- `GET /api/analyses/{id}/export?format=json|csv`
- `POST /api/analyses/{id}/fuzz` `{endpoint_ids?, strategy?, allow_mutations?, auth_token?, auth_cookie?}`
- `POST /api/analyses/{id}/auth-test` `{token?, cookie?}`
- `WS /api/apis/live?target=...` (optional `fuzz=true`, `auth_token`, `auth_cookie`)
- Errors: `{"error": {code, message, detail, retryable}}`
- Optional JWT auth via `YARI_JWT_SECRET` + `POST /api/auth/token`

See [`docs/api.md`](docs/api.md) for the full reference.

## Safety model (no blocks, no blacklists)

Yari is designed to be a good citizen against the target:

1. Read-only by default — only `GET`/`HEAD`/`OPTIONS` are contacted unless the
   caller sets `allow_mutations: true`.
2. Hard global budget (20 requests per fuzz run) and strict timeouts.
3. 300–1000 ms jitter between requests; immediate abort on `429`/`503`.
4. Benign payloads only (`'`, `"`, `%00`, `{}`, `-1`, unique canaries). No
   exploitation payloads and no credential brute force.
5. Identifiable User-Agent, discovery probes limited to documented paths
   (`/openapi.json`, `/swagger.json`, `/graphql`, ...), bundles capped to 10 × 1 MB.
6. Evidence never contains supplied tokens/cookies; `poc_payload` is always the
   harmless canary or benign payload that was sent.

## Tests

```bash
# backend
cd backend && source .venv/bin/activate && pytest -q     # 42 tests
# frontend
cd frontend && npm test && npm run build                 # 8 tests + production build
```

## Documentation

- [`docs/README.md`](docs/README.md) — index
- [`docs/architecture.md`](docs/architecture.md) — modules, data model, data flow, gRPC decision
- [`docs/api.md`](docs/api.md) — REST + WebSocket reference
- [`docs/development.md`](docs/development.md) — toolchain, tests, extending Yari
- [`ROADMAP.md`](ROADMAP.md) — status

## License

Part of the XWA ecosystem. No license file is shipped in this repository yet.
