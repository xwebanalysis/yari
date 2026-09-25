# Yari Development Guide

## Toolchain

| Tool | Path / version |
|---|---|
| Python | 3.13 via `uv` (`~/.local/bin/uv`) |
| Node | 24.21 via `mise`: `export PATH="$HOME/.local/share/mise/installs/node/24/bin:$PATH"` |
| xwa-sdk local | `/home/x/Documents/xwebanalysis/xwa-sdk/bindings/python` |

## Backend setup

```bash
cd backend
~/.local/bin/uv venv --python 3.13 --seed .venv
~/.local/bin/uv pip install --python .venv/bin/python -r requirements-dev.txt
~/.local/bin/uv pip install --python .venv/bin/python -e ../../xwa-sdk/bindings/python
.venv/bin/python -m pytest -q
```

`./yari.sh backend` performs all of the above automatically and starts
`uvicorn app.main:app --port 8050` with `DB_DRIVER=sqlite`.

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DB_DRIVER` | `sqlite` | `sqlite` or `postgresql` |
| `DB_PATH` | `./yari.db` | SQLite file (backend working dir) |
| `YARI_JWT_SECRET` | unset | enables HS256 auth + `/api/auth/token` |
| `YARI_AUTH_PASSWORD` | `yari` | password for token issuance |
| `YARI_RATE_LIMIT_MAX` / `XWA_RATE_LIMIT_MAX` | `120` | requests per minute per IP |
| `XWA_CORS_ORIGINS` | localhost/LAN regex | comma-separated CORS origins |
| `YARI_GRPC` | `0` | `1` installs the optional gRPC extras in `yari.sh` |

## Frontend setup

```bash
export PATH="$HOME/.local/share/mise/installs/node/24/bin:$PATH"
cd frontend
npm install
npm test          # vitest via @angular/build:unit-test (11 tests)
npm run build     # production build
npm start         # ng serve on :4250

# browser smoke (Playwright, real Chromium; requires ./yari.sh local running)
cd ..
/home/x/Documents/xwebanalysis/samurai/backend/.venv/bin/python e2e/browser_smoke.py
```

Fonts are self-hosted in `public/fonts` (woff2 downloaded from
`fonts.googleapis.com` with a desktop Chrome User-Agent and served from
`/fonts/...`; the `@font-face` rules live at the top of `src/styles.scss`).
If the files are missing, the CSS stacks fall back to `Space Mono`/system
monospace so the UI remains usable.

## Adding a new fuzzing strategy

1. Add the strategy name to `fuzzing.STRATEGIES`.
2. Implement `_strategy_<name>(endpoint, outcome)` using `self._send(...)` so
   the global budget, jitter and 429/503 abort rules always apply.
3. Map it in `SafeFuzzer.fuzz_endpoint`'s `plan` (and optionally into `safe`).
4. Add a `httpx.MockTransport` test in `tests/test_fuzzing.py` and, if it
   produces findings, assert `evidence.poc_payload` is benign.

## Adding a new discovery source

1. Return `DiscoveredEndpoint` objects from `discovery.py` (protocol, path,
   source, params, auth hints).
2. Include it in `discover_target()` and keep it bounded (counts + bytes).
3. Emit a progress event via the `progress` callback so the WS UI stays live.
4. Add parser unit tests; use `tests/conftest.py::mock_client` for HTTP fixtures.

## Test strategy

- **Backend (67 tests)** — pytest with `httpx.MockTransport` for all network
  code (`discovery`, `fuzzing`, `auth_testing`) and FastAPI `TestClient` for
  REST/WS integration. No test touches the real network.
- **Frontend (11 tests)** — vitest/jsdom: app shell (health, i18n toggle),
  `ApiService` via `HttpTestingController`, severity tag rendering, and the
  signal-backed endpoint filters (zoneless `computed` regression guard).
- **Browser smoke** — `e2e/browser_smoke.py` (Playwright + `http.server`
  fixture on `:8105`) drives the real UI against a running `./yari.sh local`:
  discovery, endpoint filters, safe fuzzing, JWT auth testing, history/exports,
  i18n and a live WS run, with a clean-console assertion. See
  [../e2e/README.md](../e2e/README.md) and the change-detection rule in
  [ui-architecture.md](ui-architecture.md).

## Known limitations

- **gRPC** — reflection requires the optional extras (`YARI_GRPC=1`); the
  default install reports HTTP/2 presence passively. gRPC payload fuzzing is
  out of scope for v0.1.0.
- **OpenAPI fuzzing** — Yari derives benign typed payloads from OpenAPI
  schemas (string canary, integer -1/0/1, boolean, enums, required vs
  optional) and feeds them through the budgeted engine (`schema` strategy,
  plus automatic typed payloads in `error_based`). `requestBody` params are
  only contacted with `allow_mutations: true`.
- **JS crawl** — static regex extraction; dynamic/runtime request generation
  and authenticated crawling are future work.
- **Rate-limit strategy** — header-name heuristics (`x-ratelimit-*`,
  `ratelimit-limit`, `retry-after`); no throttling curve is computed yet.
- **PDF export** is client-side (jsPDF/autoTable); the server-side export
  supports `json` and `csv` only, per the shared contract.
- **Database import** — the full-database export
  (`GET /api/database/export/raw`, `POST /api/database/export/encrypted`,
  `SAMURAI_DB_EXPORT_V1` container) exists; import/restore is pending.
