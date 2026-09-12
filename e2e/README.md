# Yari Browser E2E

Real-Chromium smoke test for the zoneless Angular frontend. It proves that the
signal-based state renders **without extra interaction** and that the endpoint
filters stay live under zoneless change detection.

## Files

| File | Purpose |
|------|---------|
| `browser_smoke.py` | Playwright test (starts/kills the fixture automatically) |
| `fixture_server.py` | Deterministic API target: `openapi.json`, GraphQL introspection, JS bundle with `fetch()`, echo endpoint |

## Requirements

1. The stack is running:

   ```bash
   ./yari.sh local         # backend :8050 + frontend :4250
   ```

2. An interpreter with Playwright and Chromium installed. In this workspace:

   ```bash
   /home/x/Documents/xwebanalysis/samurai/backend/.venv/bin/python -m playwright --version
   ```

   (Any Python with `playwright` + `playwright install chromium` works.)

## Run

```bash
/home/x/Documents/xwebanalysis/samurai/backend/.venv/bin/python e2e/browser_smoke.py
```

Options:

| Flag | Default | Meaning |
|------|---------|---------|
| `--frontend URL` | `http://127.0.0.1:4250` | Frontend base URL |
| `--fixture-port N` | `8105` | Fixture port (started automatically if closed) |
| `--no-fixture` | off | Assume the fixture is already running |
| `--headed` | off | Show the Chromium window |

The script terminates the fixture it started; the `./yari.sh local` stack is
left running.

## What it checks

1. **Shell health, no clicks** — `[BACKEND ONLINE]` appears after the async
   `health()` call.
2. **UI discovery** — REST discovery against the fixture renders the results
   section (7 endpoints, 2 findings) without extra clicks.
3. **Endpoint table** — after navigating, `rest` / `graphql` / `js_crawl` rows
   render; the protocol chip and the search box actually filter the table
   (signal-backed `computed` regression guard).
4. **Safe fuzzing** — CLEAR + select `/api/echo` + RUN FUZZ renders requests,
   findings and the evidence block.
5. **Auth test** — a pasted `alg=none` JWT renders the tests table plus the
   critical finding.
6. **History** — rows render on entry and after reload; JSON/CSV exports
   download; OPEN renders the async detail view.
7. **i18n** — EN→ES→EN keeps history rows and detail findings rendered.
8. **Live WebSocket discovery** — `/api/apis/live` streams terminal lines and
   completion results.
9. **Console** — no `console.error` and no uncaught page errors.

## Fixture routes

| Route | Response |
|-------|----------|
| `GET /openapi.json` | OpenAPI 3 spec with 3 paths (`/api/v1/users`, `/api/v1/users/{user_id}`, `/api/echo`) |
| `POST /graphql` | Schema introspection when the query contains `__schema` |
| `GET /` + `GET /app.js` | HTML + bundle with `fetch("/api/v1/users")` and `fetch("/api/echo?q=demo")` |
| `GET /api/v1/users` | JSON list |
| `GET /api/echo?q=...` | Reflects `q` verbatim (deterministic reflect finding) |
| `POST /api/echo` | JSON echo |

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `frontend not reachable at ...` | Start `./yari.sh local` first |
| Port 8105 busy | Use `--fixture-port 8115` or `--no-fixture` with your own server |
| Playwright import error | Run with an interpreter that has `playwright` installed |
| A filter check fails | The filters must remain signals — `computed()` ignores plain properties under zoneless change detection |
