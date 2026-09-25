# Yari Development Roadmap

This document tracks the strategic steps required to evolve the Yari application into a full-scale API security testing module.
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [x] Scaffold backend and frontend project structure
- [x] Dockerize environments with local development HMR support
- [x] Configure Docker-compose for rapid local development
- [x] Define shared finding data model aligned with xwa-sdk

## Endpoint Discovery <!-- phase:endpoint-discovery -->

- [x] Implement REST endpoint discovery from OpenAPI specs (JSON + YAML)
- [x] Build GraphQL introspection-based schema discovery
- [x] Detect gRPC services and reflection endpoints (reflection requires optional `grpcio`/`grpcio-reflection` via `YARI_GRPC=1`; passive HTTP/2 detection by default)
- [x] Crawl JS bundles and pages for hidden API calls (regex extraction, 10 bundles × 1 MB cap)

## Fuzzing <!-- phase:fuzzing -->

- [x] Build request template engine for mutation fuzzing (`{param}` paths + query/body params)
- [x] Implement parameter fuzzing with common injection payloads (benign set: `'`, `"`, `%00`, `{}`, `-1`, canaries)
- [x] Add fuzz target selection based on parameter types (endpoint picker + `endpoint_ids` + safe default selection)
- [x] Detect error-based information disclosure during fuzzing (status/length deltas vs baseline)
- [x] Add OpenAPI-schema-driven payload generation (benign typed values: string canary, integer -1/0/1, boolean, enums, required vs optional — same 20-request budget, jitter and read-only rules)
- [ ] Add authenticated crawling and request generation from JS runtime hooks

## Authentication Testing <!-- phase:auth-testing -->

- [x] Map authentication mechanisms (JWT, sessions, API keys)
- [x] Test JWT signature and algorithm confusion vulnerabilities (`alg=none`, HS*+kid, claim hygiene — passive, no signature brute force)
- [x] Detect missing authorization checks across endpoints (auth/no-auth comparison, capped at 2 endpoints)
- [x] Analyze session handling and token expiration flows (cookie flags, long expiry, missing claims)

## Reporting & Production Hardening <!-- phase:production-hardening -->

- [x] Build API security report generator (client-side PDF via jsPDF/autoTable)
- [x] Create JSON export for test results (plus findings CSV)
- [x] Wrap backend routes with JWT Authentication middleware (optional via `YARI_JWT_SECRET`)
- [x] Implement rate limiting and access controls (token bucket 120 req/min, health exempt, CORS restrictions)

## Safety Guarantees <!-- phase:safety -->

- [x] Safe-by-default fuzzing: 20-request budget, 300–1000 ms jitter, abort on 429/503
- [x] Read-only methods only unless `allow_mutations` is explicitly enabled
- [x] No exploitation payloads, no credential brute force, evidence never stores supplied secrets
- [x] Identifiable User-Agent and documented probe paths

## Future <!-- phase:future -->

- [ ] gRPC protobuf-driven method invocation and schema-aware checks
- [x] CI pipeline (pytest + vitest + build) for the repository
- [x] Export of the full SQLite database (xwa-sdk `SAMURAI_DB_EXPORT_V1` compatible)
- [ ] Import/restore of an exported database (pending — export only for now)
- [ ] Detection of WAF/rate-limit fingerprints during discovery (kabuki overlap)
