# Yari Development Roadmap

This document tracks the strategic steps required to evolve the Yari application into a full-scale API security testing module.
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [ ] Scaffold backend and frontend project structure
- [ ] Dockerize environments with local development HMR support
- [ ] Configure Docker-compose for rapid local development
- [ ] Define shared finding data model aligned with xwa-sdk

## Endpoint Discovery <!-- phase:endpoint-discovery -->

- [ ] Implement REST endpoint discovery from OpenAPI specs
- [ ] Build GraphQL introspection-based schema discovery
- [ ] Detect gRPC services and reflection endpoints
- [ ] Crawl JS bundles and pages for hidden API calls

## Fuzzing <!-- phase:fuzzing -->

- [ ] Build request template engine for mutation fuzzing
- [ ] Implement parameter fuzzing with common injection payloads
- [ ] Add fuzz target selection based on parameter types
- [ ] Detect error-based information disclosure during fuzzing

## Authentication Testing <!-- phase:auth-testing -->

- [ ] Map authentication mechanisms (JWT, sessions, API keys)
- [ ] Test JWT signature and algorithm confusion vulnerabilities
- [ ] Detect missing authorization checks across endpoints
- [ ] Analyze session handling and token expiration flows

## Reporting & Production Hardening <!-- phase:production-hardening -->

- [ ] Build API security report generator
- [ ] Create JSON export for test results
- [ ] Wrap backend routes with JWT Authentication middleware
- [ ] Implement rate limiting and access controls
