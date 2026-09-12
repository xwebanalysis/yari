# Yari Documentation

API security testing module of the XWA ecosystem.

| Document | Contents |
|---|---|
| [architecture.md](architecture.md) | Project layout, modules, data model, discovery/fuzzing pipelines, gRPC decision |
| [api.md](api.md) | REST endpoints, request/response shapes, export formats, WebSocket event contract |
| [development.md](development.md) | Toolchain, local setup, tests, adding checks, known limitations |
| [ui-architecture.md](ui-architecture.md) | Frontend layout and the signal-first/zoneless change-detection rule |

Quick links:

- Backend: FastAPI 0.141 + SQLAlchemy 2 + SQLite (PostgreSQL optional) on port **8050**.
- Frontend: Angular 22 + Nothing Design on port **4250**.
- Contracts: `xwa-sdk` (`Analysis`, `Finding`, `Event`, `ApiEndpoint`, `Error`).
