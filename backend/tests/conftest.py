"""Shared pytest fixtures: isolated SQLite database + TestClient.

The environment is configured before any ``app.*`` import so the engine binds to
a temporary SQLite file instead of the development database.
"""

import os
import tempfile
from pathlib import Path

_TMP_DIR = tempfile.mkdtemp(prefix="yari-tests-")
os.environ["DB_DRIVER"] = "sqlite"
os.environ["DB_PATH"] = str(Path(_TMP_DIR) / "test.db")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def anyio_backend():
    """Run async tests on asyncio only (trio is not a project dependency)."""
    return "asyncio"


@pytest.fixture(autouse=True)
def fresh_db():
    """Recreate the schema and clear middleware state before every test."""
    from app import database, models, security

    models.Base.metadata.drop_all(bind=database.engine)
    models.Base.metadata.create_all(bind=database.engine)
    security.reset_rate_limiter()
    yield


@pytest.fixture()
def client():
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def mock_client(handler) -> httpx.AsyncClient:
    """Async client backed by a MockTransport (test injection point)."""
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        base_url="https://api.example.com",
    )


@pytest.fixture()
def fake_discover(monkeypatch):
    """Replace the network discovery pipeline with a canned result."""
    from app import analyzer, discovery

    result = discovery.DiscoveryResult(
        final_url="https://example.com/",
        title="Example API",
        endpoints=[
            discovery.DiscoveredEndpoint(
                protocol="rest",
                method="GET",
                path="/api/users",
                host="example.com",
                params=[{"name": "page", "in": "query", "type": "integer"}],
                auth_required=True,
                source="openapi",
                content_types=["application/json"],
                version="1.0.0",
            ),
            discovery.DiscoveredEndpoint(
                protocol="graphql",
                method="POST",
                path="/graphql",
                host="example.com",
                params=[{"name": "user", "in": "graphql", "type": "User", "operation": "query"}],
                auth_required=None,
                source="graphql_introspection",
                content_types=["application/json"],
            ),
        ],
        findings=[
            discovery.DiscoveryFinding(
                severity="low",
                category="disclosure",
                check="graphql_introspection_enabled",
                title="GraphQL introspection is enabled",
                description="The schema is public.",
                target_url="/graphql",
                evidence={"endpoint": "/graphql", "types_exposed": 3},
                confidence="high",
            )
        ],
        specs_found=["https://example.com/openapi.json"],
        bundles_scanned=1,
        grpc_mode="passive",
    )

    async def _discover(target, max_bundles=10, client=None, timeout=15.0, progress=None):
        if progress:
            await progress("openapi", "Probing /openapi.json", {"path": "/openapi.json"})
        return result

    monkeypatch.setattr(analyzer, "discover", _discover)
    return _discover


@pytest.fixture()
def create_analysis(client, fake_discover):
    """POST a discover run and return the parsed response."""

    def _create(target: str = "https://example.com") -> dict:
        response = client.post(
            "/api/endpoints/discover", json={"target": target, "max_bundles": 2}
        )
        assert response.status_code == 200, response.text
        return response.json()

    return _create
