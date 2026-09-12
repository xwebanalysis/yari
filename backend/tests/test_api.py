"""API integration tests: health, discovery, history, export, fuzz, auth, WS."""

from datetime import datetime, timedelta

import pytest


def test_health_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["tool"] == "yari"
    assert body["version"]


def test_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "yari", "version": "0.1.0"}


def test_health_reports_database_error(client, monkeypatch):
    from app import database

    monkeypatch.setattr(database, "ping", lambda: False)
    response = client.get("/api/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "error"
    assert body["database"] == "error"


def test_discovery_persists_endpoints_and_findings(client, create_analysis):
    created = create_analysis()
    analysis = created["analysis"]

    assert analysis["status"] == "COMPLETED"
    assert created["endpoint_count"] == 2
    assert created["finding_count"] == 1
    assert created["by_protocol"] == {"rest": 1, "graphql": 1}

    listed = client.get("/api/analyses").json()
    assert len(listed) == 1
    assert listed[0]["id"] == analysis["id"]
    assert listed[0]["endpoint_count"] == 2
    assert listed[0]["finding_count"] == 1

    detail = client.get(f"/api/analyses/{analysis['id']}").json()
    endpoint = next(e for e in detail["endpoints"] if e["protocol"] == "rest")
    assert endpoint["method"] == "GET"
    assert endpoint["path"] == "/api/users"
    assert endpoint["auth_required"] is True
    assert endpoint["params"][0]["name"] == "page"


def test_discovery_upstream_error_envelope(client, monkeypatch):
    from app import analyzer

    async def failing(target, max_bundles=10, client=None, timeout=15.0, progress=None):
        raise analyzer.TargetError("Failed to fetch target: name resolution failed")

    monkeypatch.setattr(analyzer, "discover", failing)
    response = client.post("/api/endpoints/discover", json={"target": "https://bad.example"})
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "UPSTREAM_ERROR"
    assert body["error"]["retryable"] is True

    listed = client.get("/api/analyses").json()
    assert listed[0]["status"] == "ERROR"


def test_discovery_unexpected_error_marks_analysis_error(client, monkeypatch):
    from app import analyzer

    async def crashing(target, max_bundles=10, client=None, timeout=15.0, progress=None):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(analyzer, "discover", crashing)
    with pytest.raises(RuntimeError):
        client.post("/api/endpoints/discover", json={"target": "https://bad.example"})

    listed = client.get("/api/analyses").json()
    assert listed[0]["status"] == "ERROR"
    detail = client.get(f"/api/analyses/{listed[0]['id']}").json()
    assert detail["error_message"] == "parser exploded"


def test_validation_error_envelope(client):
    response = client.post("/api/endpoints/discover", json={})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_detail_export_and_delete(client, create_analysis):
    created = create_analysis()
    analysis_id = created["analysis"]["id"]

    export_json = client.get(f"/api/analyses/{analysis_id}/export?format=json")
    assert export_json.status_code == 200
    assert export_json.headers["content-disposition"] == (
        f'attachment; filename="yari-analysis-{analysis_id}.json"'
    )
    exported = export_json.json()
    assert exported["target"] == "https://example.com"
    assert len(exported["endpoints"]) == 2
    assert len(exported["findings"]) == 1
    assert exported["summary"]["endpoint_count"] == 2

    export_csv = client.get(f"/api/analyses/{analysis_id}/export?format=csv")
    assert export_csv.status_code == 200
    assert export_csv.headers["content-type"].startswith("text/csv")
    assert "attachment" in export_csv.headers["content-disposition"]
    assert "graphql_introspection_enabled" in export_csv.text

    bad_format = client.get(f"/api/analyses/{analysis_id}/export?format=xml")
    assert bad_format.status_code == 422

    deleted = client.delete(f"/api/analyses/{analysis_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/analyses/{analysis_id}").status_code == 404
    assert client.get("/api/analyses").json() == []


def test_delete_all(client, create_analysis):
    create_analysis("https://one.example")
    create_analysis("https://two.example")
    assert len(client.get("/api/analyses").json()) == 2

    assert client.delete("/api/analyses").status_code == 204
    assert client.get("/api/analyses").json() == []


def test_fuzz_endpoint_persists_run_and_findings(client, create_analysis, monkeypatch):
    from app import fuzzing

    created = create_analysis()
    analysis_id = created["analysis"]["id"]
    endpoint_id = created["analysis"]["endpoints"][0]["id"]

    async def fake_run_fuzz(target, endpoints, **kwargs):
        finding = fuzzing.FuzzFinding(
            severity="low",
            category="injection",
            check="reflected_input",
            title="Reflected input",
            description="Canary reflected.",
            target_url="https://example.com/api/users?q=xwa-canary",
            evidence={"poc_payload": "xwa-canary-1234", "param": "page"},
            confidence="high",
        )
        outcome = fuzzing.FuzzOutcome(
            strategy="safe",
            requests_sent=3,
            findings=[finding],
            endpoint={**endpoints[0], "id": endpoint_id},
        )
        return fuzzing.FuzzSummary(
            strategy="safe",
            requests_sent=3,
            findings=[finding],
            outcomes=[outcome],
        )

    monkeypatch.setattr(fuzzing, "run_fuzz", fake_run_fuzz)
    response = client.post(
        f"/api/analyses/{analysis_id}/fuzz",
        json={"strategy": "safe", "endpoint_ids": [endpoint_id]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requests_sent"] == 3
    assert len(body["runs"]) == 1
    assert body["runs"][0]["status"] == "COMPLETED"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["evidence"]["poc_payload"] == "xwa-canary-1234"


def test_fuzz_rejects_unknown_strategy(client, create_analysis):
    created = create_analysis()
    response = client.post(
        f"/api/analyses/{created['analysis']['id']}/fuzz",
        json={"strategy": "nuke"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "BAD_REQUEST"


def test_auth_test_endpoint_persists_results(client, create_analysis, monkeypatch):
    from app import auth_testing

    created = create_analysis()
    analysis_id = created["analysis"]["id"]

    async def fake_run_auth_tests(target, endpoints=(), **kwargs):
        return auth_testing.AuthTestSummary(
            results=[
                auth_testing.AuthTestResult(
                    mechanism="jwt",
                    check="jwt_expiry_present",
                    result="pass",
                    title="JWT declares a bounded expiration",
                    description="ok",
                    details={"ttl_seconds": 600},
                ),
                auth_testing.AuthTestResult(
                    mechanism="session",
                    check="cookie_httponly_missing",
                    result="medium",
                    title="Session cookie lacks HttpOnly",
                    description="JavaScript can read it.",
                    details={"cookie": "sessionid"},
                ),
            ],
            requests_sent=2,
        )

    monkeypatch.setattr(auth_testing, "run_auth_tests", fake_run_auth_tests)
    response = client.post(
        f"/api/analyses/{analysis_id}/auth-test", json={"cookie": "sessionid=abc"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requests_sent"] == 2
    assert len(body["tests"]) == 2
    assert len(body["findings"]) == 1
    assert body["findings"][0]["severity"] == "medium"
    assert body["findings"][0]["category"] == "session"


def test_websocket_event_shape_and_analysis_id(client, fake_discover):
    with client.websocket_connect("/api/apis/live?target=https://example.com") as ws:
        events = [ws.receive_json() for _ in range(6)]

    assert [event["seq"] for event in events] == [1, 2, 3, 4, 5, 6]
    assert [event["type"] for event in events] == [
        "analysis_started",
        "analysis_progress",
        "item_found",
        "item_found",
        "item_found",
        "analysis_completed",
    ]
    assert all(event["tool"] == "yari" for event in events)
    kinds = [event["payload"]["kind"] for event in events[2:5]]
    assert kinds == ["endpoint", "endpoint", "finding"]
    assert events[1]["payload"]["phase"] == "openapi"

    analysis_id = events[0]["analysis_id"]
    assert isinstance(analysis_id, str) and analysis_id.isdigit()
    persisted = client.get("/api/analyses").json()
    assert persisted[0]["id"] == int(analysis_id)

    for event in events:
        parsed = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
        assert parsed.utcoffset() == timedelta(0)
        assert event["analysis_id"] == analysis_id

    completed = events[-1]["payload"]
    assert completed["endpoint_count"] == 2
    assert completed["finding_count"] == 1
    assert completed["grpc_mode"] == "passive"


def test_websocket_fuzz_phase(client, fake_discover, monkeypatch):
    from app import fuzzing

    async def fake_run_fuzz(target, endpoints, **kwargs):
        return fuzzing.FuzzSummary(strategy="safe", requests_sent=4, outcomes=[])

    monkeypatch.setattr(fuzzing, "run_fuzz", fake_run_fuzz)
    with client.websocket_connect(
        "/api/apis/live?target=https://example.com&fuzz=true"
    ) as ws:
        events = []
        while True:
            event = ws.receive_json()
            events.append(event)
            if event["type"] in ("analysis_completed", "analysis_error"):
                break

    phases = [e["payload"].get("phase") for e in events if e["type"] == "analysis_progress"]
    assert "fuzz" in phases
    assert events[-1]["payload"]["requests_sent"] == 4


def test_rate_limit_envelope(client, monkeypatch):
    from app import security

    monkeypatch.setattr(security, "RATE_LIMIT_MAX", 2)
    security.reset_rate_limiter()

    assert client.get("/api/analyses").status_code == 200
    assert client.get("/api/analyses").status_code == 200
    blocked = client.get("/api/analyses")
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMITED"

    # health is exempt from the limiter
    assert client.get("/api/health").status_code == 200


def test_optional_jwt_auth(client, monkeypatch):
    from app import security

    monkeypatch.setattr(security, "JWT_SECRET", "test-secret")
    monkeypatch.setattr(security, "AUTH_REQUIRED", True)
    monkeypatch.setattr(security, "AUTH_PASSWORD", "s3cret")

    assert client.get("/api/analyses").status_code == 401

    token_response = client.post("/api/auth/token", json={"password": "s3cret"})
    assert token_response.status_code == 200
    token = token_response.json()["token"]

    authorized = client.get("/api/analyses", headers={"Authorization": f"Bearer {token}"})
    assert authorized.status_code == 200

    wrong = client.post("/api/auth/token", json={"password": "nope"})
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "UNAUTHORIZED"

    # WebSockets cannot send headers: token travels in the query string
    assert security.validate_ws_token(None) is False
    assert security.validate_ws_token(token) is True
