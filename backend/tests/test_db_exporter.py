"""Database export tests: raw JSON payload + encrypted container round-trip."""

import json

import pytest

from app import db_exporter, models
from app.database import SessionLocal


@pytest.fixture()
def seeded_db(client, create_analysis, fake_discover):
    """Create two analyses (one of them fuzzed) and return the response bodies."""
    first = create_analysis("https://example.com")
    fuzz = client.post(
        f"/api/analyses/{first['analysis']['id']}/fuzz",
        json={"strategy": "rate_limit", "endpoint_ids": None},
    )
    assert fuzz.status_code == 200, fuzz.text
    second = create_analysis("https://api.example.org")
    return {"first": first, "second": second, "fuzz": fuzz.json()}


def test_build_export_payload_shape(seeded_db):
    with SessionLocal() as db:
        payload = db_exporter.build_export_payload(db)

    meta = payload["export_metadata"]
    assert meta["analysis_count"] == 2
    assert meta["endpoint_count"] == 4  # 2 per analysis
    assert meta["finding_count"] >= 1  # graphql introspection finding each
    assert meta["yari_version"]
    assert "samurai_version" in meta  # container compatibility field

    analyses = payload["analyses"]
    assert [a["id"] for a in analyses] == [2, 1]  # newest first

    for analysis in analyses:
        assert set(analysis) >= {
            "id",
            "target",
            "status",
            "analysis_type",
            "created_at",
            "endpoints",
            "findings",
            "fuzz_runs",
            "auth_tests",
        }
        assert analysis["endpoints"]
        assert analysis["findings"]
        for finding in analysis["findings"]:
            assert finding["severity"] in ("pass", "info", "low", "medium", "high", "critical")
            # evidence never stores supplied secrets (nothing here, but shape)
            assert isinstance(finding.get("evidence"), (dict, list, type(None)))


def test_raw_export_endpoint(seeded_db, client):
    response = client.get("/api/database/export/raw")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "yari-database-export.json" in response.headers["content-disposition"]

    payload = response.json()
    assert payload["export_metadata"]["analysis_count"] == 2
    # fuzz run persisted on analysis #1
    first = next(a for a in payload["analyses"] if a["id"] == 1)
    assert len(first["fuzz_runs"]) >= 1
    assert first["fuzz_runs"][0]["strategy"] == "rate_limit"


def test_encrypted_export_round_trip(seeded_db, client):
    response = client.post(
        "/api/database/export/encrypted", json={"password": "test-pass-1234"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert "yari-database-export.bin.enc" in response.headers["content-disposition"]

    container = response.content
    assert container.startswith(db_exporter.EXPORT_HEADER)

    decrypted = db_exporter.decrypt_export_payload(container, "test-pass-1234")
    assert decrypted["export_metadata"]["analysis_count"] == 2
    assert decrypted["analyses"][0]["endpoints"]


def test_encrypted_export_rejects_short_password(seeded_db, client):
    for bad in ("", "ab", "abc"):
        response = client.post("/api/database/export/encrypted", json={"password": bad})
        assert response.status_code == 400
        assert "at least 4 characters" in response.json()["error"]["message"]


def test_encrypted_export_wrong_password_fails(seeded_db, client):
    response = client.post(
        "/api/database/export/encrypted", json={"password": "correct-pass"}
    )
    container = response.content
    with pytest.raises(Exception):
        db_exporter.decrypt_export_payload(container, "wrong-pass")


def test_decrypt_rejects_unknown_header():
    with pytest.raises(ValueError):
        db_exporter.decrypt_export_payload(b"NOT-AN-EXPORT", "whatever")


def test_empty_database_export(client):
    response = client.get("/api/database/export/raw")
    assert response.status_code == 200
    payload = response.json()
    assert payload["export_metadata"]["analysis_count"] == 0
    assert payload["analyses"] == []
