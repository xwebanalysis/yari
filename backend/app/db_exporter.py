"""Full-database export (xwa-sdk ``SAMURAI_DB_EXPORT_V1``-compatible).

Mirrors ``samurai/backend/app/db_exporter.py`` so Yari exports are
interchangeable across the XWA toolchain:

- The raw payload is a JSON document with ``export_metadata`` plus one list
  key (``analyses``) carrying the complete database (analyses, endpoints,
  findings, fuzz runs and auth tests).
- The encrypted variant is AES-256-GCM with a PBKDF2-SHA256 key (600,000
  iterations, random 16-byte salt, random 12-byte nonce) and keeps the exact
  ``SAMURAI_DB_EXPORT_V1`` container header.

Import/restore is intentionally not implemented yet (pending roadmap item):
there is no ``decrypt-and-restore`` endpoint in Yari. ``decrypt_export_payload``
is kept only to round-trip-verify exports in the test suite.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.orm import Session, joinedload

from . import __version__
from . import models

EXPORT_HEADER = b"SAMURAI_DB_EXPORT_V1"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _finding_dict(finding: models.Finding) -> dict:
    return {
        "id": finding.id,
        "endpoint_id": finding.endpoint_id,
        "tool": finding.tool,
        "severity": finding.severity,
        "category": finding.category,
        "check": finding.check,
        "title": finding.title,
        "description": finding.description,
        "target_url": finding.target_url,
        "evidence": finding.evidence,
        "cvss_score": finding.cvss_score,
        "confidence": finding.confidence,
        "detected_at": _iso(finding.detected_at),
    }


def _endpoint_dict(endpoint: models.ApiEndpoint) -> dict:
    return {
        "id": endpoint.id,
        "protocol": endpoint.protocol,
        "method": endpoint.method,
        "path": endpoint.path,
        "host": endpoint.host,
        "params": endpoint.params,
        "auth_required": endpoint.auth_required,
        "source": endpoint.source,
        "content_types": endpoint.content_types,
        "version": endpoint.version,
        "created_at": _iso(endpoint.created_at),
    }


def _analysis_dict(analysis: models.Analysis) -> dict:
    return {
        "id": analysis.id,
        "target": analysis.target,
        "status": analysis.status,
        "analysis_type": analysis.analysis_type,
        "created_at": _iso(analysis.created_at),
        "started_at": _iso(analysis.started_at),
        "finished_at": _iso(analysis.finished_at),
        "error_message": analysis.error_message,
        "endpoints": [_endpoint_dict(e) for e in analysis.endpoints],
        "findings": [_finding_dict(f) for f in analysis.findings],
        "fuzz_runs": [
            {
                "id": run.id,
                "endpoint_id": run.endpoint_id,
                "strategy": run.strategy,
                "requests_sent": run.requests_sent,
                "findings_count": run.findings_count,
                "status": run.status,
                "abort_reason": run.abort_reason,
                "started_at": _iso(run.started_at),
                "finished_at": _iso(run.finished_at),
            }
            for run in analysis.fuzz_runs
        ],
        "auth_tests": [
            {
                "id": test.id,
                "mechanism": test.mechanism,
                "check": test.check,
                "result": test.result,
                "details": test.details,
                "created_at": _iso(test.created_at),
            }
            for test in analysis.auth_tests
        ],
    }


def build_export_payload(db: Session) -> dict:
    """Serialize the whole Yari database into the export document."""
    analyses = (
        db.query(models.Analysis)
        .options(
            joinedload(models.Analysis.endpoints),
            joinedload(models.Analysis.findings),
            joinedload(models.Analysis.fuzz_runs),
            joinedload(models.Analysis.auth_tests),
        )
        .order_by(models.Analysis.id.desc())
        .all()
    )

    analyses_data = [_analysis_dict(analysis) for analysis in analyses]
    endpoint_count = sum(len(a.get("endpoints", [])) for a in analyses_data)
    finding_count = sum(len(a.get("findings", [])) for a in analyses_data)

    return {
        "export_metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "samurai_version": None,  # kept for container compatibility
            "yari_version": __version__,
            "analysis_count": len(analyses_data),
            "endpoint_count": endpoint_count,
            "finding_count": finding_count,
        },
        "analyses": analyses_data,
    }


def encrypt_export_payload(payload: dict, password: str) -> bytes:
    """AES-256-GCM encrypt the payload under a PBKDF2-derived key.

    Container layout (identical to samurai's exporter):
    ``SAMURAI_DB_EXPORT_V1 || salt(16) || nonce(12) || ciphertext``.
    """
    salt = os.urandom(SALT_BYTES)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_BYTES)

    plaintext = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return EXPORT_HEADER + salt + nonce + ciphertext


def decrypt_export_payload(file_bytes: bytes, password: str) -> dict:
    """Decrypt an export container (test/verification helper only).

    Import/restore is a pending roadmap item; this function exists so the
    test suite can prove exports round-trip correctly.
    """
    header_len = len(EXPORT_HEADER)
    if not file_bytes.startswith(EXPORT_HEADER):
        raise ValueError("Invalid export file format")

    salt = file_bytes[header_len : header_len + SALT_BYTES]
    nonce = file_bytes[header_len + SALT_BYTES : header_len + SALT_BYTES + NONCE_BYTES]
    ciphertext = file_bytes[header_len + SALT_BYTES + NONCE_BYTES :]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))
