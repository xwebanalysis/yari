"""SQLAlchemy models: analyses, discovered API endpoints, findings and test runs."""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (stored without timezone in SQLite/PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Analysis(Base):
    """An API security analysis session against a target (xwa-sdk Analysis)."""

    __tablename__ = "analyses"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    status = Column(String, default="RUNNING")  # PENDING, RUNNING, COMPLETED, ERROR, CANCELLED
    analysis_type = Column(String, default="api_scan")
    created_at = Column(DateTime, default=utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    endpoints = relationship(
        "ApiEndpoint", back_populates="analysis", cascade="all, delete-orphan"
    )
    findings = relationship(
        "Finding", back_populates="analysis", cascade="all, delete-orphan"
    )
    fuzz_runs = relationship(
        "FuzzRun", back_populates="analysis", cascade="all, delete-orphan"
    )
    auth_tests = relationship(
        "AuthTest", back_populates="analysis", cascade="all, delete-orphan"
    )


class ApiEndpoint(Base):
    """An API endpoint discovered from a spec, introspection, reflection or crawl."""

    __tablename__ = "api_endpoints"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    protocol = Column(String)  # rest | graphql | grpc
    method = Column(String, nullable=True)  # GET, POST, ... (None for gRPC services)
    path = Column(Text)
    host = Column(String, nullable=True)
    params = Column(JSON, nullable=True)  # [{name, in, type, required, ...}]
    auth_required = Column(Boolean, nullable=True)
    source = Column(String)  # openapi | graphql_introspection | grpc_reflection | grpc_passive | js_crawl | html
    content_types = Column(JSON, nullable=True)
    version = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    analysis = relationship("Analysis", back_populates="endpoints")


class Finding(Base):
    """A security finding on the unified xwa-sdk severity scale."""

    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    endpoint_id = Column(
        Integer, ForeignKey("api_endpoints.id", ondelete="SET NULL"), nullable=True
    )

    tool = Column(String, default="yari")
    severity = Column(String)  # pass | info | low | medium | high | critical
    category = Column(String)  # injection | auth | authz | session | disclosure | misconfig
    check = Column(String)
    title = Column(String)
    description = Column(Text, nullable=True)
    target_url = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # includes poc_payload (never secrets)
    cvss_score = Column(Float, nullable=True)
    confidence = Column(String, nullable=True)  # low | medium | high
    detected_at = Column(DateTime, default=utcnow)

    analysis = relationship("Analysis", back_populates="findings")


class FuzzRun(Base):
    """One fuzzing pass over one endpoint with one strategy."""

    __tablename__ = "fuzz_runs"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    endpoint_id = Column(
        Integer, ForeignKey("api_endpoints.id", ondelete="CASCADE"), nullable=True
    )

    strategy = Column(String)  # safe | reflect | error_based | authz_matrix | rate_limit
    requests_sent = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    status = Column(String, default="RUNNING")  # RUNNING, COMPLETED, ABORTED, ERROR
    abort_reason = Column(String, nullable=True)
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime, nullable=True)

    analysis = relationship("Analysis", back_populates="fuzz_runs")


class AuthTest(Base):
    """One authentication/session mechanism check."""

    __tablename__ = "auth_tests"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    mechanism = Column(String)  # jwt | session | apikey
    check = Column(String)
    result = Column(String)  # pass | info | low | medium | high | critical
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    analysis = relationship("Analysis", back_populates="auth_tests")
