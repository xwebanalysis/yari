"""Pydantic schemas for the Yari REST API (xwa-sdk aligned envelopes)."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class EndpointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    protocol: str
    method: Optional[str] = None
    path: str
    host: Optional[str] = None
    params: Optional[List[Dict[str, Any]]] = None
    auth_required: Optional[bool] = None
    source: str
    content_types: Optional[List[str]] = None
    version: Optional[str] = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tool: str
    severity: str
    category: Optional[str] = None
    check: Optional[str] = None
    title: str
    description: Optional[str] = None
    target_url: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    cvss_score: Optional[float] = None
    confidence: Optional[str] = None
    detected_at: Optional[datetime] = None


class FuzzRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    endpoint_id: Optional[int] = None
    strategy: str
    requests_sent: int
    findings_count: int
    status: str
    abort_reason: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class AuthTestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mechanism: str
    check: str
    result: str
    details: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: str
    analysis_type: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    endpoints: List[EndpointRead] = []
    findings: List[FindingRead] = []
    fuzz_runs: List[FuzzRunRead] = []
    auth_tests: List[AuthTestRead] = []


class AnalysisListItem(BaseModel):
    """Summary row for the analysis history (GET /api/analyses)."""

    id: int
    target: str
    status: str
    analysis_type: str
    created_at: datetime
    finished_at: Optional[datetime] = None
    endpoint_count: int = 0
    finding_count: int = 0
    high_count: int = 0
    fuzz_run_count: int = 0
    auth_test_count: int = 0


class DiscoverRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    max_bundles: int = Field(default=10, ge=0, le=20)


class DiscoverResponse(BaseModel):
    analysis: AnalysisRead
    endpoint_count: int
    finding_count: int
    by_protocol: Dict[str, int]


class FuzzRequest(BaseModel):
    endpoint_ids: Optional[List[int]] = None
    strategy: str = "safe"
    allow_mutations: bool = False
    auth_token: Optional[str] = None
    auth_cookie: Optional[str] = None


class FuzzResponse(BaseModel):
    analysis_id: int
    strategy: str
    requests_sent: int
    aborted: bool = False
    abort_reason: Optional[str] = None
    runs: List[FuzzRunRead] = []
    findings: List[FindingRead] = []


class AuthTestRequest(BaseModel):
    token: Optional[str] = None
    cookie: Optional[str] = None


class AuthTestResponse(BaseModel):
    analysis_id: int
    requests_sent: int
    tests: List[AuthTestRead] = []
    findings: List[FindingRead] = []


class TokenRequest(BaseModel):
    password: str


class TokenResponse(BaseModel):
    token: str
    expires_in: int
