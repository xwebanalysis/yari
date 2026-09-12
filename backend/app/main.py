"""Yari REST + WebSocket API (FastAPI, SQLite-first, xwa-sdk envelopes)."""

import csv
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from . import analyzer, auth_testing, database, fuzzing, models, schemas, security
from .events import EventStream

SERVICE_VERSION = "0.1.0"
TOOL = "yari"

ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMITED",
    500: "INTERNAL",
    502: "UPSTREAM_ERROR",
    503: "SERVICE_UNAVAILABLE",
}
RETRYABLE_STATUS = {429, 502, 503}

SEVERITY_CVSS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
    "pass": 0.0,
}


def _error_payload(code: str, message: str, detail=None, retryable: bool = False) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
            "retryable": retryable,
        }
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.wait_for_db()
    models.Base.metadata.create_all(bind=database.engine)
    yield


app = FastAPI(
    title="Yari API",
    description="API security testing: discovery, safe fuzzing and auth analysis",
    version=SERVICE_VERSION,
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, **security.cors_settings())
app.middleware("http")(security.auth_middleware)
app.middleware("http")(security.rate_limit_middleware)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code = ERROR_CODES.get(exc.status_code, "HTTP_ERROR")
    message = exc.detail if isinstance(exc.detail, str) else code
    detail = exc.detail if isinstance(exc.detail, dict) else None
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_payload(code, message, detail, exc.status_code in RETRYABLE_STATUS),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=_error_payload(
            "VALIDATION_ERROR",
            "Request validation failed.",
            {"errors": jsonable_encoder(exc.errors())},
        ),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort envelope so clients never receive a bare 500 body."""
    return JSONResponse(
        status_code=500,
        content=_error_payload(
            "INTERNAL",
            "Unexpected server error.",
            {"exception": exc.__class__.__name__},
        ),
    )


# ── time helpers ────────────────────────────────────────────────────────────


def _dbnow() -> datetime:
    """Naive UTC timestamp for database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# ── serialization helpers ───────────────────────────────────────────────────


def _analysis_counts(analysis: models.Analysis) -> dict:
    by_protocol: dict[str, int] = {}
    for endpoint in analysis.endpoints:
        by_protocol[endpoint.protocol] = by_protocol.get(endpoint.protocol, 0) + 1
    return {
        "endpoint_count": len(analysis.endpoints),
        "finding_count": len(analysis.findings),
        "high_count": sum(
            1 for finding in analysis.findings if finding.severity in ("high", "critical")
        ),
        "fuzz_run_count": len(analysis.fuzz_runs),
        "auth_test_count": len(analysis.auth_tests),
        "by_protocol": by_protocol,
    }


def _summary(analysis: models.Analysis) -> schemas.AnalysisListItem:
    counts = _analysis_counts(analysis)
    return schemas.AnalysisListItem(
        id=analysis.id,
        target=analysis.target,
        status=analysis.status,
        analysis_type=analysis.analysis_type,
        created_at=analysis.created_at,
        finished_at=analysis.finished_at,
        endpoint_count=counts["endpoint_count"],
        finding_count=counts["finding_count"],
        high_count=counts["high_count"],
        fuzz_run_count=counts["fuzz_run_count"],
        auth_test_count=counts["auth_test_count"],
    )


def _endpoint_payload(endpoint: models.ApiEndpoint) -> dict:
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
    }


def _persist_discovery(
    db: Session,
    analysis: models.Analysis,
    endpoints: list,
    findings: list,
) -> None:
    for endpoint in endpoints:
        db.add(
            models.ApiEndpoint(
                analysis_id=analysis.id,
                protocol=endpoint.protocol,
                method=endpoint.method,
                path=endpoint.path,
                host=endpoint.host,
                params=endpoint.params,
                auth_required=endpoint.auth_required,
                source=endpoint.source,
                content_types=endpoint.content_types,
                version=endpoint.version,
            )
        )
    for finding in findings:
        db.add(
            models.Finding(
                analysis_id=analysis.id,
                tool=TOOL,
                severity=finding.severity,
                category=finding.category,
                check=finding.check,
                title=finding.title,
                description=finding.description,
                target_url=finding.target_url,
                evidence=finding.evidence,
                cvss_score=SEVERITY_CVSS.get(finding.severity),
                confidence=finding.confidence,
            )
        )
    db.commit()


def _analysis_export(analysis: models.Analysis) -> dict:
    """Full JSON export of an analysis as a downloadable file."""
    return {
        "tool": TOOL,
        "version": SERVICE_VERSION,
        "id": analysis.id,
        "target": analysis.target,
        "status": analysis.status,
        "analysis_type": analysis.analysis_type,
        "created_at": _iso(analysis.created_at),
        "started_at": _iso(analysis.started_at),
        "finished_at": _iso(analysis.finished_at),
        "error_message": analysis.error_message,
        "endpoints": [
            {
                **_endpoint_payload(endpoint),
                "analysis_id": analysis.id,
            }
            for endpoint in analysis.endpoints
        ],
        "findings": [
            {
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
            for finding in analysis.findings
        ],
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
        "summary": _analysis_counts(analysis),
    }


def _findings_csv(analysis: models.Analysis) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "analysis_id",
            "target",
            "endpoint_id",
            "severity",
            "category",
            "check",
            "title",
            "target_url",
            "confidence",
            "cvss_score",
            "detected_at",
            "evidence",
        ]
    )
    for finding in analysis.findings:
        writer.writerow(
            [
                analysis.id,
                analysis.target,
                finding.endpoint_id or "",
                finding.severity or "",
                finding.category or "",
                finding.check or "",
                finding.title or "",
                finding.target_url or "",
                finding.confidence or "",
                finding.cvss_score if finding.cvss_score is not None else "",
                _iso(finding.detected_at) or "",
                json.dumps(finding.evidence or {}, ensure_ascii=False),
            ]
        )
    return buffer.getvalue()


# ── root / health / auth ────────────────────────────────────────────────────


@app.get("/")
def read_root():
    return {"status": "ok", "service": TOOL, "version": SERVICE_VERSION}


@app.get("/api/health")
def health():
    db_status = "ok" if database.ping() else "error"
    return JSONResponse(
        status_code=200 if db_status == "ok" else 503,
        content={
            "status": db_status,
            "database": db_status,
            "version": SERVICE_VERSION,
            "tool": TOOL,
        },
    )


@app.post("/api/auth/token", response_model=schemas.TokenResponse)
def issue_token(request: schemas.TokenRequest):
    """Issue a signed token. Only available when YARI_JWT_SECRET is set."""
    if not security.AUTH_REQUIRED:
        raise HTTPException(status_code=403, detail="Auth is disabled (no YARI_JWT_SECRET).")
    if request.password != security.AUTH_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid password.")
    return schemas.TokenResponse(
        token=security.issue_token(),
        expires_in=security.TOKEN_TTL_HOURS * 3600,
    )


# ── discovery ───────────────────────────────────────────────────────────────


@app.post("/api/endpoints/discover", response_model=schemas.DiscoverResponse)
async def discover_endpoints(
    request: schemas.DiscoverRequest,
    db: Session = Depends(database.get_db),
):
    analysis = models.Analysis(target=request.target, status="RUNNING", started_at=_dbnow())
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    try:
        result = await analyzer.discover(
            request.target, max_bundles=request.max_bundles
        )
        _persist_discovery(db, analysis, result.endpoints, result.findings)
        analysis.status = "COMPLETED"
        analysis.finished_at = _dbnow()
        db.commit()
    except analyzer.TargetError as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:  # unexpected failure: never leave the row RUNNING
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        raise

    db.refresh(analysis)
    counts = _analysis_counts(analysis)
    return schemas.DiscoverResponse(
        analysis=analysis,
        endpoint_count=counts["endpoint_count"],
        finding_count=counts["finding_count"],
        by_protocol=counts["by_protocol"],
    )


# ── analyses: history / detail / export / delete ───────────────────────────


@app.get("/api/analyses", response_model=list[schemas.AnalysisListItem])
def list_analyses(db: Session = Depends(database.get_db)):
    rows = (
        db.query(models.Analysis)
        .order_by(models.Analysis.id.desc())
        .limit(50)
        .all()
    )
    return [_summary(row) for row in rows]


@app.get("/api/analyses/{analysis_id}", response_model=schemas.AnalysisRead)
def get_analysis(analysis_id: int, db: Session = Depends(database.get_db)):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


@app.get("/api/analyses/{analysis_id}/export")
def export_analysis(
    analysis_id: int,
    fmt: Literal["json", "csv"] = Query("json", alias="format"),
    db: Session = Depends(database.get_db),
):
    """Download an analysis as JSON (default) or findings CSV."""
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    if fmt == "csv":
        return Response(
            content=_findings_csv(analysis),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="yari-analysis-{analysis.id}.csv"'
            },
        )

    return JSONResponse(
        content=_analysis_export(analysis),
        headers={
            "Content-Disposition": f'attachment; filename="yari-analysis-{analysis.id}.json"'
        },
    )


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int, db: Session = Depends(database.get_db)):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    db.delete(analysis)
    db.commit()
    return Response(status_code=204)


@app.delete("/api/analyses", status_code=204)
def delete_all_analyses(db: Session = Depends(database.get_db)):
    db.query(models.Analysis).delete()
    db.commit()
    return Response(status_code=204)


# ── fuzzing / auth testing ──────────────────────────────────────────────────


def _endpoint_dict(endpoint: models.ApiEndpoint) -> dict:
    return _endpoint_payload(endpoint)


def _select_endpoints(
    analysis: models.Analysis, endpoint_ids: list[int] | None
) -> list[models.ApiEndpoint]:
    endpoints = list(analysis.endpoints)
    if endpoint_ids:
        wanted = set(endpoint_ids)
        endpoints = [endpoint for endpoint in endpoints if endpoint.id in wanted]
    # The global request budget protects the target; this caps stored work too.
    return endpoints[:10]


def _persist_fuzz_summary(
    db: Session,
    analysis: models.Analysis,
    summary: fuzzing.FuzzSummary,
    strategy: str,
) -> list[models.Finding]:
    stored: list[models.Finding] = []
    for outcome in summary.outcomes:
        endpoint_id = (outcome.endpoint or {}).get("id")
        db.add(
            models.FuzzRun(
                analysis_id=analysis.id,
                endpoint_id=endpoint_id,
                strategy=strategy,
                requests_sent=outcome.requests_sent,
                findings_count=len(outcome.findings),
                status=outcome.status,
                abort_reason=outcome.abort_reason or outcome.skipped_reason,
                finished_at=_dbnow(),
            )
        )
        for finding in outcome.findings:
            row = models.Finding(
                analysis_id=analysis.id,
                endpoint_id=endpoint_id,
                tool=TOOL,
                severity=finding.severity,
                category=finding.category,
                check=finding.check,
                title=finding.title,
                description=finding.description,
                target_url=finding.target_url,
                evidence=finding.evidence,
                cvss_score=SEVERITY_CVSS.get(finding.severity),
                confidence=finding.confidence,
            )
            db.add(row)
            stored.append(row)
    db.commit()
    for row in stored:
        db.refresh(row)
    return stored


@app.post("/api/analyses/{analysis_id}/fuzz", response_model=schemas.FuzzResponse)
async def fuzz_analysis(
    analysis_id: int,
    request: schemas.FuzzRequest,
    db: Session = Depends(database.get_db),
):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if request.strategy not in fuzzing.STRATEGIES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown strategy '{request.strategy}'. Use one of: {', '.join(fuzzing.STRATEGIES)}.",
        )

    endpoints = _select_endpoints(analysis, request.endpoint_ids)
    if not endpoints:
        raise HTTPException(status_code=400, detail="No endpoints selected for fuzzing.")

    summary = await fuzzing.run_fuzz(
        analysis.target,
        [_endpoint_dict(endpoint) for endpoint in endpoints],
        strategy=request.strategy,
        allow_mutations=request.allow_mutations,
        auth_token=request.auth_token,
        auth_cookie=request.auth_cookie,
    )
    stored = _persist_fuzz_summary(db, analysis, summary, request.strategy)
    db.refresh(analysis)
    return schemas.FuzzResponse(
        analysis_id=analysis.id,
        strategy=request.strategy,
        requests_sent=summary.requests_sent,
        aborted=summary.aborted,
        abort_reason=summary.abort_reason,
        runs=analysis.fuzz_runs,
        findings=stored,
    )


@app.post("/api/analyses/{analysis_id}/auth-test", response_model=schemas.AuthTestResponse)
async def auth_test_analysis(
    analysis_id: int,
    request: schemas.AuthTestRequest,
    db: Session = Depends(database.get_db),
):
    analysis = db.get(models.Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    endpoints = _select_endpoints(analysis, None)
    summary = await auth_testing.run_auth_tests(
        analysis.target,
        [_endpoint_dict(endpoint) for endpoint in endpoints],
        token=request.token,
        cookie=request.cookie,
    )

    for result in summary.results:
        db.add(
            models.AuthTest(
                analysis_id=analysis.id,
                mechanism=result.mechanism,
                check=result.check,
                result=result.result,
                details={**result.details, "title": result.title},
            )
        )
    stored: list[models.Finding] = []
    for result in summary.findings:
        row = models.Finding(
            analysis_id=analysis.id,
            tool=TOOL,
            severity=result.result,
            category="session" if result.mechanism == "session" else "auth",
            check=result.check,
            title=result.title,
            description=result.description,
            target_url=result.target_url,
            evidence={"details": result.details},
            cvss_score=SEVERITY_CVSS.get(result.result),
            confidence=result.confidence,
        )
        db.add(row)
        stored.append(row)
    db.commit()
    db.refresh(analysis)
    for row in stored:
        db.refresh(row)

    return schemas.AuthTestResponse(
        analysis_id=analysis.id,
        requests_sent=summary.requests_sent,
        tests=analysis.auth_tests,
        findings=stored,
    )


# ── live WebSocket ──────────────────────────────────────────────────────────


@app.websocket("/api/apis/live")
async def websocket_api_live(
    websocket: WebSocket,
    target: str,
    token: str | None = None,
    fuzz: bool = False,
    strategy: str = "safe",
    max_bundles: int = 10,
    allow_mutations: bool = False,
    auth_token: str | None = None,
    auth_cookie: str | None = None,
):
    """Persist the analysis and stream discovery (and optional fuzz/auth) events.

    ``fuzz=true`` runs a safe pass over discovered endpoints (default: false);
    ``auth_token``/``auth_cookie`` trigger the small comparative auth check.
    """
    if security.AUTH_REQUIRED and not security.validate_ws_token(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return

    await websocket.accept()

    db = database.SessionLocal()
    analysis = models.Analysis(target=target, status="RUNNING", started_at=_dbnow())
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    stream = EventStream(websocket, str(analysis.id))

    async def progress(phase: str, message: str, data: dict | None = None) -> None:
        await stream.emit(
            "analysis_progress", {"phase": phase, "message": message, **(data or {})}
        )

    try:
        await stream.emit("analysis_started", {"target": target})
        result = await analyzer.discover(
            target, max_bundles=max_bundles, progress=progress
        )
        _persist_discovery(db, analysis, result.endpoints, result.findings)
        db.refresh(analysis)

        for endpoint in analysis.endpoints:
            await stream.emit(
                "item_found",
                {
                    "kind": "endpoint",
                    "id": endpoint.id,
                    "protocol": endpoint.protocol,
                    "method": endpoint.method,
                    "path": endpoint.path,
                    "source": endpoint.source,
                },
            )
        for finding in analysis.findings:
            await stream.emit(
                "item_found",
                {
                    "kind": "finding",
                    "id": finding.id,
                    "severity": finding.severity,
                    "category": finding.category,
                    "check": finding.check,
                    "title": finding.title,
                    "target_url": finding.target_url,
                },
            )

        requests_sent = 0
        if fuzz and analysis.endpoints:
            await progress("fuzz", f"Running safe fuzzing strategy '{strategy}'", {})
            summary = await fuzzing.run_fuzz(
                target,
                [_endpoint_dict(endpoint) for endpoint in analysis.endpoints[:10]],
                strategy=strategy,
                allow_mutations=allow_mutations,
                auth_token=auth_token,
                auth_cookie=auth_cookie,
            )
            stored_findings = _persist_fuzz_summary(db, analysis, summary, strategy)
            db.refresh(analysis)
            requests_sent += summary.requests_sent
            for finding in stored_findings:
                await stream.emit(
                    "item_found",
                    {
                        "kind": "finding",
                        "id": finding.id,
                        "severity": finding.severity,
                        "check": finding.check,
                        "title": finding.title,
                    },
                )

        if auth_token or auth_cookie:
            await progress("auth", "Analyzing authentication mechanisms", {})
            auth_summary = await auth_testing.run_auth_tests(
                target,
                [_endpoint_dict(endpoint) for endpoint in analysis.endpoints[:10]],
                token=auth_token,
                cookie=auth_cookie,
            )
            requests_sent += auth_summary.requests_sent
            for result_item in auth_summary.results:
                db.add(
                    models.AuthTest(
                        analysis_id=analysis.id,
                        mechanism=result_item.mechanism,
                        check=result_item.check,
                        result=result_item.result,
                        details={**result_item.details, "title": result_item.title},
                    )
                )
            db.commit()
            for result_item in auth_summary.findings:
                await stream.emit(
                    "item_found",
                    {
                        "kind": "finding",
                        "severity": result_item.result,
                        "category": "session"
                        if result_item.mechanism == "session"
                        else "auth",
                        "check": result_item.check,
                        "title": result_item.title,
                        "target_url": result_item.target_url,
                    },
                )

        analysis.status = "COMPLETED"
        analysis.finished_at = _dbnow()
        db.commit()
        db.refresh(analysis)
        counts = _analysis_counts(analysis)
        await stream.emit(
            "analysis_completed",
            {
                **counts,
                "requests_sent": requests_sent,
                "grpc_mode": result.grpc_mode,
                "bundles_scanned": result.bundles_scanned,
                "specs_found": result.specs_found,
            },
        )
    except analyzer.TargetError as exc:
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        try:
            await stream.emit(
                "analysis_error",
                {"code": "TARGET_ERROR", "message": str(exc), "retryable": True},
            )
        except WebSocketDisconnect:
            return
    except WebSocketDisconnect:
        analysis.status = "CANCELLED"
        analysis.finished_at = _dbnow()
        db.commit()
    except Exception as exc:  # defensive: never leave the analysis RUNNING
        analysis.status = "ERROR"
        analysis.finished_at = _dbnow()
        analysis.error_message = str(exc)
        db.commit()
        try:
            await stream.emit(
                "analysis_error",
                {"code": "INTERNAL", "message": str(exc), "retryable": False},
            )
        except WebSocketDisconnect:
            return
    finally:
        db.close()
