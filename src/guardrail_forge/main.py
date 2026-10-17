from time import perf_counter
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from hashlib import sha256

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from guardrail_forge.auth import require_api_key
from guardrail_forge.config import get_settings
from guardrail_forge import __version__
from guardrail_forge.audit import AuditPage, AuditPurgeResult, AuditRecord, AuditSummary
from guardrail_forge.storage import AuditStore
from guardrail_forge.rate_limit import SlidingWindowRateLimiter
from guardrail_forge.benchmarks import BUILTIN_SUITES
from guardrail_forge.evaluations import (
    EvaluationReport,
    EvaluationSuite,
    EvaluationSuiteSummary,
    render_markdown,
    run_suite,
)
from guardrail_forge.metrics import MetricsRegistry, render_prometheus
from guardrail_forge.alerts import ActiveAlert, evaluate_alerts
from guardrail_forge.models import (
    BatchScanRequest,
    BatchScanResponse,
    EvaluationRequest,
    EvaluationResponse,
    ScanRequest,
    ScanResponse,
)
from guardrail_forge.policy import SecurityPolicy
from guardrail_forge.scanner import scan_text

app = FastAPI(title="GuardRail Forge", version=__version__)
rate_limiter = SlidingWindowRateLimiter(get_settings().rate_limit_per_minute)
metrics = MetricsRegistry()


def get_audit_store() -> AuditStore:
    return AuditStore(get_settings().database_path)


def record_scan(store: AuditStore, source: str, result: ScanResponse) -> None:
    store.save(AuditRecord.from_scan(source, result))
    metrics.record_scan(result)


def _parse_content_length(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return -1
    return parsed if parsed >= 0 else -1


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    started = perf_counter()
    decision = None
    if request.url.path.startswith("/v1/") and rate_limiter.limit:
        credential = request.headers.get("x-api-key")
        identity = sha256(credential.encode()).hexdigest() if credential else (request.client.host if request.client else "unknown")
        decision = rate_limiter.check(identity)
    content_length = _parse_content_length(request.headers.get("content-length"))
    if decision is not None and not decision.allowed:
        response = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": str(decision.retry_after)},
        )
    elif content_length == -1:
        response = JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "Invalid Content-Length header"},
        )
    elif content_length is not None and content_length > get_settings().max_request_bytes:
        response = JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={"detail": "Request body too large"},
        )
    else:
        response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["Server-Timing"] = f'app;dur={(perf_counter() - started) * 1000:.2f}'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if decision is not None:
        response.headers["X-RateLimit-Limit"] = str(decision.limit)
        response.headers["X-RateLimit-Remaining"] = str(decision.remaining)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "guardrail-forge"}


@app.get("/ready")
def ready(store: AuditStore = Depends(get_audit_store)) -> JSONResponse:
    available = store.is_ready()
    return JSONResponse(
        status_code=status.HTTP_200_OK if available else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ready" if available else "unavailable", "database": available},
    )


@app.get("/version")
def version() -> dict[str, str]:
    return {"version": __version__}


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(render_prometheus(metrics.snapshot()), media_type="text/plain")


@app.get("/v1/alerts", response_model=list[ActiveAlert], dependencies=[Depends(require_api_key)])
def active_alerts() -> list[ActiveAlert]:
    return evaluate_alerts(metrics.snapshot())


@app.post("/v1/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
def scan(payload: ScanRequest, store: AuditStore = Depends(get_audit_store)) -> ScanResponse:
    result = scan_text(payload.text)
    record_scan(store, payload.source, result)
    return result


@app.post("/v1/scan/batch", response_model=BatchScanResponse, dependencies=[Depends(require_api_key)])
def scan_batch(payload: BatchScanRequest, store: AuditStore = Depends(get_audit_store)) -> BatchScanResponse:
    results = [scan_text(item.text) for item in payload.items]
    for item, result in zip(payload.items, results, strict=True):
        record_scan(store, item.source, result)
    return BatchScanResponse(safe=all(result.safe for result in results), results=results)


@app.post("/v1/evaluate", response_model=EvaluationResponse, dependencies=[Depends(require_api_key)])
def evaluate(payload: EvaluationRequest, store: AuditStore = Depends(get_audit_store)) -> EvaluationResponse:
    result = scan_text(payload.text)
    record_scan(store, payload.source, result)
    policy = SecurityPolicy(
        name=payload.policy_name,
        block_at=payload.block_at,
        blocked_categories=frozenset(payload.blocked_categories),
    )
    return EvaluationResponse(policy_name=policy.name, allowed=policy.allows(result.findings), scan=result)


@app.get("/v1/audits", response_model=AuditPage, dependencies=[Depends(require_api_key)])
def list_audits(
    limit: int = 50,
    offset: int = 0,
    safe: bool | None = None,
    source: str | None = None,
    min_risk: int | None = None,
    store: AuditStore = Depends(get_audit_store),
) -> AuditPage:
    limit = min(max(limit, 1), 100)
    offset = max(offset, 0)
    min_risk = min(max(min_risk, 0), 100) if min_risk is not None else None
    items, total = store.list(
        limit=limit, offset=offset, safe=safe, source=source, min_risk=min_risk
    )
    return AuditPage(items=items, total=total, limit=limit, offset=offset)


@app.get("/v1/audits/{record_id}", response_model=AuditRecord, dependencies=[Depends(require_api_key)])
def get_audit(record_id: str, store: AuditStore = Depends(get_audit_store)) -> AuditRecord:
    record = store.get(record_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit record not found")
    return record


@app.get("/v1/audits-summary", response_model=AuditSummary, dependencies=[Depends(require_api_key)])
def audit_summary(store: AuditStore = Depends(get_audit_store)) -> AuditSummary:
    return store.summary()


@app.delete("/v1/audits", response_model=AuditPurgeResult, dependencies=[Depends(require_api_key)])
def purge_audits(
    older_than_days: int = 30,
    store: AuditStore = Depends(get_audit_store),
) -> AuditPurgeResult:
    older_than_days = min(max(older_than_days, 1), 3650)
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    return AuditPurgeResult(deleted=store.purge_before(cutoff), cutoff=cutoff)


@app.get("/v1/audits-export", response_class=PlainTextResponse, dependencies=[Depends(require_api_key)])
def export_audits(store: AuditStore = Depends(get_audit_store)) -> PlainTextResponse:
    return PlainTextResponse(
        store.export_jsonl(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="guardrail-audits.jsonl"'},
    )


@app.get(
    "/v1/evaluations",
    response_model=list[EvaluationSuiteSummary],
    dependencies=[Depends(require_api_key)],
)
def list_evaluations() -> list[EvaluationSuiteSummary]:
    return [
        EvaluationSuiteSummary(
            name=suite.name,
            description=suite.description,
            case_count=len(suite.cases),
            tags=sorted({tag for case in suite.cases for tag in case.tags}),
        )
        for suite in BUILTIN_SUITES.values()
    ]


@app.post(
    "/v1/evaluations/run",
    response_model=EvaluationReport,
    dependencies=[Depends(require_api_key)],
)
def run_custom_evaluation(suite: EvaluationSuite) -> EvaluationReport:
    return run_suite(suite)


@app.post(
    "/v1/evaluations/{suite_name}/run",
    response_model=EvaluationReport,
    dependencies=[Depends(require_api_key)],
)
def run_evaluation(suite_name: str) -> EvaluationReport:
    suite = BUILTIN_SUITES.get(suite_name)
    if suite is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evaluation suite not found")
    return run_suite(suite)


@app.get(
    "/v1/evaluations/{suite_name}/report",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_api_key)],
)
def evaluation_report(suite_name: str) -> PlainTextResponse:
    suite = BUILTIN_SUITES.get(suite_name)
    if suite is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evaluation suite not found")
    return PlainTextResponse(
        render_markdown(run_suite(suite)),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{suite_name}-evaluation.md"'},
    )

