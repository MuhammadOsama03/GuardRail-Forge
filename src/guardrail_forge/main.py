from time import perf_counter
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from guardrail_forge.auth import require_api_key
from guardrail_forge.config import get_settings
from guardrail_forge import __version__
from guardrail_forge.audit import AuditPage, AuditPurgeResult, AuditRecord, AuditSummary
from guardrail_forge.storage import AuditStore
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


def get_audit_store() -> AuditStore:
    return AuditStore(get_settings().database_path)


def record_scan(store: AuditStore, source: str, result: ScanResponse) -> None:
    store.save(AuditRecord.from_scan(source, result))


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
    content_length = _parse_content_length(request.headers.get("content-length"))
    if content_length == -1:
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
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "guardrail-forge"}


@app.get("/version")
def version() -> dict[str, str]:
    return {"version": __version__}


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

