from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, Request

from guardrail_forge.auth import require_api_key
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

app = FastAPI(title="GuardRail Forge", version="0.1.0")


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    started = perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["Server-Timing"] = f'app;dur={(perf_counter() - started) * 1000:.2f}'
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "guardrail-forge"}


@app.post("/v1/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
def scan(payload: ScanRequest) -> ScanResponse:
    return scan_text(payload.text)


@app.post("/v1/scan/batch", response_model=BatchScanResponse, dependencies=[Depends(require_api_key)])
def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    results = [scan_text(item.text) for item in payload.items]
    return BatchScanResponse(safe=all(result.safe for result in results), results=results)


@app.post("/v1/evaluate", response_model=EvaluationResponse, dependencies=[Depends(require_api_key)])
def evaluate(payload: EvaluationRequest) -> EvaluationResponse:
    result = scan_text(payload.text)
    policy = SecurityPolicy(
        name=payload.policy_name,
        block_at=payload.block_at,
        blocked_categories=frozenset(payload.blocked_categories),
    )
    return EvaluationResponse(policy_name=policy.name, allowed=policy.allows(result.findings), scan=result)

