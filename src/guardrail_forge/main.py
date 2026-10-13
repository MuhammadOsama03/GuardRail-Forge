from fastapi import FastAPI

from guardrail_forge.models import BatchScanRequest, BatchScanResponse, ScanRequest, ScanResponse
from guardrail_forge.scanner import scan_text

app = FastAPI(title="GuardRail Forge", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "guardrail-forge"}


@app.post("/v1/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    return scan_text(payload.text)


@app.post("/v1/scan/batch", response_model=BatchScanResponse)
def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    results = [scan_text(item.text) for item in payload.items]
    return BatchScanResponse(safe=all(result.safe for result in results), results=results)

