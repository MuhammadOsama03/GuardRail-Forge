from fastapi import FastAPI

from guardrail_forge.models import ScanRequest, ScanResponse
from guardrail_forge.scanner import scan_text

app = FastAPI(title="GuardRail Forge", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "guardrail-forge"}


@app.post("/v1/scan", response_model=ScanResponse)
def scan(payload: ScanRequest) -> ScanResponse:
    return scan_text(payload.text)

