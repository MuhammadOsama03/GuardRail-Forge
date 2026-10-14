from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


class ScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)
    source: str = Field(default="user", max_length=64)


class Finding(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    message: str
    start: int
    end: int


class ScanResponse(BaseModel):
    safe: bool
    action: Action
    risk_score: int = Field(ge=0, le=100)
    findings: list[Finding]
    redacted_text: str


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)


class BatchScanResponse(BaseModel):
    safe: bool
    results: list[ScanResponse]

