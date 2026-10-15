from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from guardrail_forge.models import Action, Finding, ScanResponse


class AuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str
    safe: bool
    action: Action
    risk_score: int = Field(ge=0, le=100)
    finding_count: int = Field(ge=0)
    categories: list[str]
    findings: list[Finding]

    @classmethod
    def from_scan(cls, source: str, scan: ScanResponse) -> "AuditRecord":
        return cls(
            source=source,
            safe=scan.safe,
            action=scan.action,
            risk_score=scan.risk_score,
            finding_count=len(scan.findings),
            categories=sorted({finding.category for finding in scan.findings}),
            findings=scan.findings,
        )


class AuditPage(BaseModel):
    items: list[AuditRecord]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class AuditSummary(BaseModel):
    total_scans: int = Field(ge=0)
    blocked_scans: int = Field(ge=0)
    average_risk_score: float = Field(ge=0, le=100)
    category_counts: dict[str, int]

