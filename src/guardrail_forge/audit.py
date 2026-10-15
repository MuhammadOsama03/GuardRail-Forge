from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from guardrail_forge.models import Action, Finding


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


class AuditPage(BaseModel):
    items: list[AuditRecord]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)

