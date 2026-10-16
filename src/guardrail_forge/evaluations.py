from datetime import UTC, datetime

from pydantic import BaseModel, Field


class EvaluationCase(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    text: str = Field(min_length=1, max_length=100_000)
    expected_safe: bool
    tags: set[str] = Field(default_factory=set, max_length=20)


class EvaluationSuite(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    cases: list[EvaluationCase] = Field(min_length=1, max_length=1_000)


class EvaluationCaseResult(BaseModel):
    case_id: str
    expected_safe: bool
    actual_safe: bool
    passed: bool
    risk_score: int
    finding_rules: list[str]


class EvaluationReport(BaseModel):
    suite_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total: int
    passed: int
    failed: int
    pass_rate: float
    results: list[EvaluationCaseResult]

