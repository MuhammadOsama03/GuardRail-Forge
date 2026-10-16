from datetime import UTC, datetime

from pydantic import BaseModel, Field

from guardrail_forge.scanner import scan_text


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


class EvaluationSuiteSummary(BaseModel):
    name: str
    description: str
    case_count: int
    tags: list[str]


def run_suite(suite: EvaluationSuite) -> EvaluationReport:
    results: list[EvaluationCaseResult] = []
    for case in suite.cases:
        scan = scan_text(case.text)
        results.append(
            EvaluationCaseResult(
                case_id=case.id,
                expected_safe=case.expected_safe,
                actual_safe=scan.safe,
                passed=scan.safe == case.expected_safe,
                risk_score=scan.risk_score,
                finding_rules=sorted({finding.rule_id for finding in scan.findings}),
            )
        )
    passed = sum(result.passed for result in results)
    return EvaluationReport(
        suite_name=suite.name,
        total=len(results),
        passed=passed,
        failed=len(results) - passed,
        pass_rate=round(passed / len(results), 4),
        results=results,
    )

