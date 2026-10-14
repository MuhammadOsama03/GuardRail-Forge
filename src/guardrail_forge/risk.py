from guardrail_forge.models import Finding, Severity

SEVERITY_POINTS = {
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 50,
    Severity.CRITICAL: 80,
}


def calculate_risk_score(findings: list[Finding]) -> int:
    """Return a stable 0–100 score with diminishing weight for repeated findings."""
    ordered = sorted((SEVERITY_POINTS[item.severity] for item in findings), reverse=True)
    score = 0.0
    for index, points in enumerate(ordered):
        score += points * (0.5**index)
    return min(100, round(score))

