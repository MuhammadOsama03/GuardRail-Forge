from guardrail_forge.models import Finding, Severity
from guardrail_forge.risk import calculate_risk_score


def finding(severity: Severity) -> Finding:
    return Finding(rule_id="test", category="test", severity=severity, message="test", start=0, end=1)


def test_empty_scan_has_zero_risk() -> None:
    assert calculate_risk_score([]) == 0


def test_risk_prioritizes_severity_and_caps_at_100() -> None:
    assert calculate_risk_score([finding(Severity.HIGH)]) == 50
    assert calculate_risk_score([finding(Severity.CRITICAL)] * 4) == 100
