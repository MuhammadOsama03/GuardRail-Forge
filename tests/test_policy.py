from guardrail_forge.models import Finding, Severity
from guardrail_forge.policy import SecurityPolicy


def finding(severity: Severity, category: str = "test") -> Finding:
    return Finding(rule_id="test", category=category, severity=severity, message="test", start=0, end=1)


def test_policy_blocks_at_configured_severity() -> None:
    policy = SecurityPolicy(block_at=Severity.CRITICAL)
    assert policy.allows([finding(Severity.HIGH)]) is True
    assert policy.allows([finding(Severity.CRITICAL)]) is False


def test_policy_can_block_category_below_threshold() -> None:
    policy = SecurityPolicy(block_at=Severity.CRITICAL, blocked_categories=frozenset({"custom"}))
    assert policy.allows([finding(Severity.LOW, "custom")]) is False
