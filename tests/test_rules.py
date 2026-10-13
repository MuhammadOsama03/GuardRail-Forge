from guardrail_forge.models import Severity
from guardrail_forge.rules import PatternRule, RuleEngine


def test_rule_engine_returns_ordered_findings() -> None:
    rule = PatternRule.compile("test", "test", Severity.HIGH, "matched", r"danger")
    findings = RuleEngine((rule,)).inspect("danger then DANGER")
    assert [finding.start for finding in findings] == [0, 12]
    assert all(finding.rule_id == "test" for finding in findings)
