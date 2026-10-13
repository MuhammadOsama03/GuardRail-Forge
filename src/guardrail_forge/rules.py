import re
from dataclasses import dataclass

from guardrail_forge.models import Finding, Severity


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]

    @classmethod
    def compile(
        cls, rule_id: str, category: str, severity: Severity, message: str, pattern: str
    ) -> "PatternRule":
        return cls(rule_id, category, severity, message, re.compile(pattern, re.IGNORECASE))

    def inspect(self, text: str) -> list[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                message=self.message,
                start=match.start(),
                end=match.end(),
            )
            for match in self.pattern.finditer(text)
        ]


class RuleEngine:
    def __init__(self, rules: tuple[PatternRule, ...] = ()) -> None:
        self.rules = rules

    def inspect(self, text: str) -> list[Finding]:
        return sorted(
            (finding for rule in self.rules for finding in rule.inspect(text)),
            key=lambda finding: (finding.start, finding.end, finding.rule_id),
        )

