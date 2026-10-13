from dataclasses import dataclass

from guardrail_forge.models import Finding, Severity

SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class SecurityPolicy:
    name: str = "default"
    block_at: Severity = Severity.HIGH
    blocked_categories: frozenset[str] = frozenset()

    def allows(self, findings: list[Finding]) -> bool:
        threshold = SEVERITY_RANK[self.block_at]
        return not any(
            finding.category in self.blocked_categories
            or SEVERITY_RANK[finding.severity] >= threshold
            for finding in findings
        )

