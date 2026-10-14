import re

from guardrail_forge.models import Finding, Severity

SECRET_PATTERNS = (
    ("secret.openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("secret.bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}")),
    ("secret.aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("secret.slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
)

PII_PATTERNS = (
    ("pii.email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("pii.credit_card", re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")),
)


def find_secrets(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="secret_exposure",
                    severity=Severity.CRITICAL,
                    message="Potential credential exposure",
                    start=match.start(),
                    end=match.end(),
                )
            )
    return sorted(findings, key=lambda finding: finding.start)


def find_pii(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pattern in PII_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="personal_data",
                    severity=Severity.HIGH,
                    message="Potential personal data exposure",
                    start=match.start(),
                    end=match.end(),
                )
            )
    return sorted(findings, key=lambda finding: finding.start)


def redact(text: str, findings: list[Finding]) -> str:
    result = text
    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        result = result[: finding.start] + "[REDACTED]" + result[finding.end :]
    return result

