from guardrail_forge.detectors import default_engine
from guardrail_forge.models import Finding, ScanResponse, Severity
from guardrail_forge.redaction import find_pii, find_secrets, redact

BLOCKING_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


def scan_text(text: str) -> ScanResponse:
    findings = default_engine().inspect(text) + find_secrets(text) + find_pii(text)
    findings.sort(key=lambda finding: (finding.start, finding.end, finding.rule_id))
    sensitive = [finding for finding in findings if finding.category in {"secret_exposure", "personal_data"}]
    return ScanResponse(
        safe=not any(finding.severity in BLOCKING_SEVERITIES for finding in findings),
        findings=findings,
        redacted_text=redact(text, sensitive),
    )

