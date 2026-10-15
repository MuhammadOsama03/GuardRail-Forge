from guardrail_forge.audit import AuditRecord
from guardrail_forge.models import Action


def test_audit_record_assigns_identity_and_timestamp() -> None:
    record = AuditRecord(
        source="user",
        safe=True,
        action=Action.ALLOW,
        risk_score=0,
        finding_count=0,
        categories=[],
        findings=[],
    )
    assert record.id
    assert record.created_at.tzinfo is not None
