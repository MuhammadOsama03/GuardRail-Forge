from guardrail_forge.audit import AuditRecord
from guardrail_forge.models import Action
from guardrail_forge.storage import AuditStore


def test_store_round_trips_audit_record(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    record = AuditRecord(
        source="user", safe=True, action=Action.ALLOW, risk_score=0,
        finding_count=0, categories=[], findings=[]
    )
    store.save(record)
    assert store.get(record.id) == record


def test_store_returns_none_for_unknown_record(tmp_path) -> None:
    assert AuditStore(tmp_path / "audit.db").get("missing") is None
