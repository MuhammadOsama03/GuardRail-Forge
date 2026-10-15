from datetime import UTC, datetime, timedelta

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


def test_store_lists_newest_records_with_pagination(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    records = [
        AuditRecord(source=str(index), safe=True, action=Action.ALLOW, risk_score=0,
                    finding_count=0, categories=[], findings=[])
        for index in range(3)
    ]
    for record in records:
        store.save(record)
    page, total = store.list(limit=2, offset=1)
    assert total == 3
    assert len(page) == 2


def test_store_filters_by_verdict_source_and_risk(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    store.save(AuditRecord(source="sdk", safe=False, action=Action.BLOCK, risk_score=80,
                           finding_count=0, categories=[], findings=[]))
    store.save(AuditRecord(source="web", safe=True, action=Action.ALLOW, risk_score=0,
                           finding_count=0, categories=[], findings=[]))
    page, total = store.list(safe=False, source="sdk", min_risk=50)
    assert total == 1
    assert page[0].source == "sdk"


def test_store_summarizes_security_activity(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    store.save(AuditRecord(source="sdk", safe=False, action=Action.BLOCK, risk_score=80,
                           finding_count=0, categories=["prompt_injection"], findings=[]))
    store.save(AuditRecord(source="web", safe=True, action=Action.ALLOW, risk_score=20,
                           finding_count=0, categories=[], findings=[]))
    summary = store.summary()
    assert summary.total_scans == 2
    assert summary.blocked_scans == 1
    assert summary.average_risk_score == 50
    assert summary.category_counts == {"prompt_injection": 1}


def test_store_purges_only_records_before_cutoff(tmp_path) -> None:
    store = AuditStore(tmp_path / "audit.db")
    old = AuditRecord(created_at=datetime.now(UTC) - timedelta(days=60), source="old",
                      safe=True, action=Action.ALLOW, risk_score=0, finding_count=0,
                      categories=[], findings=[])
    current = AuditRecord(source="current", safe=True, action=Action.ALLOW, risk_score=0,
                          finding_count=0, categories=[], findings=[])
    store.save(old)
    store.save(current)
    assert store.purge_before(datetime.now(UTC) - timedelta(days=30)) == 1
    assert store.get(current.id) is not None
