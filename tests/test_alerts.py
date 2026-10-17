from guardrail_forge.alerts import AlertRule, AlertSeverity, evaluate_alerts
from guardrail_forge.metrics import MetricsSnapshot


def test_alert_evaluator_triggers_at_threshold() -> None:
    snapshot = MetricsSnapshot(scans_total=10, blocked_total=4, findings_total=7, categories={})
    rules = (AlertRule(id="blocks", metric="blocked_total", threshold=4,
                       severity=AlertSeverity.CRITICAL, message="too many blocks"),)
    alerts = evaluate_alerts(snapshot, rules)
    assert alerts[0].rule_id == "blocks"
    assert alerts[0].current_value == 4


def test_alert_evaluator_ignores_unknown_metrics() -> None:
    snapshot = MetricsSnapshot(scans_total=0, blocked_total=0, findings_total=0, categories={})
    rules = (AlertRule(id="unknown", metric="missing", threshold=0, message="missing"),)
    assert evaluate_alerts(snapshot, rules) == []
