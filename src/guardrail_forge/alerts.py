from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from guardrail_forge.metrics import MetricsSnapshot


class AlertSeverity(StrEnum):
    WARNING = "warning"
    CRITICAL = "critical"


class AlertRule(BaseModel):
    id: str
    metric: str
    threshold: float = Field(ge=0)
    severity: AlertSeverity = AlertSeverity.WARNING
    message: str


class ActiveAlert(BaseModel):
    rule_id: str
    severity: AlertSeverity
    message: str
    current_value: float
    threshold: float
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


DEFAULT_ALERT_RULES = (
    AlertRule(id="blocked-volume", metric="blocked_total", threshold=10, message="Blocked scan volume is elevated"),
    AlertRule(id="finding-volume", metric="findings_total", threshold=25, message="Security finding volume is elevated"),
)


def evaluate_alerts(snapshot: MetricsSnapshot, rules: tuple[AlertRule, ...] = DEFAULT_ALERT_RULES) -> list[ActiveAlert]:
    values = snapshot.model_dump()
    alerts: list[ActiveAlert] = []
    for rule in rules:
        current = values.get(rule.metric)
        if isinstance(current, (int, float)) and current >= rule.threshold:
            alerts.append(
                ActiveAlert(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    current_value=current,
                    threshold=rule.threshold,
                )
            )
    return alerts

