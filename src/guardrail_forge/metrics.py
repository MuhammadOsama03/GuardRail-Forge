from collections import Counter
from threading import Lock

from pydantic import BaseModel

from guardrail_forge.models import ScanResponse


class MetricsSnapshot(BaseModel):
    scans_total: int
    blocked_total: int
    findings_total: int
    categories: dict[str, int]


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._scans = 0
        self._blocked = 0
        self._findings = 0
        self._categories: Counter[str] = Counter()

    def record_scan(self, scan: ScanResponse) -> None:
        with self._lock:
            self._scans += 1
            self._blocked += int(not scan.safe)
            self._findings += len(scan.findings)
            self._categories.update(finding.category for finding in scan.findings)

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(
                scans_total=self._scans,
                blocked_total=self._blocked,
                findings_total=self._findings,
                categories=dict(sorted(self._categories.items())),
            )


def render_prometheus(snapshot: MetricsSnapshot) -> str:
    lines = [
        "# TYPE guardrail_scans_total counter",
        f"guardrail_scans_total {snapshot.scans_total}",
        "# TYPE guardrail_blocked_total counter",
        f"guardrail_blocked_total {snapshot.blocked_total}",
        "# TYPE guardrail_findings_total counter",
        f"guardrail_findings_total {snapshot.findings_total}",
    ]
    for category, count in snapshot.categories.items():
        lines.append(f'guardrail_findings_by_category_total{{category="{category}"}} {count}')
    return "\n".join(lines) + "\n"

