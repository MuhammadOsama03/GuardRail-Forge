import sqlite3
from pathlib import Path

from guardrail_forge.audit import AuditRecord, AuditSummary


class AuditStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    safe INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_records(created_at DESC)"
            )

    def save(self, record: AuditRecord) -> AuditRecord:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_records VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.created_at.isoformat(),
                    record.source,
                    int(record.safe),
                    record.risk_score,
                    record.model_dump_json(),
                ),
            )
        return record

    def get(self, record_id: str) -> AuditRecord | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM audit_records WHERE id = ?", (record_id,)
            ).fetchone()
        return AuditRecord.model_validate_json(row["payload"]) if row else None

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        safe: bool | None = None,
        source: str | None = None,
        min_risk: int | None = None,
    ) -> tuple[list[AuditRecord], int]:
        clauses: list[str] = []
        parameters: list[object] = []
        if safe is not None:
            clauses.append("safe = ?")
            parameters.append(int(safe))
        if source is not None:
            clauses.append("source = ?")
            parameters.append(source)
        if min_risk is not None:
            clauses.append("risk_score >= ?")
            parameters.append(min_risk)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT payload FROM audit_records{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (*parameters, limit, offset),
            ).fetchall()
            total = connection.execute(
                f"SELECT COUNT(*) FROM audit_records{where}", parameters
            ).fetchone()[0]
        return [AuditRecord.model_validate_json(row["payload"]) for row in rows], total

    def summary(self) -> AuditSummary:
        with self.connect() as connection:
            rows = connection.execute("SELECT payload FROM audit_records").fetchall()
        records = [AuditRecord.model_validate_json(row["payload"]) for row in rows]
        category_counts: dict[str, int] = {}
        for record in records:
            for category in record.categories:
                category_counts[category] = category_counts.get(category, 0) + 1
        return AuditSummary(
            total_scans=len(records),
            blocked_scans=sum(not record.safe for record in records),
            average_risk_score=(
                round(sum(record.risk_score for record in records) / len(records), 2)
                if records else 0
            ),
            category_counts=dict(sorted(category_counts.items())),
        )

