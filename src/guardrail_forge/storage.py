import sqlite3
from pathlib import Path

from guardrail_forge.audit import AuditRecord


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

    def list(self, limit: int = 50, offset: int = 0) -> tuple[list[AuditRecord], int]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM audit_records ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0]
        return [AuditRecord.model_validate_json(row["payload"]) for row in rows], total

