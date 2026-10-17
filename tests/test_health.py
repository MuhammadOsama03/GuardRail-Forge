from fastapi.testclient import TestClient

from guardrail_forge.main import app
from guardrail_forge.main import get_audit_store
from guardrail_forge.storage import AuditStore


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "guardrail-forge"}
    assert response.headers["x-request-id"]
    assert response.headers["server-timing"].startswith("app;dur=")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_preserves_client_request_id() -> None:
    response = TestClient(app).get("/health", headers={"X-Request-ID": "trace-123"})
    assert response.headers["x-request-id"] == "trace-123"


def test_reports_service_version() -> None:
    assert TestClient(app).get("/version").json() == {"version": "0.4.0"}


def test_readiness_checks_audit_database(tmp_path) -> None:
    app.dependency_overrides[get_audit_store] = lambda: AuditStore(tmp_path / "audit.db")
    response = TestClient(app).get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": True}
    app.dependency_overrides.clear()


def test_dashboard_shell_is_served() -> None:
    response = TestClient(app).get("/dashboard/")
    assert response.status_code == 200
    assert "GuardRail Forge" in response.text


def test_rejects_oversized_declared_body() -> None:
    response = TestClient(app).post(
        "/v1/scan",
        headers={"content-length": "250001"},
        json={"text": "hello"},
    )
    assert response.status_code == 413


def test_rejects_invalid_content_length() -> None:
    response = TestClient(app).post(
        "/v1/scan",
        headers={"content-length": "not-a-number"},
        content=b'{"text":"hello"}',
    )
    assert response.status_code == 400
