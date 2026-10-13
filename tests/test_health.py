from fastapi.testclient import TestClient

from guardrail_forge.main import app


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "guardrail-forge"}
    assert response.headers["x-request-id"]
    assert response.headers["server-timing"].startswith("app;dur=")


def test_preserves_client_request_id() -> None:
    response = TestClient(app).get("/health", headers={"X-Request-ID": "trace-123"})
    assert response.headers["x-request-id"] == "trace-123"
