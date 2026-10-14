from fastapi.testclient import TestClient

from guardrail_forge.main import app


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
