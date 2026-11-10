from fastapi.testclient import TestClient
from guardrail_forge.main import app
from guardrail_forge.auth import require_api_key


def test_metrics_enforces_auth_dependency():
    def reject():
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Missing API key")
    app.dependency_overrides[require_api_key] = reject
    try:
        response = TestClient(app).get("/metrics")
        assert response.status_code == 401
    finally:
        app.dependency_overrides.pop(require_api_key, None)
