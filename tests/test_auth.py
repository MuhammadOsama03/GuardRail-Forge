from fastapi.testclient import TestClient

from guardrail_forge.config import Settings, get_settings
from guardrail_forge.main import app


def test_scan_requires_configured_api_key() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(api_key="secret")
    client = TestClient(app)
    assert client.post("/v1/scan", json={"text": "hello"}).status_code == 401
    assert client.post("/v1/scan", headers={"X-API-Key": "secret"}, json={"text": "hello"}).status_code == 200
    app.dependency_overrides.clear()
