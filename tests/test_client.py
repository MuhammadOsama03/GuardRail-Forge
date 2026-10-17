import json

from guardrail_forge.client import GuardRailClient


class Response:
    def __init__(self, payload=None):
        self.payload = payload or {
            "safe": True, "action": "allow", "risk_score": 0,
            "findings": [], "redacted_text": "hello",
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


def test_python_client_builds_authenticated_scan_request() -> None:
    captured = {}

    def opener(request, timeout):
        captured.update(url=request.full_url, key=request.get_header("X-api-key"), timeout=timeout)
        return Response()

    result = GuardRailClient("https://guardrail.test/", "secret", timeout=3, opener=opener).scan("hello")
    assert result.safe is True
    assert captured == {"url": "https://guardrail.test/v1/scan", "key": "secret", "timeout": 3}


def test_python_client_scans_batches() -> None:
    scan = {"safe": True, "action": "allow", "risk_score": 0, "findings": [], "redacted_text": "safe"}
    client = GuardRailClient("https://guardrail.test", opener=lambda *_args, **_kwargs: Response({"safe": True, "results": [scan, scan]}))
    result = client.scan_batch(["one", "two"])
    assert result.safe is True
    assert len(result.results) == 2
