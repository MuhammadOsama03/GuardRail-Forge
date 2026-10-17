import json

from guardrail_forge.client import GuardRailClient


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return json.dumps(
            {"safe": True, "action": "allow", "risk_score": 0, "findings": [], "redacted_text": "hello"}
        ).encode()


def test_python_client_builds_authenticated_scan_request() -> None:
    captured = {}

    def opener(request, timeout):
        captured.update(url=request.full_url, key=request.get_header("X-api-key"), timeout=timeout)
        return Response()

    result = GuardRailClient("https://guardrail.test/", "secret", timeout=3, opener=opener).scan("hello")
    assert result.safe is True
    assert captured == {"url": "https://guardrail.test/v1/scan", "key": "secret", "timeout": 3}
