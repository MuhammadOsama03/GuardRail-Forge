import json
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from guardrail_forge.models import EvaluationRequest, EvaluationResponse, ScanRequest, ScanResponse


class GuardRailError(RuntimeError):
    pass


class GuardRailClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 10,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.opener = opener

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except HTTPError as error:
            raise GuardRailError(f"GuardRail API returned HTTP {error.code}") from error

    def scan(self, text: str, source: str = "python-sdk") -> ScanResponse:
        payload = ScanRequest(text=text, source=source)
        return ScanResponse.model_validate(self._post("/v1/scan", payload.model_dump()))

    def evaluate(self, request: EvaluationRequest) -> EvaluationResponse:
        return EvaluationResponse.model_validate(
            self._post("/v1/evaluate", request.model_dump(mode="json"))
        )

