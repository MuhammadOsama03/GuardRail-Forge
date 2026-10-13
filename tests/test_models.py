import pytest
from pydantic import ValidationError

from guardrail_forge.models import ScanRequest


def test_scan_request_rejects_empty_text() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(text="")


def test_scan_request_defaults_source() -> None:
    assert ScanRequest(text="hello").source == "user"
