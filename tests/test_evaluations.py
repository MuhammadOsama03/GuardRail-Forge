import pytest
from pydantic import ValidationError

from guardrail_forge.evaluations import EvaluationCase, EvaluationSuite


def test_suite_requires_at_least_one_case() -> None:
    with pytest.raises(ValidationError):
        EvaluationSuite(name="empty", cases=[])


def test_case_supports_security_tags() -> None:
    case = EvaluationCase(id="injection-1", text="hello", expected_safe=True, tags={"baseline"})
    assert case.tags == {"baseline"}
