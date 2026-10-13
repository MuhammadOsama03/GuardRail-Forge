from guardrail_forge.redaction import find_secrets, redact


def test_redacts_openai_style_key() -> None:
    text = "token=sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = find_secrets(text)
    assert findings[0].rule_id == "secret.openai_key"
    assert redact(text, findings) == "token=[REDACTED]"


def test_preserves_safe_text() -> None:
    assert redact("safe", []) == "safe"
