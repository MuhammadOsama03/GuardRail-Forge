from guardrail_forge.redaction import find_pii, find_secrets, redact


def test_redacts_openai_style_key() -> None:
    text = "token=sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = find_secrets(text)
    assert findings[0].rule_id == "secret.openai_key"
    assert redact(text, findings) == "token=[REDACTED]"


def test_preserves_safe_text() -> None:
    assert redact("safe", []) == "safe"


def test_detects_cloud_and_private_key_credentials() -> None:
    text = "AKIAIOSFODNN7EXAMPLE -----BEGIN PRIVATE KEY-----"
    assert [item.rule_id for item in find_secrets(text)] == [
        "secret.aws_access_key",
        "secret.private_key",
    ]


def test_detects_email_address() -> None:
    findings = find_pii("Contact analyst@example.com")
    assert findings[0].rule_id == "pii.email"


def test_detects_formatted_card_number() -> None:
    findings = find_pii("Card 4111 1111 1111 1111")
    assert findings[0].rule_id == "pii.credit_card"


def test_ignores_number_that_fails_card_checksum() -> None:
    assert find_pii("Reference 4111 1111 1111 1112") == []
