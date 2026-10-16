import json

from guardrail_forge.eval_cli import main


def test_cli_emits_machine_readable_report(capsys) -> None:
    assert main(["--suite", "core-security", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["suite_name"] == "core-security"
    assert payload["failed"] == 0


def test_cli_emits_markdown(capsys) -> None:
    assert main(["--format", "markdown"]) == 0
    assert "# Evaluation: core-security" in capsys.readouterr().out
