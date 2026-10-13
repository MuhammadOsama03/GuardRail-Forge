# GuardRail Forge

Security testing, threat detection, and runtime protection for AI applications and agents.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn guardrail_forge.main:app --reload
```
