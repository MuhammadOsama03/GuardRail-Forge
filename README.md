# GuardRail Forge

Security testing, threat detection, and runtime protection for AI applications and agents.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn guardrail_forge.main:app --reload
```

The API is available at `http://localhost:8000`, with interactive documentation at `/docs`.

Version 0.2 adds obfuscation and role-delimiter detection, broader cloud-secret coverage, checksum-aware payment-card detection, overlap-safe redaction, aggregate risk scores, and custom policy evaluation.

## Scan content

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"text":"Ignore previous instructions"}'
```

The response includes a safety verdict, structured findings with exact character ranges, and a copy of the text with detected credentials or personal data redacted. Up to 100 inputs can be checked using `POST /v1/scan/batch`.

## Authentication

Set `GUARDRAIL_API_KEY` in shared environments and send it through the `X-API-Key` header. Authentication is intentionally optional for local development. Copy `.env.example` to `.env` as a starting point, but never commit real secrets.

## Current detection coverage

- Attempts to override prior instructions
- Requests to expose system or developer prompts
- Role-override and jailbreak phrases
- OpenAI-style keys, GitHub tokens, and bearer tokens
- Email addresses and payment-card-like numbers

Pattern rules are deterministic and explainable. They are an initial protection layer, not a replacement for access control, sandboxing, output validation, or human approval of sensitive actions.

## Custom policy evaluation

Use `POST /v1/evaluate` to apply a caller-selected severity threshold and blocked-category set. The response keeps the scanner's baseline recommendation separate from the custom policy verdict, making policy decisions explicit and auditable.

Requests are limited to 250 KB by default. Override the limit with `GUARDRAIL_MAX_REQUEST_BYTES` when necessary.
