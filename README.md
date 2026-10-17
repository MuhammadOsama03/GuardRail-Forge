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

Version 0.3 adds a durable SQLite audit trail with filtered pagination, record lookup, activity summaries, retention cleanup, JSON Lines export, and database-aware readiness reporting.

Version 0.4 adds per-client sliding-window rate limits and repeatable security evaluation suites for API, CLI, and CI workflows.

Version 1.0 completes the first production release with an operational dashboard, Python SDK, Prometheus metrics, alert evaluation, and hardened container deployment.

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

## Audit operations

Every scan and policy evaluation records security metadata without retaining the submitted text. Configure storage with `GUARDRAIL_DATABASE_PATH`.

- `GET /v1/audits` lists records and accepts `safe`, `source`, `min_risk`, `limit`, and `offset` filters.
- `GET /v1/audits/{record_id}` retrieves one record.
- `GET /v1/audits-summary` reports scan, block, risk, and category totals.
- `GET /v1/audits-export` downloads chronological JSON Lines.
- `DELETE /v1/audits?older_than_days=30` removes expired records.
- `GET /ready` verifies that the configured database is reachable.

## Security evaluation gates

Run the built-in regression suite locally or in CI:

```bash
guardrail-eval --suite core-security --minimum-pass-rate 1.0
```

Use `--format markdown` for a reviewable report. The API exposes suite discovery at `GET /v1/evaluations`, built-in execution at `POST /v1/evaluations/{suite_name}/run`, caller-supplied suites at `POST /v1/evaluations/run`, and Markdown reports at `GET /v1/evaluations/{suite_name}/report`.

API traffic is limited to 120 requests per client per minute by default. Set `GUARDRAIL_RATE_LIMIT_PER_MINUTE=0` to disable limiting or choose a deployment-appropriate capacity.

## Operations dashboard and metrics

Open `/dashboard/` for responsive audit metrics, alerts, and recent security activity. When API authentication is enabled, enter the key in the dashboard; it remains in browser session storage only.

Prometheus-compatible counters are exposed at `/metrics`. Active threshold alerts are available through `GET /v1/alerts`.

## Python client

```python
from guardrail_forge.client import GuardRailClient

client = GuardRailClient("http://localhost:8000", api_key="your-key")
result = client.scan("Untrusted user content")
if not result.safe:
    print(result.findings)
```

## Production deployment

```bash
cp .env.example .env
# Replace GUARDRAIL_API_KEY with a strong random value.
docker compose up --build -d
```

The Compose deployment runs without Linux capabilities, uses a read-only root filesystem, prevents privilege escalation, persists audit data in a named volume, and performs database-aware health checks.
