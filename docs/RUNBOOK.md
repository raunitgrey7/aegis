# Aegis — Operator Runbook

## Prerequisites

- Python 3.11+ and Node.js 20+ (for the frontend), or Docker + Docker Compose.
- Optional: [Ollama](https://ollama.com) running locally for the AI narrative. Without it, Aegis produces
  a complete deterministic narrative instead.

## Run locally (no Docker)

```bash
# backend
python -m venv .venv && . .venv/Scripts/activate      # or .venv/bin/activate on *nix
pip install -e backend
pip install -e simulator
uvicorn aegis.main:app --host 0.0.0.0 --port 8000      # seeds demo data on startup

# frontend (separate shell)
cd frontend
npm install
NEXT_PUBLIC_API_URL=http://localhost:8000/api npm run dev   # http://localhost:3000
```

The API seeds a realistic demo dataset (benign baseline + a spread of attacks) on startup, so the
dashboard is populated immediately. Log in with `analyst / analyst`.

## Run with Docker Compose

```bash
docker compose up --build
```

Brings up Postgres, Redis, Ollama, the API, the detection worker, the web UI, Prometheus and Grafana.
The API is on `:8000`, the UI on `:3000`, Prometheus on `:9090`, Grafana on `:3001`.

## Configuration (env vars)

All settings are `AEGIS_`-prefixed and read from the environment or a `.env` file
(`backend/aegis/config.py`). The important ones:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AEGIS_API_HOST` / `AEGIS_API_PORT` | `0.0.0.0` / `8000` | API bind |
| `AEGIS_CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed UI origins |
| `AEGIS_DATABASE_URL` | SQLite file | Persistence (use Postgres in prod) |
| `AEGIS_REDIS_URL` | `None` | Redis Streams bus; unset ⇒ in-memory bus |
| `AEGIS_JWT_SECRET` | dev placeholder | **Change in production** — signs JWTs |
| `AEGIS_INGEST_API_KEY` | `aegis-dev-ingest-key` | **Change in production** — ingest auth |
| `AEGIS_ADMIN_USERNAME` / `AEGIS_ADMIN_PASSWORD` | `admin` / `admin` | **Change in production** |
| `AEGIS_MAX_REQUEST_BYTES` | `2 MiB` | Request size cap |
| `AEGIS_MAX_EVENTS_PER_BATCH` | `5000` | Ingest batch cap |
| `AEGIS_RATE_LIMIT_PER_MINUTE` | `600` | Token-bucket rate limit |
| `AEGIS_CORRELATION_WINDOW_SECONDS` | `3600` | Detection-clustering window |
| `AEGIS_INCIDENT_MIN_SCORE` | `40` | Incident admission floor |
| `AEGIS_OLLAMA_URL` / `AEGIS_OLLAMA_MODEL` | `http://localhost:11434` / `llama3.1:8b` | Local LLM |
| `AEGIS_LLM_ENABLED` | `true` | Toggle the AI narrative entirely |

## Enable the AI narrative (optional)

```bash
ollama serve &
ollama pull llama3.1:8b
export AEGIS_OLLAMA_MODEL=llama3.1:8b
```

The investigation engine checks `GET /api/tags` for availability and falls back to the deterministic
narrative if the model is down, times out, or returns invalid JSON. If the model's output cites any event
ID that does not exist in the incident, the report reverts to the deterministic narrative — so the LLM can
never introduce ungrounded claims.

## Run the evaluation benchmark

```bash
python -m aegis_sim.evaluation --attacks 100 --benign 100 --seed 1337 --out evaluation/results
```

Deterministic for a fixed seed. Writes `results.json`, `results.md`, and `example_incidents.json`.

## Refresh threat-intel feeds

The repo ships an offline snapshot so the platform runs with no network. To pull the latest public feeds:

```bash
python -m aegis.threat_intel.feeds refresh
```

Downloads abuse.ch Feodo/URLhaus/ThreatFox and Spamhaus DROP into
`backend/aegis/data/threat_intel/`. Feeds are parsed defensively; a bad feed file is logged and skipped,
never crashing the platform.

## Inject a test attack against a running platform

```bash
ADMIN=$(curl -s -X POST http://localhost:8000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' | jq -r .access_token)
curl -s -X POST http://localhost:8000/api/simulate -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{"scenario":"C"}'
```

## Observability

- Prometheus metrics at `GET /api/metrics` (events ingested, detections, open incidents by severity,
  ingest/investigation latency histograms, API request counters).
- Health at `GET /api/healthz`.
- The audit log (`GET /api/audit`, admin) is hash-chained; `verification.valid` must be `true`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `401` on every call | Missing/expired JWT — re-login; check `AEGIS_JWT_SECRET` matches across replicas |
| `401` on `/ingest` | Wrong `x-api-key`; must equal `AEGIS_INGEST_API_KEY` |
| `403` on an action | Role too low; analyst for investigate/status, admin for simulate/audit |
| `413` on ingest | Batch or body exceeds caps — split the batch |
| `429` | Rate limit hit — back off or raise `AEGIS_RATE_LIMIT_PER_MINUTE` |
| Investigation `llm_used:false` when you expected true | Ollama not reachable, timed out, or returned bad JSON; or the output was ungrounded and reverted. Check `GET /api/healthz` `llm` field |
| Empty dashboard | Startup seeding disabled or failed; POST some events or run `/simulate` |
| Password hashing error on startup | Ensure `passlib` is installed; Aegis uses `pbkdf2_sha256` (no bcrypt backend needed) |
