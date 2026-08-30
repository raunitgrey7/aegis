# Aegis — API Reference

Base URL: `http://localhost:8000/api`. Interactive docs (OpenAPI/Swagger) at `http://localhost:8000/docs`.
All routes are defined in `backend/aegis/api/routers.py`.

## Authentication flow

Humans authenticate with username/password and receive a JWT (HS256, `jwt_expiry_minutes` default 480).
Send it as `Authorization: Bearer <token>` on every other request. The ingest pipeline authenticates with
a static API key header (`x-api-key`) instead.

```bash
# 1. login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"analyst"}' | jq -r .access_token)

# 2. use it
curl -s http://localhost:8000/api/overview -H "Authorization: Bearer $TOKEN"
```

Demo accounts (in-memory store, `api/security.py:UserStore`): `admin/admin` (admin), `analyst/analyst`
(analyst), `viewer/viewer` (viewer). **Change these for any non-demo deployment.**

## RBAC roles

Ordered: `viewer (10) < analyst (20) < admin (30)`, plus a machine `ingestor (5)` role authenticated by
API key. `require_role(min)` returns **403** below the required level.

## Endpoints by area

### auth
| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/auth/login` | — | Exchange credentials for a JWT |
| GET | `/auth/me` | any | Current identity `{username, role, tenant}` |

### ingest
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ingest` | `x-api-key` | Normalize + ingest a batch of raw collector records. Enforces `max_events_per_batch` (5000) and the rate limiter |

```bash
curl -s -X POST http://localhost:8000/api/ingest \
  -H 'x-api-key: aegis-dev-ingest-key' -H 'Content-Type: application/json' \
  -d '{"collector":"windows","events":[
       {"EventID":4625,"Computer":"WS-042","TimeCreated":"2026-08-30T02:00:00Z",
        "EventData":{"TargetUserName":"alice","IpAddress":"5.188.86.172"}}]}'
# → {"accepted":1,"deduplicated":0,"detections":1,"incidents_open":14}
```

### dashboard
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/overview` | viewer | Threat level, counts, severity/phase distributions, tactic coverage, top incidents, graph & TI stats |

### incidents
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/incidents?severity=&status=&limit=` | viewer | Filtered incident summaries |
| GET | `/incidents/{id}` | viewer | Full incident + events + `critical_path` |
| GET | `/incidents/{id}/graph` | viewer | Attack graph `{nodes, edges}` + critical path |
| POST | `/incidents/{id}/status` | analyst | Update status (`open`/`investigating`/`contained`/`resolved`/`false_positive`) |

### investigation
| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/incidents/{id}/investigate` | analyst | Run the agent pipeline; returns narrative, timeline, agent findings, MITRE, recommended actions, `grounding` |
| POST | `/incidents/{id}/copilot` | analyst | Ask a question about the incident; answer cites evidence and is grounded |

```bash
curl -s -X POST http://localhost:8000/api/incidents/SEC-0007/copilot \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"question":"what external IPs did this host connect to?"}'
# → {"answer":"...","evidence":[{"event_id":"evt_...","time":"02:24:20","summary":"..."}],
#    "llm_used":false,"grounding":{"grounded":true, ...}}
```

### graph
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/graph/entity?q=&depth=` | viewer | Neighbourhood of an entity in the knowledge graph |
| GET | `/graph/search?q=` | viewer | Fuzzy entity search |
| GET | `/graph/threat-map` | viewer | External IPs/domains across incidents with TI context |

### threat-intel
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/threat-intel/stats` | viewer | Loaded indicator counts by type and feed |
| GET | `/threat-intel/lookup?value=` | viewer | Look up an IP/domain/hash/URL |

### rules & mitre
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/rules` | viewer | All loaded detection rules + fire counts |
| GET | `/mitre/coverage` | viewer | Catalogue technique coverage by the rule set (tactics tree) |
| GET | `/mitre/observed` | viewer | Techniques actually observed across incidents |

### simulator
| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/simulate` | admin | Inject attack scenario A–H into the live platform |
| GET | `/simulate/scenarios` | viewer | List available scenarios |

### admin / audit
| Method | Path | Role | Description |
|--------|------|------|-------------|
| GET | `/audit?n=` | admin | Recent audit entries + hash-chain verification |

### ops
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | — | Liveness + event/incident counts + LLM availability |
| GET | `/metrics` | — | Prometheus exposition |
| GET | `/` (root) | — | Service banner |

## Response shapes

Full JSON schemas for `/overview`, incidents, the attack graph, and the investigation report are in
`docs/API_CONTRACT.md`. Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`)
and `X-Response-Time-ms` are set on every response; unhandled errors return a generic 500 with no stack
trace.
