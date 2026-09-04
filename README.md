<div align="center">

# 🛡️ Aegis

### AI-Powered Cybersecurity Investigation & Threat-Intelligence Platform

**Ingest security telemetry → detect malicious behavior deterministically → reconstruct the attack chain as a graph → investigate and explain it with evidence-grounded AI.**

**[▶ Live demo](https://aegis-ochre-eight.vercel.app)** · Self-hosted · local LLM · zero API-key dependency · reproducible benchmark

![Detection](https://img.shields.io/badge/detection_rate-100%25-22c55e)
![FPR](https://img.shields.io/badge/false_incidents-76%2Fmillion-38bdf8)
![F1](https://img.shields.io/badge/F1-99.1%25-818cf8)
![Rules](https://img.shields.io/badge/detections-58-38bdf8)
![ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-69%2F80_techniques-f97316)
![License](https://img.shields.io/badge/license-All_Rights_Reserved-red)
![CI](https://img.shields.io/badge/demo-live-22c55e)
![Python](https://img.shields.io/badge/python-3.12-3776ab)
![Next.js](https://img.shields.io/badge/Next.js-16-000000)

</div>

---

## The problem

A real intrusion is a handful of events — a login, a PowerShell spawn, an outbound connection, an archive, an upload — scattered across authentication, endpoint, network and DNS logs and buried in **millions** of benign ones. A normal log viewer shows six unrelated lines. SOC tools emit thousands of disconnected alerts a day, and analysts triage them in isolation.

The bottleneck isn't detection. It's **investigation** — connecting scattered signals into a story you can trust and act on.

## What Aegis does

```
02:13  Login from unusual location          02:17  Outbound connection to known-bad IP
02:15  PowerShell process spawned           02:18  Large archive created
02:16  Encoded command executed             02:19  Archive transmitted externally
```

Aegis turns those six events into **one incident**:

> **SEC-0007 — Credential compromise → execution → data exfiltration**
> Severity: **Critical** · Risk **91/100** · Confidence **94%**
> Initial Access ✓ · Execution ✓ · Command & Control ✓ · Collection ✓ · Exfiltration ✓
> *Every node in the attack graph links back to a real event ID.*

## The core principle: **AI is not the detector**

```
   ❌  Logs → LLM → "this looks malicious"      (a confident guess you can't trust)

   ✅  Events → Normalize → Rules + Statistics + Threat Intel → Correlation
              → Attack Graph → Risk Scoring → AI Investigation → Analyst
```

Detection is **deterministic, explainable and reproducible**. The local LLM enters only at the end, and only to *explain*. Its narrative passes two independent checks before an analyst sees it: **reference integrity** (every cited event ID must exist) and a **semantic claim check** — every entity, ATT&CK technique and kill-chain phase the narrative asserts must have been observed by the deterministic layer. Fail either and the report falls back to the rule-derived narrative. This bounds a hallucinating or prompt-injected model; it does **not** claim to verify causal interpretation — that stays with the analyst, and the UI says so rather than showing a green "trust me" badge.

---

## ✨ Features

| | |
|---|---|
| **Multi-source ingestion** | One normalized schema for Windows Event Log / Sysmon, Linux auditd, Zeek/netflow, DNS, cloud & EDR. Vendor adapters auto-detect format. |
| **58 detections, 3 methods** | A YAML rule DSL (`match` / `threshold` / `sequence`), statistical baselines (login-hour histograms, first-seen geo, robust z-score egress, process rarity, DNS entropy), and threat-intel matching. |
| **Attack-story reconstruction** | Detections are correlated into incidents and rendered as a **layered, phase-annotated attack graph** — click any node for the underlying evidence. |
| **Security knowledge graph** | Telemetry becomes typed, time-stamped relationships (NetworkX), so *"show me everything this host touched"* is one query, not a log search. |
| **MITRE ATT&CK mapping** | Every detection maps to techniques; incidents show tactic coverage. 69/80 catalogued techniques covered by the shipped rules. |
| **Explainable risk scoring** | `noisy-OR(detections) + kill-chain bonus + threat-intel + asset-criticality + breadth`, capped at 100 — with a full breakdown of *why* it's a 91. |
| **AI investigation agents** | Specialized Identity / Process / Network / File agents produce findings; a synthesizer writes the narrative; a **reference-integrity + semantic claim verifier** drops any fabricated citation *and* any entity/technique/phase the detectors never observed. |
| **Risk Ledger (v2)** | Per-entity risk that accumulates and decays over days, so weak signals spread across a week compound into a **slow-burn incident** — catching low-and-slow / living-off-the-land campaigns a fixed time window misses. |
| **External-telemetry harness (v2)** | Runs against real Windows-log-schema (OTRF / Winlogbeat / Sysmon) telemetry the author did not write — `python -m aegis_sim.external`. |
| **Investigation Copilot** | Ask *"what did this host connect to?"* — every answer cites the events it used. |
| **Local threat intelligence** | IOC store fed by **public** feeds (abuse.ch Feodo/URLhaus/ThreatFox, Spamhaus DROP) — no commercial API, ₹0 cost. |
| **Secure by design** | JWT + RBAC, API-key ingest, rate limiting, hash-chained audit log, input/size caps, and an architectural **prompt-injection defense** for hostile telemetry. |
| **Enterprise simulator** | A synthetic 60-user org, a benign-traffic generator with hard negatives, and 9 harmless attack scenarios (incl. a low-and-slow campaign) with ground truth. |
| **Reproducible benchmark** | 100 attack + 100 benign scenarios → detection rate, FPR, chain reconstruction, technique F1, latency — all deterministic, LLM excluded. |

---

## 📊 Benchmark results

Committed run — **108 attack + 108 benign** scenarios against a synthetic 60-user enterprise after a 23,047-event benign training baseline (`seed 1337`, fully reproducible with `make eval`):

| Metric | Result |
|--------|-------:|
| **Detection Rate** (recall) | **100.0%** |
| **False incidents / million events** | **~76** |
| False-Positive Rate (balanced set) | 1.9% |
| Precision | 98.2% |
| F1 | 99.1% |
| Attack-chain reconstruction | 88.0% |
| MITRE technique recall | 84.3% |
| IOC correlation accuracy | 80.0% |
| Detection latency (per event) | sub-millisecond |

**216 runs across 9 attack classes** (incl. a low-and-slow campaign) — TP 108 · FP 2 · TN 106 · FN 0. Full report: [`evaluation/results/results.md`](evaluation/results/results.md).

> The LLM is not involved in any number above. Detection is deterministic.

**What this benchmark is — and is not.** The same author wrote the attack scenarios, the benign
look-alikes *and* the 58 rules, so this is a **reproducibility / regression harness**, not an
independent detection-efficacy result. It proves the pipeline behaves as designed and stays stable
across changes; it says nothing about attacks nobody scripted. Percentage FPR is likewise cosmetic on a
balanced set, so the report now also gives **false incidents per million events** and a projected
false-incident/day load. Credible detection numbers need external telemetry and a red team the author
doesn't control — see below.

---

## 🔬 v2 — answering the hard questions

Real practitioners stress-tested the v1 claims. Each critique is now answered with code, not wording:

| Critique | v2 answer |
|----------|-----------|
| *"2% FPR is meaningless — measure per million events, not percent."* | The eval reports **false incidents per million events** and a projected per-day load at enterprise scale. The unit that reaches an analyst is a correlated *incident*, not a raw event. |
| *"You wrote the attacks, look-alikes and rules — that's a unit test, not a detection result."* | Stated plainly in the report, plus an **external-telemetry harness** (`aegis_sim.external`) that runs Aegis over real Windows-log-schema (OTRF/Winlogbeat/Sysmon) telemetry the author did not write. |
| *"Verifying cited IDs exist proves reference integrity, not truth — a model can cite real events and invent their meaning."* | A **Claim Verifier** fact-checks every entity, ATT&CK technique and kill-chain phase in the narrative against the deterministic record; unsupported assertions revert the report to the rule-derived narrative. The UI shows *what was and wasn't verified* — no green "trust me" badge. |
| *"How does the attack graph hold against low-and-slow / living-off-the-land?"* | A **Risk Ledger** accumulates per-entity risk with time-decay, and **graph-path correlation** links hosts by topology rather than time — surfacing campaigns spread over days that never cluster into a chain. |

Honest limits that remain: the Claim Verifier is bounded by what the rules recorded (it can't validate causal *interpretation*); external public datasets are still gameable; ledger decay parameters need tuning on real data. Full breakdown in [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md).

---

## 🏗️ Architecture

```
                         ┌─────────────────────────┐
                         │   Web UI (Next.js/React) │
                         │ Overview · Incidents ·   │
                         │ Attack Graph · Copilot   │
                         └────────────┬────────────┘
                                      │  REST + JWT
                         ┌────────────▼────────────┐
                         │   FastAPI  (RBAC · rate  │
                         │   limit · audit · /metrics)│
                         └────────────┬────────────┘
         ┌───────────────┬────────────┼────────────┬───────────────┐
         ▼               ▼            ▼            ▼               ▼
   Detection        Correlation   Investigation  Threat Intel   Knowledge
   (rules/stats/TI)  → Incidents   (AI agents)    (IOC store)    Graph
         └───────────────┴────────────┼────────────┴───────────────┘
                                      ▼
                    PostgreSQL · Redis Streams · Ollama (local LLM)
```

**Pipeline:** `events → normalize → detect → knowledge graph → correlate → attack graph → risk score → AI investigation → analyst`. The same `Platform` object powers the API, the streaming worker, and the evaluation harness. Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Tech stack
**Backend** Python · FastAPI · Pydantic · SQLAlchemy · NetworkX  ·  **Data** PostgreSQL · Redis Streams · pgvector  ·  **AI** Ollama (local LLM) · local embeddings · evidence grounding  ·  **Frontend** Next.js · TypeScript · Tailwind · React Flow · Recharts  ·  **Ops** Docker Compose · Prometheus · Grafana · GitHub Actions

---

## 🚀 Quick start

### Docker (everything)

```bash
git clone https://github.com/raunitgrey7/aegis.git && cd aegis
docker compose up --build            # API :8000, Web :3000
# optional: local AI narrative + dashboards
docker compose --profile ai --profile observability up --build
docker compose exec ollama ollama pull llama3.1:8b   # once, for the AI narrative
```

Open **http://localhost:3000** and log in with `analyst` / `analyst`. The platform boots with a seeded demo environment (real incidents, attack graphs, threat map).

### Local development

```bash
python -m venv .venv && . .venv/Scripts/activate      # Windows: .venv\Scripts\activate
pip install -e backend -e simulator

uvicorn aegis.main:app --reload                        # API + docs at http://localhost:8000/docs
cd frontend && npm install && npm run dev              # UI at http://localhost:3000
```

Demo accounts: `admin/admin`, `analyst/analyst`, `viewer/viewer`.

### Reproduce the benchmark

```bash
python -m aegis_sim.evaluation --attacks 100 --benign 100 --out evaluation/results
```

### Build the pitch deck

```bash
python pitch/build_deck.py            # → pitch/Aegis-Pitch-Deck.pptx (reads real results.json)
```

---

## 🎬 A tour in three commands

```bash
# 1. push a live "malicious document → C2" attack into the running API
python scripts/seed_demo.py --scenario C

# 2. see it detected, correlated and scored
curl -s localhost:8000/api/incidents -H "Authorization: Bearer $TOKEN" | jq '.incidents[0]'

# 3. run the AI investigation (grounded, cites real evidence)
curl -s -X POST localhost:8000/api/incidents/SEC-0001/investigate -H "Authorization: Bearer $TOKEN" | jq '.grounding'
```

---

## 🧪 Tests & CI

```bash
make test          # 57 backend tests: schema, DSL, detectors, correlation, scoring, graph,
                   # investigation, prompt-injection guard, API auth/RBAC, audit chain, scenarios
make lint
```

GitHub Actions runs the test suite, a benchmark smoke test with quality gates (≥90% detection, ≤10% FPR), and the frontend build on every push.

---

## 📚 Documentation

| Doc | What's inside |
|-----|---------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, the pipeline, "AI is not the detector", diagrams |
| [DETECTION.md](docs/DETECTION.md) | Rule DSL, condition operators, anomaly math, all 58 rules, risk formula |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Securing a security product; prompt-injection defense-in-depth |
| [EVALUATION.md](docs/EVALUATION.md) | Synthetic enterprise, scenarios A–H, metrics, methodology |
| [API.md](docs/API.md) · [API_CONTRACT.md](docs/API_CONTRACT.md) | Full REST reference with RBAC and examples |
| [RUNBOOK.md](docs/RUNBOOK.md) | Operate locally & in Docker, env vars, troubleshooting |

---

## ⚖️ Safety & scope

The attack simulator generates **synthetic telemetry only** — it describes attacks as events; it never attacks, exploits, or touches any real system. Threat-intelligence uses public, freely-redistributable feeds. This is a research/portfolio platform. **Copyright © 2026 Raunit Thakur. All rights reserved** — see [LICENSE](LICENSE).

---

<div align="center">

**Aegis turns scattered telemetry into a story you can trust.**

Built by [Raunit Thakur](https://github.com/raunitgrey7)

Copyright © 2026 Raunit Thakur. All rights reserved.

</div>
