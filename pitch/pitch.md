# Aegis — Investor & Customer Pitch Playbook

*The AI security analyst that reconstructs the whole attack. Self-hosted, evidence-grounded, zero API-key dependency.*

This document is your complete pitch kit: the narrative, the exact things to say, every statistic, the competitive case, the business model, and the target-customer list. Read the **90-second version** first; the rest is depth for Q&A.

---

## 0. The 90-second version (memorize this)

> "Security teams today aren't short on alerts — they're drowning in them. A single real intrusion is maybe six events scattered across authentication, endpoint, network and DNS logs, buried in millions of benign ones. Analysts triage those alerts one at a time and miss the story that connects them. The industry's answer has been 'bolt an LLM onto your logs' — but that just produces confident guesses you can't put in an incident report.
>
> **Aegis takes a different stance: AI is not the detector.** Detection is done by deterministic engines — rules, statistics, and threat intelligence — so it's explainable and reproducible. Aegis then *correlates* the scattered detections into a single incident, *reconstructs the attack as a graph* you can click through to raw evidence, and only *then* uses a local LLM to explain it — with every sentence validated against real evidence IDs, so it can't hallucinate.
>
> On our reproducible benchmark — 100 simulated attacks and 100 benign look-alikes — Aegis detects **100% of attacks at a 2% false-positive rate**, reconstructs the attack chain with **89.5% accuracy**, and does it with **zero API-key cost** because it runs local models. It's self-hosted, so your telemetry never leaves your network. That's the pitch: we turn scattered telemetry into a story you can trust."

---

## 1. The problem (open here)

Say this, in order:

1. **"The bottleneck moved."** Detection is largely solved — every EDR/SIEM fires alerts. The expensive, scarce, slow part is **investigation**: deciding whether a cluster of signals is a real intrusion and what actually happened.
2. **The 6-event problem.** Show the timeline: login → PowerShell → encoded command → outbound connection → archive created → archive uploaded. "Six lines in six different tools. A human sees six shrugs. The attack is invisible unless something *connects* them."
3. **Alert fatigue is a business risk.** SOCs get thousands of disconnected alerts/day. The 2013 Target breach alerts fired — nobody connected them. Analysts burn out; mean-time-to-respond climbs.
4. **The talent gap.** ~4 million unfilled cybersecurity roles globally. You can't hire your way out; you have to *augment* the analysts you have.
5. **Why "chat with your logs" fails.** An LLM pointed at raw logs will confidently label things malicious with no evidence trail. You cannot base containment — disabling accounts, isolating hosts — on an unverifiable paragraph. Worse, logs contain attacker-controlled text, so the LLM itself becomes an attack surface (prompt injection).

**Land the tension:** "So the market wants AI in the SOC, but the naïve way to add it is untrustworthy and insecure. That gap is the opportunity."

---

## 2. The solution (the core idea)

One sentence: **"Aegis is a self-hosted platform that detects suspicious behavior deterministically, reconstructs the attack chain as a graph, and explains the evidence with grounded AI."**

The principle that makes it credible — put it on screen:

```
  ❌  Logs → LLM → "this looks malicious"          (a guess you can't defend)

  ✅  Events → Normalize → Rules + Statistics + Threat Intel → Correlation
            → Attack Graph → Risk Scoring → AI Investigation → Analyst
```

The nine-stage pipeline, and where AI sits (stage 8, explain-only):
1. **Ingestion** — one normalized schema for Windows/Sysmon, Linux auditd, Zeek/netflow, DNS, cloud, EDR.
2. **Detection** — three deterministic methods (below).
3. **Knowledge graph** — telemetry becomes typed, time-stamped relationships.
4. **Correlation** — detections sharing an identity/host/time collapse into one incident.
5. **Attack graph** — a layered, kill-chain-annotated reconstruction.
6. **MITRE ATT&CK mapping** — every technique labeled.
7. **Risk scoring** — explainable 0–100 with a full breakdown.
8. **AI investigation** — local LLM writes the narrative; **grounding validator** rejects any fabricated citation.
9. **Analyst** — a report they can act on, every claim linked to a real event.

**Say:** "Detection is the part you must trust, so we made it deterministic and reproducible. Explanation is the part AI is genuinely good at, so we use it there — and we fence it so it can't lie."

---

## 3. The killer feature: Attack-Story Reconstruction (demo this live)

Open an incident. Walk the graph left to right:

> `mallory` (identity) → `LT-011` (workstation) → `winword.exe → powershell.exe` (macro spawned an encoded PowerShell) → `45.155.205.233` + `cdn.statistics-collect.com` (outbound C2) → **Cobalt Strike C2 / Sliver C2** (matched threat intel).

Then: **click any node → the raw evidence appears** (the actual encoded command, the connection, bytes out). "This is the difference between an alert list and an investigation. Every node traces to a real event ID. An analyst can defend every step to their boss, to legal, to auditors."

Then flip to **AI Investigation**: point at the green badge — **"Evidence-grounded · 3/3 citations verified · 0 fabricated."** "The AI wrote this narrative, but it physically cannot cite an event that doesn't exist — if it tries, we drop the sentence and fall back to the deterministic write-up. That's how you make AI safe for security decisions."

---

## 4. The statistics (say these numbers with confidence)

All from a **reproducible, seeded benchmark** (`make eval`, seed 1337): 100 attack scenarios + 100 benign look-alikes against a synthetic 60-user enterprise, after a 23,047-event benign training baseline (30,496 events total). **The LLM is not involved in any of these numbers.**

| Metric | Result | What it means |
|--------|-------:|---------------|
| **Detection rate (recall)** | **100.0%** | Every attack scenario raised an incident |
| **False-positive rate** | **2.0%** | Almost never cries wolf on benign look-alikes |
| **Precision** | **98.0%** | When it alerts, it's right 49 out of 50 times |
| **F1 score** | **99.0%** | Balanced accuracy |
| **Attack-chain reconstruction** | **89.5%** | Recovers ~9 of 10 kill-chain phases |
| **MITRE technique recall** | **86.7%** | Correctly labels the techniques used |
| **IOC correlation accuracy** | **82.9%** | Matches known-bad indicators |
| **Evidence coverage** | **73.4%** | Fraction of attack events attached to the incident |
| **Detection latency** | **sub-millisecond / event** | ~0.24 ms per event in the engine |

**Confusion matrix (200 runs):** TP 100 · FP 2 · TN 98 · FN 0.

Coverage & scale numbers:
- **58 detections** across a YAML rule DSL (match / threshold / sequence), 5 statistical detectors, and threat-intel matching.
- **69 / 80** MITRE ATT&CK techniques covered by the shipped rules; **13** kill-chain phases modeled.
- **Threat intel:** local IOC store seeded from public feeds (abuse.ch Feodo/URLhaus/ThreatFox, Spamhaus DROP) — 1,700+ indicators, **₹0** feed cost.
- **57 automated tests**, CI-gated (detection ≥90%, FPR ≤10%).

**Honesty notes for a technical audience (they will respect this):**
- "These are on *synthetic* telemetry we control — it validates the engine and is fully reproducible, but real-world tuning is the next phase. We're transparent about that."
- "Technique *precision* is 62% because an incident aggregates every technique in the cluster, some beyond the ground-truth set — we'd rather over-surface context than hide it."

---

## 5. Why Aegis is better (the competitive case)

Frame competitors in three buckets and where each falls short:

| | **Aegis** | Legacy SIEM (Splunk, QRadar) | EDR (CrowdStrike, SentinelOne) | "AI + logs" startups |
|---|---|---|---|---|
| **Who decides malice** | Deterministic engines | Rules (analyst-written) | Vendor ML (black box) | The LLM (guesses) |
| **Output** | Reconstructed attack graph | Alert firehose | Endpoint alerts | Prose summaries |
| **Trust / evidence** | Every claim cites a real event | Manual pivoting | Limited explainability | Unverifiable |
| **Prompt-injection safety** | Architectural defense-in-depth | N/A | N/A | Usually ignored |
| **Data residency** | Self-hosted, telemetry never leaves | On-prem/cloud | Cloud | Cloud (your logs → their LLM) |
| **Cost model** | ₹0 external — local models & feeds | $$$ per-GB ingest | $$ per-endpoint | Per-token LLM bills |
| **Proof** | Reproducible benchmark | — | Marketing | Demo video |

The three sentences that win the room:
1. **"We don't ask you to trust the AI — we make the AI prove it."** (grounding)
2. **"Your logs never leave your network, and there's no per-token meter running."** (self-hosted, ₹0)
3. **"It's not another alert tool; it hands the analyst a finished, defensible story."** (reconstruction)

---

## 6. Security of the product itself (a differentiator, especially for CISOs)

"A security product must itself be secure — and we consume attacker-controlled text, so we treated prompt injection as an architecture problem, not a prompt trick."

- Untrusted telemetry is neutralized and fenced before it ever reaches the model.
- The model has **no tools** — it only emits text; it can't take actions.
- Output is validated against real evidence IDs (defense-in-depth: prevention + containment).
- Plus the basics: JWT + RBAC, API-key ingest, rate limiting, a **hash-chained audit log**, input/size caps, ReDoS protection.

This slide converts skeptical security buyers because it shows you think like them.

---

## 7. Market & business model (for investors)

- **Market:** SIEM + SOAR + XDR is a >$50B and growing security-operations market; the wedge is **AI-assisted investigation / "AI SOC analyst,"** the hottest 2025–26 category.
- **Wedge product:** an evidence-grounded investigation & attack-reconstruction layer that sits on top of the telemetry a company already collects.
- **Why now:** local LLMs (Llama/Mistral via Ollama) are finally good enough to run investigation on-prem, which unlocks the data-residency + zero-cost story that cloud AI-SOC tools can't match.
- **Go-to-market motions:**
  1. **Open-source core → paid enterprise** (managed multi-tenant, connectors, SSO, retention, support). Classic dev-led/security-led adoption.
  2. **MSSP/MDR channel** — sell to the providers who investigate for many clients; reconstruction + grounding cuts their analyst-hours per incident.
  3. **Design-partner pilots** with mid-market SOCs drowning in alerts.
- **Moat:** the detection-content library (rules + behavioral chains + tuned baselines), the grounding/verification layer, and the reproducible-eval harness that lets you prove quality release-over-release.
- **The ask (tailor):** design partners + a seed round to (a) build production stream ingestion (Kafka/Redpanda), (b) ship live agent-based collectors, (c) add SOAR response playbooks, (d) fine-tune a local investigation model.

---

## 8. Roadmap (what the money/partnership buys)

`Kafka/Redpanda stream processing` → `live agent-based collectors` → `SOAR response playbooks (auto-contain)` → `fine-tuned local investigation model` → `multi-tenant SaaS + MSSP console` → `compliance/reporting packs (SOC 2, PCI, HIPAA evidence)`.

---

## 9. Objection handling (rapid-fire)

- **"Isn't this just a SIEM?"** — SIEM stores and alerts; Aegis *investigates and reconstructs*. We sit on top of your telemetry, we don't replace ingestion.
- **"Your numbers are synthetic."** — Correct, and reproducible with one command. It validates the engine deterministically; real-world tuning is the design-partner phase. That honesty is the point.
- **"LLMs hallucinate — how can I trust it in security?"** — You don't have to. The LLM never detects, and its narrative is validated against real evidence IDs; fabricated citations are dropped automatically.
- **"Why local models instead of GPT-4-class?"** — Data residency (logs never leave), zero per-token cost, and the LLM only does explanation, where local models are already strong. You can point it at a bigger model if you want; it's configurable.
- **"How is this different from CrowdStrike's AI?"** — Vendor AI is a cloud black box tied to their agent. Aegis is self-hosted, vendor-neutral (ingests any telemetry), and every conclusion is evidence-linked and auditable.

---

## 10. The close

"Three deep AI products, three different engineering domains — a personal-AI OS, an SRE incident brain, and now Aegis for security. Aegis proves the thesis: apply AI where it's genuinely useful — explanation — on top of a deterministic, trustworthy core. It runs today, self-hosted, at zero API cost, with a benchmark anyone can reproduce. I'm looking for [design partners / a pilot / seed investment] to take it from a validated engine to a production SOC product."

Links: **Live demo:** `<DEPLOYED_URL>` · **Code:** github.com/raunitgrey7/aegis · **Deck:** `pitch/Aegis-Pitch-Deck.pptx`

---

## 11. Target clients & companies (who to actually contact)

Prioritized by how sharply Aegis's value (self-hosted, evidence-grounded, ₹0-cost investigation) lands.

### Tier 1 — best fit (lead here)
- **MSSPs / MDR providers** — they investigate for many clients and live or die on analyst-hours per incident. Reconstruction + grounding is a direct margin lever.
  - India: **TCS Cyber, Wipro (CyberShield/Alero), Infosys Cyber, HCLTech, Tech Mahindra, Paladion/Atos, Sequretek, Kratikal, WeSecureApp, Netrika.**
  - Global: **Arctic Wolf, Expel, Red Canary, eSentire, Rapid7 MDR, Secureworks, Trustwave, Sophos MDR.**
- **Mid-market SOCs drowning in alerts** — 500–5,000-employee firms with a small security team and an EDR/SIEM already generating noise. Fintech, SaaS, e-commerce, healthcare, gaming.
- **Regulated / data-residency-sensitive orgs** where "logs never leave the network" is a hard requirement:
  - **Banks, NBFCs, insurers** (India: HDFC, ICICI, Axis, SBI, Kotak; PSU banks) — RBI/SEBI localization pressure.
  - **Defense, government, PSUs, critical infrastructure** (power, telecom, ports) — CERT-In mandates, air-gapped preference.
  - **Healthcare & pharma** (HIPAA/DISHA), **payments/PCI** shops.

### Tier 2 — strong fit
- **Security product companies** that could OEM/embed the reconstruction + grounding layer: **Securonix, Exabeam, Sumo Logic, Devo, Panther, Hunters, Anvilogic** (SIEM/UEBA players wanting an evidence-grounded AI layer).
- **Cloud-native / DevSecOps teams** at fast-scaling startups (Series B+) building an in-house SOC for the first time.
- **Universities & research labs / CTF and SOC-training programs** — the simulator + reproducible benchmark are a teaching asset.

### Tier 3 — ecosystem & credibility
- **Cyber-focused VCs / accelerators** for funding + intros: (global) **YC, a16z (American Dynamism/security), Ballistic Ventures, Team8, Lightspeed;** (India) **Chiratae, Blume, 3one4, Together Fund, Z47/Matrix, Cornerstone VC.**
- **Vercel / Hugging Face / open-source security communities** for distribution and design partners.

### How to reach out (one-liner template)
> "I built Aegis — a self-hosted AI SOC analyst that reconstructs the full attack chain from scattered telemetry and grounds every AI claim in real evidence. On a reproducible benchmark it hits 100% detection at a 2% false-positive rate, with zero API-key cost. 15 minutes to show you a live investigation?"

**Warm-path advice:** MSSPs and mid-market SOC leads convert fastest — they feel the alert-fatigue and analyst-hour pain daily. Start with a design partner there, get one real-telemetry case study, then use it to open regulated-enterprise and investor conversations.
