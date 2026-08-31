# LinkedIn Post — Aegis launch

> Hero image to attach: `docs/screenshots/01-overview.jpg` (the Security Overview dashboard).
> Optionally add `02-attack-graph.jpg` and `04-copilot.jpg` as a carousel.
> Replace `<LIVE_URL>` with the deployed Vercel link once it's live.

---

🛡️ I built **Aegis** — an AI security analyst that reconstructs the *whole* attack, not just another pile of alerts.

Security teams aren't short on alerts. They're drowning in them. A real intrusion is ~6 events — a login, a PowerShell spawn, an outbound connection, an archive, an upload — scattered across four different tools and buried in millions of benign ones. A normal log viewer shows six shrugs. The attack is invisible unless something *connects* them.

The industry's answer has been "bolt an LLM onto your logs." But that just produces confident guesses you can't put in an incident report — and your logs contain attacker-controlled text, so the LLM itself becomes an attack surface.

Aegis takes a different stance: **AI is not the detector.**

🔹 Detection is done by deterministic engines — rules, statistics, and threat intelligence — so it's explainable and reproducible.
🔹 Scattered detections get correlated into a single incident.
🔹 The attack is reconstructed as a graph you can click through to the raw evidence.
🔹 Only *then* does a local LLM explain it — and every sentence is validated against real event IDs, so it physically can't hallucinate. You get a green "Evidence-grounded ✓ — 3/3 citations verified, 0 fabricated" badge on every report.

On a reproducible benchmark (100 simulated attacks + 100 benign look-alikes):
✅ 100% detection rate
✅ 2% false-positive rate
✅ 99% F1
✅ 89.5% attack-chain reconstruction
✅ 69/80 MITRE ATT&CK techniques covered
✅ sub-millisecond detection per event
✅ ₹0 API-key cost — it runs local models, self-hosted, so telemetry never leaves your network

The whole thing is real and running: a FastAPI backend with 58 detections, a security knowledge graph + attack-graph reconstruction, multi-agent AI investigation with a prompt-injection defense, and a Next.js SOC console — deployed with Hugging Face + Vercel, backed by 57 tests and CI.

This is the third in a series of deep AI products across very different engineering domains (a personal-AI OS, an SRE incident brain, and now security) — the thesis being: put AI where it's genuinely useful (explanation), on top of a deterministic, trustworthy core.

🔗 Live demo: <LIVE_URL>  (log in as analyst / analyst)
💻 Code + docs: https://github.com/raunitgrey7/aegis

Would love feedback from anyone in the SOC / detection-engineering / threat-intel world — what would make this useful on *your* real telemetry?

#CyberSecurity #AI #ThreatIntelligence #SIEM #SOC #MITREATTACK #IncidentResponse #ThreatDetection #MachineLearning #InfoSec #SecurityEngineering #DFIR #BlueTeam #DetectionEngineering #ArtificialIntelligence #LLM #OpenSource #Python #NextJS #CyberDefense #AIsecurITY #SecurityOperations #DataSecurity #CloudSecurity #TechInnovation

---

## Shorter variant (if you want a punchier post)

🛡️ Most security tools give you a pile of alerts. **Aegis** gives you the whole attack — reconstructed as a graph, with every AI conclusion backed by real evidence.

The principle: **AI is not the detector.** Deterministic engines (rules + statistics + threat intel) decide what's malicious; the local LLM only *explains* — and every claim is validated against real event IDs, so it can't hallucinate.

Reproducible benchmark: **100% detection · 2% false positives · 99% F1 · 89.5% attack-chain reconstruction** — self-hosted, ₹0 API cost.

🔗 Live: <LIVE_URL>  ·  💻 github.com/raunitgrey7/aegis

#CyberSecurity #AI #ThreatDetection #SOC #MITREATTACK #IncidentResponse #DetectionEngineering #InfoSec #LLM #BlueTeam
