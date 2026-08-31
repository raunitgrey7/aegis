---
title: Aegis API
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
short_description: AI-powered cybersecurity investigation & threat-intel API
---

# Aegis API — backend for the Aegis platform

This Space hosts the **Aegis** FastAPI backend: deterministic threat detection (rules + statistics +
threat intelligence), incident correlation, attack-graph reconstruction, MITRE ATT&CK mapping, risk
scoring, and evidence-grounded AI investigation.

- Interactive API docs: **`/docs`**
- Health: **`/api/healthz`**
- The Space seeds a realistic demo environment on startup (14 incidents, ~11k events).
- Demo accounts: `admin/admin`, `analyst/analyst`, `viewer/viewer`.

The web UI (Next.js) is deployed separately on Vercel and proxies to this API.

Source & docs: https://github.com/raunitgrey7/aegis
