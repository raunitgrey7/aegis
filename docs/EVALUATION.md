# Aegis — Evaluation Methodology & Results

Aegis ships a reproducible benchmark. Every number in the README and pitch deck is produced by
`simulator/aegis_sim/evaluation.py` against synthetic-but-realistic telemetry, is deterministic for a
fixed seed, and **does not involve the LLM** — detection is deterministic, so the metrics measure the
deterministic engines only.

## Why synthetic

Real enterprise telemetry with labelled attacks is not shareable. A seeded simulator gives labelled
ground truth (which events belong to which attack, and the expected techniques/phases), reproducible runs,
and — critically — **hard negatives**: benign activity engineered to look like an attack, which is where
naive detectors fail.

## The synthetic enterprise (`aegis_sim/enterprise.py`)

- **60 users** across 8 departments (engineering, finance, hr, sales, legal, operations, marketing, it),
  each with a workstation (`WS-###`/`LT-###`), a home IP, and per-user login-hour behaviour.
- Roles: developers (run PowerShell/git/7-Zip legitimately), IT admins (`adm-*`, run admin tooling and
  RDP to servers), and ~15% travellers with 2 approved foreign countries.
- **10 servers**: `DC-01/02` (domain controllers), `FS-01` (file), `DB-01`, `API-01`, `WEB-01`,
  `VPN-01`, `PRX-01`, `DNS-01`, `BKP-01`. Home country `IN`; travel countries `US/GB/SG/DE`.
- **20 benign SaaS destinations** (Microsoft 365, Google, GitHub, Slack, Zoom, Salesforce, npm, PyPI…)
  with real-looking IPs.

## Benign generator and hard negatives (`aegis_sim/benign.py`)

The generator produces a normal working day and deliberately includes activity that resembles attacks:

- Users **fat-finger passwords** (a few failures then success) — must not fire brute-force.
- **Travellers log in from abroad** — must not fire "impossible/foreign login" on its own.
- **Developers run PowerShell** build scripts with `-ExecutionPolicy Bypass`, and **7-Zip** — must not
  fire execution/collection rules.
- **IT admins** create new-hire accounts (`net user … /add`), run `mmc`/`gpupdate`, RDP to servers.
- **Large OneDrive / backup uploads** (hundreds of MB to sanctioned cloud) — must not fire exfiltration.
- Office documents opened from Outlook attachments.

These are the benign "lookalike" scenarios (`_benign_lookalike`) used to measure false positives.

## Attack scenarios A–H (`aegis_sim/scenarios.py`)

Each scenario emits synthetic telemetry describing an attack (it never *performs* one) plus ground truth.

| ID | Scenario | Expected techniques | Expected phases | Severity |
|----|----------|---------------------|-----------------|----------|
| A | Brute-force authentication | T1110.001, T1078 | credential_access, initial_access | high |
| B | Suspicious off-hours login | T1078, T1133, T1059.001 | initial_access, execution | high |
| C | Malicious document execution | T1566.001, T1059.001, T1027.010, T1071.001 | execution, command_and_control | critical |
| D | Privilege escalation & backdoor account | T1548.002, T1068, T1136.001, T1098 | privilege_escalation, persistence | critical |
| E | Hands-on-keyboard lateral movement | T1087.002, T1003.001, T1021.002, T1047 | discovery, credential_access, lateral_movement | critical |
| F | Ransomware detonation | T1490, T1562.001, T1486 | defense_evasion, impact | critical |
| G | DNS tunnelling / exfiltration channel | T1071.004, T1568.002, T1048.003 | command_and_control | medium |
| H | Data collection & exfiltration | T1039, T1560.001, T1048, T1567.002 | collection, exfiltration | high |

## Metrics (definitions)

Given a run of N attack and N benign scenarios after a benign training baseline:

- **Detection rate (recall)** — fraction of attack scenarios that produced an incident overlapping the
  scenario's events. TP / (TP + FN).
- **False positive rate** — fraction of benign scenarios that raised a high/critical (or above-floor)
  incident. FP / (FP + TN).
- **Precision** = TP / (TP + FP); **F1** = harmonic mean of precision and recall.
- **Attack-chain reconstruction** — mean fraction of the scenario's expected kill-chain phases recovered
  in the incident.
- **MITRE technique precision / recall** — matched techniques vs. the incident's technique set and vs.
  ground truth, respectively.
- **IOC correlation accuracy** — fraction of expected threat-intel indicators that were matched.
- **Evidence coverage** — mean fraction of the scenario's events attached to the incident.
- **Latency** — wall-clock to ingest + correlate a scenario batch (mean and p95); **throughput** in
  events/second.

Determinism: the enterprise, benign traffic, and attacks are all driven by a seeded `random.Random`, and
each run is isolated on its own simulated day so correlation windows never collide across runs.

## Latest results (seed 1337, 100 attack + 100 benign)

Source of truth: `evaluation/results/results.md` (regenerate with the command below).

| Metric | Result |
|--------|-------:|
| Detection rate (recall) | **100.0%** |
| False positive rate | **2.0%** |
| Precision | 98.0% |
| F1 | 99.0% |
| Attack-chain reconstruction | 89.5% |
| MITRE technique recall | 86.7% |
| MITRE technique precision | 62.2% |
| IOC correlation accuracy | 82.9% |
| Evidence coverage | 73.4% |
| Mean / p95 latency | 767 ms / 2269 ms |

Confusion matrix — TP 100, FP 2, TN 98, FN 0. Baseline 23,047 benign events; 30,496 events total.

Per-scenario detection was 100% across A–H. Chain reconstruction is lower for E (lateral movement, 66.7%)
because per-host cooldowns cite one representative remote-exec event rather than all four, and technique
precision (62%) is intentionally conservative — Aegis reports every technique its rules matched, which can
exceed the minimal ground-truth set. These are honest, explainable gaps, not tuning artefacts.

## Reproduce

```bash
python -m aegis_sim.evaluation --attacks 100 --benign 100 --seed 1337 --out evaluation/results
```

Writes `results.json`, `results.md`, and `example_incidents.json` (one fully-worked incident per scenario,
used to seed the UI and docs).
