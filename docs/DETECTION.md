# Aegis — Detection Engine Reference

Detection in Aegis is deterministic and statistical. Three subsystems run on every event and emit
`Detection` objects (`backend/aegis/schemas/detections.py`): the **rule engine**, the **statistical
anomaly engine**, and the **threat-intel matcher**. The correlation engine then clusters detections into
incidents. No LLM is involved anywhere in this document.

## 1. Rule engine and the YAML DSL

Rules live in `backend/aegis/rules/*.yaml` and are loaded by `backend/aegis/detection/rules.py`. Each
rule declares an `id`, `title`, `severity`, `score`, `techniques` (MITRE), `phase` (kill-chain), a
`confidence`, and a `kind`. There are three kinds:

### match — stateless single-event
Fires when one event satisfies a `where` condition.

```yaml
- id: EXEC-001
  title: Encoded PowerShell command
  kind: match
  severity: high
  score: 55
  techniques: [T1059.001, T1027.010]
  phase: execution
  group_by: [host]
  where:
    event_type: process_start
    process_name: { in: [powershell.exe, pwsh.exe, powershell_ise.exe] }
    command_line: { regex: "(?i)(^|\\s)-(e|ec|enc|encodedcommand)\\s+[A-Za-z0-9+/=]{20,}" }
  confidence: 0.93
```

### threshold — N events in a window (optionally followed by a trigger)
Fires when `count_gte` matching events occur within `window_seconds` for one `group_by` key. `distinct:
<field>` counts unique values instead of raw events. An optional `then:` condition turns it into
"N of X, then Y" — e.g. brute force *then* success:

```yaml
- id: AUTH-001
  title: Brute-force authentication followed by success
  kind: threshold
  group_by: [user]
  window_seconds: 180
  where: { event_type: authentication, action: login_failure }
  count_gte: 5
  then: { event_type: authentication, action: login_success }
```

`AUTH-002` uses `distinct: user` grouped by `src_ip` to catch password spraying (10 distinct accounts
failing from one IP).

### sequence — ordered multi-stage behaviour
Fires when every `step` matches, in order, inside `window_seconds` for one `group_by` key. This is how
behavioural chains that are individually benign but jointly malicious are caught:

```yaml
- id: BEHAV-002
  title: Encoded PowerShell → C2 → staged archive → exfiltration
  kind: sequence
  group_by: [host]
  window_seconds: 1800
  steps:
    - { event_type: process_start, process_name: { in: [powershell.exe, pwsh.exe] },
        command_line: { regex: "(?i)-(e|ec|enc|encodedcommand)\\s+[A-Za-z0-9+/=]{20,}" } }
    - { event_type: network_connection, dst_ip: { private: false } }
    - { event_type: file_create, file_path: { regex: "(?i)\\.(zip|7z|rar|tar\\.gz)$" } }
    - { event_type: network_connection, dst_ip: { private: false }, bytes_out: { gte: 10000000 } }
```

Each rule also has a `cooldown_seconds` (default 600) so a firing rule does not spam duplicate detections
for the same group.

### Condition operators

A condition is `field → matcher`. A bare scalar means case-insensitive equality; a mapping selects
operators (`backend/aegis/detection/conditions.py`):

| Operator | Meaning |
|----------|---------|
| `eq`, `neq` | (in)equality, case-insensitive for strings |
| `in`, `not_in` | membership in a list |
| `regex` | Python regex `search`, input capped at `MAX_REGEX_INPUT=4096` bytes (ReDoS guard) |
| `contains`, `startswith`, `endswith` | substring / prefix / suffix (accept a list) |
| `gte`, `lte`, `gt`, `lt` | numeric comparison |
| `exists: true/false` | field present and non-empty |
| `private: true/false` | IP is RFC1918/loopback/link-local (`is_private_ip`) |
| `entropy_gte: <x>` | Shannon entropy of the first label ≥ x |
| `len_gte: <n>` | string length ≥ n |
| `any_of: [ ... ]` | OR of sub-conditions |
| `not: { ... }` | negation of a sub-condition |

A top-level `where` ANDs all field matchers; `any_of` adds an OR group; `not` adds a negation. Regexes are
compiled once at load and evaluated against length-capped input.

### Rule packs (58 rules)

| Pack | File | Count | Example IDs |
|------|------|------:|-------------|
| Authentication & identity | `authentication.yaml` | 7 | AUTH-001…007 (brute force, spraying, impossible travel, honeytoken) |
| Execution / evasion / discovery / cred access | `execution.yaml` | 12 | EXEC-001…006, DEFEV-001…003, DISC-001, CRED-001/002 |
| Persistence & privilege escalation | `persistence_privilege.yaml` | 10 | PRIV-001…005, PERS-001…005 |
| Lateral movement | `lateral_movement.yaml` | 6 | LAT-001…006 (PsExec/WMI, admin-share, port scan, PtH) |
| Collection / C2 / exfil / files / DNS | `collection_exfiltration.yaml` | 16 | COLL-001…003, C2-001…003, EXFIL-001…003, FILE-001…004, DNS-001…003 |
| Behavioural chains | `behavioral_chains.yaml` | 7 | BEHAV-001…007 (Office→shell→net, discovery→dump→lateral, shadow-delete→encrypt) |

Rules are keyed to MITRE techniques; combined rule + anomaly technique coverage is exposed at
`GET /api/mitre/coverage` (69 of 80 catalogue techniques covered in the shipped catalogue).

## 2. Statistical anomaly engine

`backend/aegis/detection/anomaly.py`. Each detector learns a per-entity baseline online from benign
history and emits an explainable `Detection` — an analyst can always read *why*. Detectors and their
parameters:

| Detector | ID | Signal | Key parameters |
|----------|----|--------|----------------|
| Login-hour histogram | `ANOM-LOGIN-HOUR` | login in an hour the user essentially never uses | `min_history=12`, `rarity_threshold=0.03`, neighbour-hour smoothing |
| First-seen location | `ANOM-LOGIN-LOCATION` | first successful login from a new country / public IP | `min_history=5` |
| Egress volume | `ANOM-EGRESS-VOLUME` | outbound bytes far above host baseline | `min_history=20`, robust z ≥ `3.5` |
| Process rarity | `ANOM-RARE-PROCESS` | process never seen on host and rare org-wide | `min_host_history=40`, `org_rarity_max=2` |
| DNS entropy / burst | `ANOM-DNS-ENTROPY`, `ANOM-DNS-BURST` | high-entropy labels (DGA) or query storms | `entropy_threshold=3.9`, `label_len_threshold=40`, `burst=40/60s` |

**Robust z-score (egress).** Bytes are log-transformed (`x = ln(1+bytes_out)`); the baseline uses the
median and MAD:

```
z = 0.6745 · (x − median) / MAD        (fires when z ≥ 3.5)
```

Median/MAD are used instead of mean/σ so a handful of legitimately large transfers do not inflate the
baseline and blind the detector. Sanctioned corporate cloud destinations (OneDrive, SharePoint, Google
Workspace, approved backup) are excluded from egress alerting to suppress the obvious false positive.

**Shannon entropy (DNS).** `H = −Σ p·log2(p)` over the characters of the first DNS label; a long,
high-entropy subdomain is the DGA/tunnelling signal.

## 3. Threat-intelligence matching

`backend/aegis/threat_intel/`. Indicators (IP, domain, URL, hash, CIDR) are loaded from **public feeds**
cached on disk (abuse.ch Feodo Tracker, URLhaus, ThreatFox; Spamhaus DROP; a curated local set) by
`feeds.py`. `matcher.py` extracts IOCs from each event (`dst_ip`, `src_ip`, `domain`, `url`, `file_hash`,
and the host of a URL) and looks them up; domain lookups walk parent domains, IP lookups fall back to
CIDR containment. A hit emits a `THREAT_INTEL` detection whose score scales with the indicator's
confidence. No commercial API is ever called.

## 4. From detections to incidents

`backend/aegis/correlation/engine.py`. Detections that share an entity key (`user:`, `host:`, `session:`,
or a public `ip:`) within `correlation_window_seconds` (default 3600) are merged with union-find into one
cluster. A shared external IP alone is a *weak* key and will not merge two hosts' clusters unless they
also share a strong key.

### Incident admission policy

Not every detection deserves an incident. `build_incident` enforces:

1. **A lone statistical anomaly is never an incident** — `if len(dets) == 1 and kind == ANOMALY: return
   None`. Anomalies are signals that need corroboration.
2. **A single sub-floor medium/low rule hit stays an alert** — dropped unless it is HIGH/CRITICAL or there
   are ≥2 distinct rules, i.e. `risk < incident_min_score (40) and max_sev not in {HIGH, CRITICAL} and
   len(distinct_rules) < 2 → None`.
3. Anything else — a high/critical detection, or corroborated evidence above the risk floor — becomes an
   incident, with a phase-ordered kill chain, an attack graph extracted from the incident's own evidence,
   MITRE techniques, and a risk score.

### Risk scoring formula

`backend/aegis/scoring/risk.py`:

```
weighted[i] = detection.score · (0.6 + 0.4 · detection.confidence)
base        = 100 · (1 − Π(1 − weighted[i]/100))          # noisy-OR: independent evidence compounds
chain_bonus = 0.6 · Σ PHASE_WEIGHT[p]  over distinct phases (≥2), capped at 25
ti_bonus    = min(12, 6 · #threat_intel_hits)
asset_bonus = 8 if a critical host (DC-/DB-/FS-/API-/PRD-/SRV-/ERP-) else 0
            + 6 if a critical user (adm-/da-/administrator/svc-backup/svc-sql) else 0
breadth     = min(10, 3 · (#hosts − 1))
risk        = min(100, base + chain_bonus + ti_bonus + asset_bonus + breadth)
```

`PHASE_WEIGHT` rewards later, more damaging phases (`exfiltration`=9, `impact`=10, `lateral_movement`=7).
Severity buckets: `risk ≥ 85` critical, `≥ 65` high, `≥ 40` medium, `≥ 20` low, else info. Confidence
blends mean detection confidence with evidence-kind diversity and detection volume. Every term is returned
in `score_breakdown` and shown in the UI so the score is fully explainable.
