# Aegis API Contract (for the web UI)

Base URL: `http://localhost:8000/api` (dev). Frontend reads `process.env.NEXT_PUBLIC_API_URL` (default `http://localhost:8000/api`).

Auth: `POST /auth/login {username,password}` → `{access_token, role, expires_in_minutes}`. Send `Authorization: Bearer <token>` on every other call. Demo accounts: `admin/admin` (admin), `analyst/analyst` (analyst), `viewer/viewer` (viewer).

## Endpoints

| Method | Path | Role | Returns |
|--------|------|------|---------|
| POST | `/auth/login` | — | `{access_token, token_type, role, expires_in_minutes}` |
| GET | `/auth/me` | any | `{username, role, tenant}` |
| GET | `/overview` | viewer | dashboard payload (below) |
| GET | `/incidents?severity=&status=&limit=` | viewer | `{count, incidents:[summary]}` |
| GET | `/incidents/{id}` | viewer | full incident + `events` + `critical_path` |
| GET | `/incidents/{id}/graph` | viewer | `{graph:{nodes,edges}, critical_path:[id]}` |
| POST | `/incidents/{id}/status {status}` | analyst | `{incident_id, status}` |
| POST | `/incidents/{id}/investigate` | analyst | investigation report (below) |
| POST | `/incidents/{id}/copilot {question}` | analyst | `{question, answer, evidence:[{event_id,time,summary}], llm_used, grounding}` |
| GET | `/graph/entity?q=&depth=` | viewer | `{center, entity, nodes:[{id,kind,label,risk,...}], edges:[{source,target,relation,...}]}` |
| GET | `/graph/search?q=` | viewer | `{results:[{id,kind,label,risk}]}` |
| GET | `/graph/threat-map` | viewer | `{nodes:[{type,value,incident,risk,known_malicious,threat,hosts}]}` |
| GET | `/threat-intel/stats` | viewer | `{ips,domains,hashes,urls,cidrs,feeds}` |
| GET | `/rules` | viewer | `{count, rules:[{id,title,kind,severity,score,techniques,phase,description,fired}]}` |
| GET | `/mitre/coverage` | viewer | `{techniques_total, techniques_covered, tactics:{<tactic>:{label,total,covered,techniques}}}` |
| GET | `/mitre/observed` | viewer | `{coverage:[{tactic,label,count}], techniques:[id]}` |
| POST | `/simulate {scenario:"A".."H"}` | admin | `{scenario,name,events,detections,new_incidents,expected_techniques}` |
| GET | `/simulate/scenarios` | viewer | `{scenarios:[{id,function}]}` |
| GET | `/audit?n=` | admin | `{verification:{valid,entries,head}, entries:[...]}` |
| GET | `/healthz` | — | `{status, events, incidents, llm}` |

## /overview payload

```json
{
  "threat_level": "CRITICAL|HIGH|ELEVATED|LOW",
  "active_incidents": 14, "critical": 8, "high": 3,
  "suspicious_users": 9, "affected_hosts": 16,
  "events_ingested": 11244, "events_deduplicated": 3, "detections": 210,
  "graph": {"nodes": 3858, "edges": 9000, "by_kind": {"host": 60, "user": 61, "ip": 900, ...}},
  "threat_intel": {"ips": 15, "domains": 12, "hashes": 4, "urls": 2, "cidrs": 1707},
  "detector": {"events_processed": 11244, "avg_latency_us": 240.0, "rules_loaded": 58, ...},
  "top_incidents": [{"incident_id","title","severity","risk","hosts","users","phases","status","created_at"}],
  "severity_distribution": {"critical":8,"high":3,"medium":2,"low":1,"info":0},
  "phase_distribution": [{"phase","label","count"}],
  "tactic_coverage": [{"tactic","label","count"}]
}
```

## Incident (GET /incidents/{id})

```json
{
  "incident_id":"SEC-0007","title":"...","status":"open","severity":"critical",
  "risk_score":100.0,"confidence":0.97,
  "created_at":"...","first_event_at":"...","last_event_at":"...",
  "affected_users":["mallory"],"affected_hosts":["LT-011"],
  "external_ips":["45.155.205.233"],"domains":["cdn.statistics-collect.com"],
  "techniques":["T1059.001","T1071.001",...],
  "phases":[{"phase":"execution","label":"Execution","present":true,"techniques":[...],"detection_ids":[...],"first_seen":"..."}],
  "detections":[{"detection_id","kind","rule_id","title","description","severity","score","confidence","techniques","phase","timestamp","entities","evidence_event_ids","details"}],
  "event_ids":["evt_..."],
  "graph":{"nodes":[{"id","type","label","layer","risk","attributes","evidence_event_ids"}],
           "edges":[{"id","source","target","relation","timestamp","phase","techniques","evidence_event_ids"}]},
  "score_breakdown":{"detections_noisy_or":100.0,"kill_chain_bonus":20.4,"threat_intel_bonus":12.0,"asset_criticality_bonus":0,"breadth_bonus":0,"raw_total":132.4,"capped":100.0},
  "events":[{ full SecurityEvent objects }],
  "critical_path":["user:mallory","host:LT-011",...]
}
```

Graph node `type` ∈ {user, host, process, file, ip, domain, ioc, service}; `layer` 0..5 (identity→host→process→file→ip/domain→ioc). Edge `relation` ∈ {logged_into, failed_login, spawned, executed, ran, connected_to, resolved, resolves_to, wrote, modified, read, escalated_on, known_as, ...}. Use `layer` for left→right columns and `phase` to colour edges.

## Investigation report (POST /incidents/{id}/investigate)

```json
{
  "incident_id","title","severity","risk_score","confidence","generated_at",
  "llm_used":false,"model":null,
  "summary":"...","attack_narrative":"multi-paragraph text",
  "affected_users":[],"affected_hosts":[],"external_ips":[],"phases_present":[],
  "techniques":[{"id","name","tactic","url"}],
  "timeline":[{"time","event_id","summary","phase","techniques"}],
  "agent_findings":[{"agent":"identity|process|network|file","headline","detail","confidence","evidence_event_ids"}],
  "recommended_actions":["..."],
  "injection_warnings":[{"event_id","field","value"}],
  "grounding":{"evidence_total","evidence_cited","fabricated_ids","coverage","fidelity","grounded"},
  "latency_ms": 12.3
}
```

## SecurityEvent (inside incident.events)

`event_id, timestamp, source, event_type, action, outcome, host, user, session_id, process_name, process_id, parent_process_name, command_line, file_path, file_hash, file_size, src_ip, src_port, dst_ip, dst_port, protocol, domain, url, bytes_in, bytes_out, geo_country, privilege, target_user, service_name, message, severity_hint, tags[]`

## Kill-chain phase order & colours (suggested)

reconnaissance, initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, command_and_control, exfiltration, impact.
Severity colours: critical `#ef4444`, high `#f97316`, medium `#eab308`, low `#3b82f6`, info `#64748b`.
