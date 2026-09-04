"""Audit harness for REAL external attack telemetry (Mordor / OTRF ATT&CK-Evals JSON).

Runs Aegis over datasets the author did not write (e.g. the MITRE ATT&CK Evals APT29 emulation) and
produces an honest audit:

* schema coverage  - how many raw Windows/Sysmon EventIDs the normalizer actually maps vs. drops
* detection output - rules fired, incidents formed, ATT&CK techniques surfaced
* the gap          - EventIDs present in the data but unmapped, and expected APT techniques not detected

This is deliberately NOT the synthetic benchmark: nobody tuned these logs to the rules, so the misses
are real and are the point. Output feeds ``docs/APT29_AUDIT.md``.
"""

from __future__ import annotations

import argparse
import collections
import json
import time
import zipfile
from pathlib import Path

from aegis.config import get_settings
from aegis.ingestion.normalizer import normalize
from aegis.pipeline import Platform
from aegis.schemas.events import EventType

# Publicly documented ATT&CK techniques exercised by the Evals APT29 emulation (day1+day2).
APT29_GROUND_TRUTH = {
    "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell", "T1027": "Obfuscated Files",
    "T1204.002": "Malicious File", "T1055": "Process Injection", "T1003.001": "LSASS Memory",
    "T1003.003": "NTDS", "T1053.005": "Scheduled Task", "T1547.001": "Registry Run Key",
    "T1543.003": "Windows Service", "T1021.002": "SMB/Admin Shares", "T1021.001": "RDP",
    "T1560.001": "Archive via Utility", "T1005": "Data from Local System", "T1041": "Exfil over C2",
    "T1071.001": "Web Protocols", "T1070.001": "Clear Event Logs", "T1018": "Remote System Discovery",
    "T1082": "System Info Discovery", "T1083": "File and Directory Discovery", "T1057": "Process Discovery",
    "T1087.002": "Domain Account Discovery", "T1552.001": "Credentials In Files", "T1136.001": "Create Account",
    "T1078": "Valid Accounts", "T1048": "Exfil Alternative Protocol", "T1074.001": "Local Data Staging",
    "T1113": "Screen Capture", "T1105": "Ingress Tool Transfer", "T1140": "Deobfuscate",
}


def iter_records(path: Path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith((".json", ".jsonl")):
                    with z.open(name) as fh:
                        for raw in fh:
                            raw = raw.strip()
                            if raw:
                                try:
                                    yield json.loads(raw)
                                except Exception:
                                    continue
    else:
        with path.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue


def audit(path: Path, label: str, cap: int | None = None) -> dict:
    platform = Platform(enable_anomaly=True, max_events=1_500_000)
    seen_eid: collections.Counter = collections.Counter()
    dropped_eid: collections.Counter = collections.Counter()
    type_dist: collections.Counter = collections.Counter()
    n = 0
    t0 = time.time()
    batch = []
    for rec in iter_records(path):
        eid = rec.get("EventID")
        seen_eid[eid] += 1
        try:
            e = normalize(rec, collector="windows")
        except Exception:
            dropped_eid[eid] += 1
            continue
        type_dist[e.event_type.value] += 1
        if e.event_type == EventType.SYSTEM_LOG:
            dropped_eid[eid] += 1  # normalized but to an inert type -> effectively invisible to rules
        batch.append(e)
        n += 1
        if len(batch) >= 20000:
            platform.ingest_many(batch, correlate=False)
            batch = []
        if cap and n >= cap:
            break
    if batch:
        platform.ingest_many(batch, correlate=False)
    platform.correlate(force=True)
    elapsed = round(time.time() - t0, 1)

    incidents = list(platform.incidents.values())
    techniques_found = collections.Counter()
    for i in incidents:
        for tct in i.techniques:
            techniques_found[tct] += 1
    rules_fired = collections.Counter(d.rule_id for d in platform.detections)

    gt = set(APT29_GROUND_TRUTH)
    found = set(techniques_found)
    detected_gt = sorted(gt & found)
    missed_gt = sorted(gt - found)

    mapped_events = sum(v for k, v in type_dist.items() if k != "system_log")
    coverage = round(mapped_events / n * 100, 1) if n else 0.0

    return {
        "label": label,
        "events_total": n,
        "elapsed_s": elapsed,
        "schema_coverage_pct": coverage,
        "mapped_events": mapped_events,
        "aegis_type_distribution": dict(type_dist),
        "top_eventids_seen": seen_eid.most_common(15),
        "top_eventids_dropped": dropped_eid.most_common(15),
        "detections": platform.stats.detections,
        "incidents": len(incidents),
        "rules_fired": dict(rules_fired.most_common(25)),
        "techniques_found": dict(techniques_found.most_common()),
        "apt29_detected": detected_gt,
        "apt29_missed": missed_gt,
        "apt29_recall_pct": round(len(detected_gt) / len(gt) * 100, 1),
        "top_incidents": [
            {"id": i.incident_id, "title": i.title, "severity": i.severity.value, "risk": i.risk_score,
             "phases": i.present_phases, "techniques": i.techniques[:10], "hosts": i.affected_hosts}
            for i in sorted(incidents, key=lambda x: -x.risk_score)[:8]
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", type=Path, required=True)
    ap.add_argument("--label", default="dataset")
    ap.add_argument("--cap", type=int, default=None)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    res = audit(args.file, args.label, args.cap)
    print(json.dumps({k: v for k, v in res.items() if k not in ("aegis_type_distribution",)}, indent=2, default=str)[:2500])
    print("\nSchema coverage: {}%  |  APT29 technique recall: {}%  ({}/{})".format(
        res["schema_coverage_pct"], res["apt29_recall_pct"], len(res["apt29_detected"]), len(APT29_GROUND_TRUTH)))
    print("Detected:", res["apt29_detected"])
    print("MISSED  :", res["apt29_missed"])
    out = args.out or (get_settings().rules_dir.parent.parent.parent / "evaluation" / "results" / f"apt_audit_{args.label}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=str))
    print("written", out)


if __name__ == "__main__":
    main()
