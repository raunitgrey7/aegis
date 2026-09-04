"""External-telemetry evaluation harness.

The synthetic benchmark (``evaluation.py``) is a regression harness written by the same author as the
rules. This module is the honest counterweight: it runs Aegis over telemetry in the **real Windows
log schema** used by the public OTRF Security-Datasets / Mordor project (Winlogbeat / Sysmon JSON),
i.e. records the author did not shape to match the detectors.

The repository ships a *small* OTRF-schema sample so the path is exercised offline. That sample proves
**format compatibility**, not detection efficacy. The real test is pointing this at the full public
datasets:

    # download real attack telemetry (author did not write it), then:
    python -m aegis_sim.external --dir path/to/OTRF/Security-Datasets/datasets

``load_jsonl`` accepts the OTRF/Winlogbeat shapes (flat ``@timestamp`` / ``Hostname`` / ``EventID`` /
``EventData``) that ``aegis.ingestion.normalizer`` now understands. Nested ``.gz`` and ``.zip`` OTRF
archives are handled transparently.
"""

from __future__ import annotations

import argparse
import gzip
import json
import zipfile
from collections import Counter
from pathlib import Path

from aegis.config import get_settings
from aegis.ingestion.normalizer import normalize
from aegis.pipeline import Platform

SAMPLE = get_settings().__class__().rules_dir.parent / "data" / "external" / "sample_winlogbeat.jsonl"


def _iter_records(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith((".json", ".jsonl")):
                    for line in z.read(name).decode("utf-8", "ignore").splitlines():
                        line = line.strip()
                        if line:
                            yield json.loads(line)
    else:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)


def load_jsonl(path: Path) -> list:
    events = []
    for rec in _iter_records(path):
        # OTRF wraps event fields under EventData or at top level; normalize() autodetects windows shape
        try:
            events.append(normalize(rec, collector="windows"))
        except Exception:
            continue
    return events


def run_external(paths: list[Path], verbose: bool = True) -> dict:
    platform = Platform(enable_anomaly=True)
    total = 0
    files = 0
    for p in paths:
        evs = load_jsonl(p)
        if not evs:
            continue
        files += 1
        total += len(evs)
        platform.ingest_many(evs, correlate=False)
    platform.correlate(force=True)

    incidents = list(platform.incidents.values())
    techniques: Counter = Counter()
    for i in incidents:
        for t in i.techniques:
            techniques[t] += 1
    rules_fired = Counter(d.rule_id for d in platform.detections)

    result = {
        "files": files,
        "events_ingested": platform.stats.events_ingested,
        "detections": platform.stats.detections,
        "incidents": len(incidents),
        "top_incidents": [
            {"id": i.incident_id, "title": i.title, "severity": i.severity.value,
             "risk": i.risk_score, "phases": i.present_phases, "techniques": i.techniques}
            for i in sorted(incidents, key=lambda x: -x.risk_score)[:10]
        ],
        "techniques_observed": dict(techniques.most_common()),
        "rules_fired": dict(rules_fired.most_common(15)),
    }
    if verbose:
        print(f"Ingested {result['events_ingested']} external-schema events from {files} file(s).")
        print(f"Detections: {result['detections']}  Incidents: {result['incidents']}")
        for i in result["top_incidents"]:
            print(f"  {i['id']} [{i['severity']}] risk {i['risk']} — {i['title']}")
            print(f"     phases: {', '.join(i['phases'])}  techniques: {', '.join(i['techniques'][:8])}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Aegis over external (OTRF/Winlogbeat-schema) telemetry")
    ap.add_argument("--dir", type=Path, default=None, help="directory of OTRF .json/.jsonl/.gz/.zip files")
    ap.add_argument("--file", type=Path, default=None)
    args = ap.parse_args()
    if args.file:
        paths = [args.file]
    elif args.dir:
        paths = [p for p in args.dir.rglob("*") if p.suffix in (".json", ".jsonl", ".gz", ".zip")]
    else:
        print(f"No --dir/--file given; running the bundled OTRF-schema sample: {SAMPLE.name}")
        paths = [SAMPLE]
    run_external(paths)


if __name__ == "__main__":
    main()
