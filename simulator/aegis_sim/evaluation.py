"""Evaluation harness.

Builds a benign baseline (so anomaly detectors are trained), then runs N attack scenarios and N benign
"lookalike" scenarios, and measures the metrics claimed in the README:

  * Detection Rate (recall on attacks)
  * False Positive Rate (benign scenarios that raised an incident)
  * Attack-chain reconstruction accuracy (fraction of expected kill-chain phases recovered)
  * MITRE technique classification (precision/recall/F1 vs ground truth)
  * IOC correlation accuracy
  * Evidence coverage (fraction of scenario events attached to the incident)
  * Investigation / detection latency

Everything is deterministic given ``seed``. Output is written as JSON + Markdown so the pitch deck and
README consume *real* numbers.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegis.pipeline import Platform
from aegis.schemas.events import SecurityEvent

from aegis_sim.benign import BenignGenerator
from aegis_sim.enterprise import Enterprise
from aegis_sim.scenarios import SCENARIOS, ScenarioResult, generate_scenario


@dataclass
class ScenarioEval:
    scenario_id: str
    name: str
    detected: bool
    incident_id: str | None
    risk: float
    severity: str
    expected_phases: list[str]
    recovered_phases: list[str]
    phase_recall: float
    expected_techniques: list[str]
    matched_techniques: list[str]
    technique_recall: float
    technique_precision: float
    ioc_expected: int
    ioc_matched: int
    evidence_expected: int
    evidence_covered: int
    evidence_coverage: float
    latency_ms: float


@dataclass
class EvalReport:
    seed: int
    n_attack: int
    n_benign: int
    baseline_events: int
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    phase_reconstruction: float = 0.0
    technique_precision: float = 0.0
    technique_recall: float = 0.0
    technique_f1: float = 0.0
    ioc_accuracy: float = 0.0
    evidence_coverage: float = 0.0
    mean_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    events_per_second: float = 0.0
    false_incidents_per_million_events: float = 0.0
    projected_false_incidents_per_day: float = 0.0
    benign_events_processed: int = 0
    by_scenario: dict[str, dict] = field(default_factory=dict)
    per_run: list[dict] = field(default_factory=list)
    confusion: dict[str, int] = field(default_factory=dict)
    generated_at: str = ""
    total_events: int = 0


def _pct(x: float) -> float:
    return round(100.0 * x, 1)


def _benign_lookalike(sid: str, ent: Enterprise, gen: BenignGenerator, rng: random.Random, day: datetime) -> list[SecurityEvent]:
    """Hard-negative traffic resembling an attack type but legitimate."""
    u = ent.random_user(rng, admin=(sid in ("D", "E")))
    t = day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59), tzinfo=UTC)
    evs: list[SecurityEvent] = []
    if sid == "A":  # user fat-fingers password a few times then succeeds
        for _ in range(rng.randint(2, 4)):
            evs.append(gen.login(u, t, ok=False))
            t += timedelta(seconds=rng.randint(5, 20))
        evs.append(gen.login(u, t, ok=True))
    elif sid == "B":  # traveller logs in from abroad, legitimately
        c = rng.choice(u.travel_countries or ["US"])
        ip = f"{rng.randint(20, 60)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        evs.append(gen.login(u, t, ok=True, country=c, src_ip=ip, privilege="rdp"))
        evs.append(gen.process(u, t + timedelta(seconds=30), "outlook.exe", "explorer.exe", r"C:\...\OUTLOOK.EXE"))
    elif sid == "C":  # developer runs a real PowerShell build script
        evs.append(gen.process(u, t, "powershell.exe", "code.exe", r"C:\...\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File .\\build.ps1"))
        d, ip, port = ("github.com", "140.82.112.4", 443)
        evs.append(gen.conn(u, t + timedelta(seconds=5), ip, port, "git.exe", bytes_out=3_000_000, domain=d))
    elif sid == "D":  # IT admin legitimately creates a new-hire account
        evs.append(gen.process(u, t, "mmc.exe", "explorer.exe", r"C:\Windows\System32\mmc.exe", "mmc.exe dsa.msc"))
        evs.append(gen.process(u, t + timedelta(seconds=30), "net.exe", "cmd.exe", r"C:\Windows\System32\net.exe", "net user newhire05 /add /domain"))
    elif sid == "E":  # admin RDPs to a couple of servers for maintenance
        for srv in rng.sample(ent.servers, k=2):
            evs.append(gen.login(u, t, host=srv.name, privilege="rdp"))
            t += timedelta(minutes=rng.randint(1, 4))
    elif sid == "F":  # backup software touches many files (not encryption)
        for i in range(rng.randint(80, 130)):
            evs.append(gen.file(u, t + timedelta(seconds=i * 0.3), SecurityEvent.model_fields and __import__("aegis.schemas.events", fromlist=["EventType"]).EventType.FILE_READ, f"C:\\Users\\{u.name}\\Documents\\report_{i}.docx", "veeam.agent.exe", size=rng.randint(10_000, 400_000)))
    elif sid == "G":  # CDN with many subdomains (legit high-volume DNS)
        for _ in range(rng.randint(30, 45)):
            evs.append(gen.dns(u, t, f"seg-{rng.randint(1, 9999)}.cdn.jsdelivr.net", "104.16.18.35"))
            t += timedelta(seconds=rng.uniform(0.5, 2))
    elif sid == "H":  # legit large upload to OneDrive / backup
        evs.append(gen.conn(u, t, "13.107.136.9", 443, "onedrive.exe", bytes_out=rng.randint(200_000_000, 500_000_000), domain="onedrive.live.com"))
    return evs


def run_evaluation(
    n_attack: int = 100,
    n_benign: int = 100,
    seed: int = 1337,
    baseline_days: int = 3,
    out_dir: Path | None = None,
    verbose: bool = False,
) -> EvalReport:
    rng = random.Random(seed)
    ent = Enterprise(seed=seed, n_users=60)
    platform = Platform(enable_anomaly=True)
    gen = BenignGenerator(ent, rng)

    # --- 1. baseline: train anomaly detectors on quiet days -------------------------------------
    base_start = datetime(2026, 8, 1, tzinfo=UTC)
    baseline_events = 0
    for d in range(baseline_days):
        day = base_start + timedelta(days=d)
        evs = gen.day(day, density=0.7)
        platform.ingest_many(evs, correlate=False)
        baseline_events += len(evs)
    platform.correlate(force=True)
    _ = len(platform.incidents)  # baseline sanity

    scenario_ids = list(SCENARIOS.keys())
    evals: list[ScenarioEval] = []
    per_run: list[dict] = []
    latencies: list[float] = []
    tp = fp = tn = fn = 0
    total_events = baseline_events

    # each run gets its own isolated day so 1-hour correlation windows never collide across runs
    run_day = base_start + timedelta(days=baseline_days)

    # --- 2. attack runs -------------------------------------------------------------------------
    for i in range(n_attack):
        sid = scenario_ids[i % len(scenario_ids)]
        run_day += timedelta(days=1)
        t = run_day + timedelta(hours=rng.randint(1, 20), minutes=rng.randint(0, 59))
        sc = generate_scenario(sid, ent, rng, t)
        # a little concurrent benign noise around the attack window so it isn't in a vacuum
        noise = gen.day(run_day, density=0.05, window=(t - timedelta(minutes=20), t + timedelta(minutes=40)),
                        users=rng.sample(ent.users, k=8))
        before = set(platform.incidents.keys())
        t0 = time.perf_counter()
        platform.ingest_many(sc.events + noise, correlate=True)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt)
        total_events += len(sc.events) + len(noise)
        ev = _score_scenario(platform, sc, before, dt)
        evals.append(ev)
        per_run.append({"type": "attack", "scenario": sid, "detected": ev.detected, "risk": ev.risk})
        if ev.detected:
            tp += 1
        else:
            fn += 1
            if verbose:
                print(f"  MISS attack {sid} run {i}: risk={ev.risk}")

    # --- 3. benign runs -------------------------------------------------------------------------
    for i in range(n_benign):
        sid = scenario_ids[i % len(scenario_ids)]
        run_day += timedelta(days=1)
        t = run_day + timedelta(hours=rng.randint(1, 20), minutes=rng.randint(0, 59))
        evs = _benign_lookalike(sid, ent, gen, rng, t)
        evs += gen.day(run_day, density=0.05, window=(t - timedelta(minutes=15), t + timedelta(minutes=30)),
                       users=rng.sample(ent.users, k=6))
        before = set(platform.incidents.keys())
        t0 = time.perf_counter()
        platform.ingest_many(evs, correlate=True)
        dt = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt)
        total_events += len(evs)
        raised = _new_high_incident(platform, before)
        per_run.append({"type": "benign", "scenario": sid, "detected": raised})
        if raised:
            fp += 1
            if verbose:
                print(f"  FP benign {sid} run {i}")
        else:
            tn += 1

    # --- 4. aggregate ---------------------------------------------------------------------------
    report = _aggregate(evals, seed, n_attack, n_benign, baseline_events, latencies, tp, fp, tn, fn, total_events)
    report.by_scenario = _by_scenario(evals)

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "results.json").write_text(json.dumps({**asdict(report), "per_run": per_run}, indent=2))
        (out_dir / "results.md").write_text(render_markdown(report))
        _write_scenario_examples(platform, ent, rng, out_dir)
    report.per_run = per_run
    return report


def _score_scenario(platform: Platform, sc: ScenarioResult, before: set[str], latency_ms: float) -> ScenarioEval:
    from aegis.threat_intel.matcher import ThreatIntelMatcher

    sc_ev_ids = {e.event_id for e in sc.events}
    # find the incident that best covers this scenario's evidence
    best = None
    best_overlap = 0
    for inc in platform.incidents.values():
        overlap = len(set(inc.event_ids) & sc_ev_ids)
        if overlap > best_overlap:
            best, best_overlap = inc, overlap
    detected = best is not None and best_overlap > 0 and (best.incident_id in before or best.incident_id not in before or True)
    detected = best is not None and best_overlap > 0

    recovered = best.present_phases if best else []
    phase_recall = len(set(sc.expected_phases) & set(recovered)) / len(sc.expected_phases) if sc.expected_phases else 0.0
    matched_t = sorted(set(sc.expected_techniques) & set(best.techniques)) if best else []
    t_recall = len(matched_t) / len(sc.expected_techniques) if sc.expected_techniques else 0.0
    t_prec = len(set(sc.expected_techniques) & set(best.techniques)) / len(best.techniques) if best and best.techniques else 0.0

    ti = ThreatIntelMatcher(platform.ti_store)
    ioc_expected = sum(1 for e in sc.events for _ in ti.extract(e) if _ioc_hit(platform, e))
    ioc_matched = 0
    if best:
        for d in best.detections:
            if d.kind.value == "threat_intel":
                ioc_matched += 1
    evidence_covered = best_overlap
    evidence_coverage = best_overlap / len(sc_ev_ids) if sc_ev_ids else 0.0

    return ScenarioEval(
        scenario_id=sc.scenario_id, name=sc.name, detected=detected,
        incident_id=best.incident_id if best else None,
        risk=best.risk_score if best else 0.0, severity=best.severity.value if best else "none",
        expected_phases=sc.expected_phases, recovered_phases=recovered, phase_recall=phase_recall,
        expected_techniques=sc.expected_techniques, matched_techniques=matched_t,
        technique_recall=t_recall, technique_precision=t_prec,
        ioc_expected=ioc_expected, ioc_matched=min(ioc_matched, ioc_expected) if ioc_expected else ioc_matched,
        evidence_expected=len(sc_ev_ids), evidence_covered=evidence_covered, evidence_coverage=evidence_coverage,
        latency_ms=latency_ms,
    )


def _ioc_hit(platform: Platform, e: SecurityEvent) -> bool:
    return bool(
        platform.ti_store.lookup_ip(e.dst_ip)
        or platform.ti_store.lookup_domain(e.domain)
        or platform.ti_store.lookup_hash(e.file_hash)
    )


def _new_high_incident(platform: Platform, before: set[str]) -> bool:
    for iid, inc in platform.incidents.items():
        if iid not in before and inc.severity.value in ("high", "critical"):
            return True
        if iid not in before and inc.risk_score >= platform.settings.incident_min_score:
            return True
    return False


def _aggregate(evals, seed, n_attack, n_benign, baseline_events, latencies, tp, fp, tn, fn, total_events) -> EvalReport:
    import numpy as np

    detected = [e for e in evals if e.detected]
    det_rate = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = det_rate
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    phase = float(np.mean([e.phase_recall for e in detected])) if detected else 0.0
    t_prec = float(np.mean([e.technique_precision for e in detected])) if detected else 0.0
    t_rec = float(np.mean([e.technique_recall for e in detected])) if detected else 0.0
    t_f1 = 2 * t_prec * t_rec / (t_prec + t_rec) if (t_prec + t_rec) else 0.0
    ioc_num = sum(e.ioc_matched for e in evals)
    ioc_den = sum(e.ioc_expected for e in evals)
    ioc_acc = ioc_num / ioc_den if ioc_den else 1.0
    ev_cov = float(np.mean([e.evidence_coverage for e in detected])) if detected else 0.0
    lat = np.asarray(latencies)
    elapsed_s = float(lat.sum()) / 1000.0

    # --- base-rate-honest false-positive accounting (answers "2% is meaningless at scale") -------
    # An incident, not an event, is what reaches an analyst. Measure false *incidents* against the true
    # event volume the platform processed, projected to a per-million-events and per-analyst-day figure.
    false_incidents = fp
    benign_events = total_events - sum(e.evidence_expected for e in evals if e.detected)  # ~all events are benign
    fp_per_million = round(false_incidents / max(benign_events, 1) * 1_000_000, 2)
    # a mid-size enterprise emits on the order of 50M security events/day; project the false-incident load
    ENTERPRISE_EVENTS_PER_DAY = 50_000_000
    false_incidents_per_day = round(fp_per_million * ENTERPRISE_EVENTS_PER_DAY / 1_000_000, 1)

    report = EvalReport(
        seed=seed, n_attack=n_attack, n_benign=n_benign, baseline_events=baseline_events,
        detection_rate=_pct(det_rate), false_positive_rate=_pct(fpr), precision=_pct(precision),
        recall=_pct(recall), f1=_pct(f1), phase_reconstruction=_pct(phase),
        technique_precision=_pct(t_prec), technique_recall=_pct(t_rec), technique_f1=_pct(t_f1),
        ioc_accuracy=_pct(ioc_acc), evidence_coverage=_pct(ev_cov),
        mean_latency_ms=round(float(lat.mean()), 2), p95_latency_ms=round(float(np.percentile(lat, 95)), 2),
        events_per_second=round(total_events / elapsed_s, 0) if elapsed_s else 0.0,
        confusion={"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        generated_at=datetime.now(UTC).isoformat(), total_events=total_events,
    )
    report.false_incidents_per_million_events = fp_per_million
    report.projected_false_incidents_per_day = false_incidents_per_day
    report.benign_events_processed = benign_events
    return report


def _by_scenario(evals: list[ScenarioEval]) -> dict[str, dict]:
    import numpy as np

    out: dict[str, dict] = {}
    ids = sorted({e.scenario_id for e in evals})
    for sid in ids:
        es = [e for e in evals if e.scenario_id == sid]
        det = [e for e in es if e.detected]
        out[sid] = {
            "name": es[0].name,
            "runs": len(es),
            "detected": len(det),
            "detection_rate": _pct(len(det) / len(es)) if es else 0.0,
            "phase_reconstruction": _pct(float(np.mean([e.phase_recall for e in det]))) if det else 0.0,
            "technique_recall": _pct(float(np.mean([e.technique_recall for e in det]))) if det else 0.0,
            "evidence_coverage": _pct(float(np.mean([e.evidence_coverage for e in det]))) if det else 0.0,
            "mean_risk": round(float(np.mean([e.risk for e in det])), 1) if det else 0.0,
            "expected_techniques": es[0].expected_techniques,
        }
    return out


def _write_scenario_examples(platform: Platform, ent: Enterprise, rng: random.Random, out_dir: Path) -> None:
    """Persist one fully-worked example incident per scenario for the docs / UI seed."""
    examples = {}
    plat = Platform(enable_anomaly=True)
    gen = BenignGenerator(ent, random.Random(99))
    base = datetime(2026, 8, 1, tzinfo=UTC)
    for d in range(3):
        plat.ingest_many(gen.day(base + timedelta(days=d), density=0.7), correlate=False)
    plat.correlate(force=True)
    for sid in SCENARIOS:
        _ = set(plat.incidents.keys())
        t = base + timedelta(days=4, hours=int(ord(sid) - 65) + 1)
        sc = generate_scenario(sid, ent, random.Random(ord(sid)), t)
        plat.ingest_many(sc.events, correlate=True)
        best, ov = None, 0
        sc_ids = {e.event_id for e in sc.events}
        for inc in plat.incidents.values():
            o = len(set(inc.event_ids) & sc_ids)
            if o > ov:
                best, ov = inc, o
        if best:
            examples[sid] = json.loads(best.model_dump_json())
    (out_dir / "example_incidents.json").write_text(json.dumps(examples, indent=2, default=str))


def render_markdown(r: EvalReport) -> str:
    lines = [
        "# Aegis Evaluation Report",
        "",
        f"_Generated {r.generated_at} · seed {r.seed} · deterministic & reproducible_",
        "",
        f"Ran **{r.n_attack} attack** and **{r.n_benign} benign** scenarios against a synthetic 60-user "
        f"enterprise after a **{r.baseline_events:,}-event** benign training baseline "
        f"(**{r.total_events:,}** events total).",
        "",
        "## Headline metrics",
        "",
        "| Metric | Result |",
        "|--------|-------:|",
        f"| Detection Rate (recall) | **{r.detection_rate}%** |",
        f"| False Positive Rate | **{r.false_positive_rate}%** |",
        f"| Precision | {r.precision}% |",
        f"| F1 score | {r.f1}% |",
        f"| Attack-chain reconstruction | {r.phase_reconstruction}% |",
        f"| MITRE technique recall | {r.technique_recall}% |",
        f"| MITRE technique precision | {r.technique_precision}% |",
        f"| IOC correlation accuracy | {r.ioc_accuracy}% |",
        f"| Evidence coverage | {r.evidence_coverage}% |",
        f"| Mean detection latency | {r.mean_latency_ms} ms |",
        f"| p95 detection latency | {r.p95_latency_ms} ms |",
        f"| Throughput | {r.events_per_second:,.0f} events/s |",
        "",
        f"Confusion matrix — TP {r.confusion['tp']}, FP {r.confusion['fp']}, "
        f"TN {r.confusion['tn']}, FN {r.confusion['fn']}.",
        "",
        "## Base-rate-honest false-positive load",
        "",
        "A percentage FPR on a balanced set is cosmetic. What reaches an analyst is a false *incident*, "
        "and what matters is how many arrive against real event volume:",
        "",
        "| Metric | Result |",
        "|--------|-------:|",
        f"| Benign events processed | {r.benign_events_processed:,} |",
        f"| False incidents raised | {r.confusion['fp']} |",
        f"| **False incidents per million events** | **{r.false_incidents_per_million_events}** |",
        f"| Projected false incidents/day @ 50M events/day | {r.projected_false_incidents_per_day} |",
        "",
        "> This is still on synthetic benign traffic. The projection assumes the synthetic base rate holds "
        "on real telemetry, which is exactly the assumption an external evaluation has to test.",
        "",
        "## Per-scenario breakdown",
        "",
        "| ID | Scenario | Runs | Det. rate | Chain recon. | Technique recall | Evidence cov. | Mean risk |",
        "|----|----------|-----:|----------:|-------------:|-----------------:|--------------:|----------:|",
    ]
    for sid, s in r.by_scenario.items():
        lines.append(
            f"| {sid} | {s['name']} | {s['runs']} | {s['detection_rate']}% | {s['phase_reconstruction']}% "
            f"| {s['technique_recall']}% | {s['evidence_coverage']}% | {s['mean_risk']} |"
        )
    lines += [
        "",
        "_Detection is fully deterministic; the LLM is not involved in any number above._",
        "",
        "## What this benchmark is — and is not",
        "",
        "This is a **reproducibility / regression harness**: the same author wrote the attack scenarios, "
        "the benign look-alikes, and the detection rules. A high score here proves the pipeline behaves as "
        "designed and stays stable across changes. It is **not** an independent detection-efficacy result — "
        "it says nothing about attacks the author did not script. Credible detection numbers require "
        "external telemetry the author did not generate and a red team the author does not control; that is "
        "the `aegis_sim.external` evaluation and the design-partner phase, not this file.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Run the Aegis evaluation harness")
    ap.add_argument("--attacks", type=int, default=100)
    ap.add_argument("--benign", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[2] / "evaluation" / "results")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    rep = run_evaluation(args.attacks, args.benign, args.seed, out_dir=args.out, verbose=args.verbose)
    print(render_markdown(rep))
