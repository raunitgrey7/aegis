"""v2: claim verifier (semantic fact-check) and risk ledger (low-and-slow) tests."""

import random
from datetime import UTC, datetime, timedelta

from aegis.correlation.ledger import RiskLedger
from aegis.investigation.claims import verify_claims
from aegis.pipeline import Platform
from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import Severity


def _det(rule_id, score, ts, kind=DetectionKind.RULE, **entities):
    return Detection(kind=kind, rule_id=rule_id, title=rule_id, severity=Severity.MEDIUM, score=score,
                     confidence=0.8, techniques=["T1547.001"], phase="persistence", timestamp=ts,
                     entities=entities, evidence_event_ids=[f"evt_{rule_id.lower()}"])


def _incident_with(platform, sid):
    from aegis_sim.enterprise import Enterprise
    from aegis_sim.scenarios import generate_scenario

    ent = Enterprise(seed=3)
    sc = generate_scenario(sid, ent, random.Random(3), datetime(2026, 8, 30, 3, 0, tzinfo=UTC))
    platform.ingest_many(sc.events, correlate=True)
    sc_ids = {e.event_id for e in sc.events}
    inc = max(platform.incidents.values(), key=lambda i: len(set(i.event_ids) & sc_ids))
    return inc, platform.incident_events(inc)


def test_claim_verifier_passes_faithful_narrative(platform):
    inc, evs = _incident_with(platform, "C")
    faithful = f"powershell.exe on {inc.affected_hosts[0]} connected to {inc.external_ips[0]}."
    v = verify_claims(faithful, inc, evs)
    assert v["verified"], v["unsupported_claims"]


def test_claim_verifier_flags_invented_entities(platform):
    inc, evs = _incident_with(platform, "C")
    real_id = evs[0].event_id
    fake = f"Host connected to 8.8.8.8 and DB-99 ({real_id}); ransomware via mimikatz.exe (T1486)."
    v = verify_claims(fake, inc, evs)
    assert not v["verified"]
    vals = {c["value"] for c in v["unsupported_claims"]}
    assert "8.8.8.8" in vals and "DB-99" in vals and "T1486" in vals and "mimikatz.exe" in vals


def test_claim_verifier_respects_negation(platform):
    inc, evs = _incident_with(platform, "C")
    txt = "No exfiltration was observed and there was no ransomware."
    v = verify_claims(txt, inc, evs)
    # "exfiltration"/"ransomware" are negated -> must NOT be counted as asserted phases
    assert all(c["kind"] != "phase" for c in v["unsupported_claims"])


def test_investigation_report_has_verification(platform):
    from aegis.investigation.engine import InvestigationEngine
    from aegis.mitre.catalog import get_catalog

    inc, evs = _incident_with(platform, "C")
    rep = InvestigationEngine(get_catalog(), llm=None).investigate(inc, evs)
    assert rep.verification["reference_integrity"]["label"] == "Citations resolve to real events"
    assert "not_verified" in rep.verification
    assert rep.claim_verification["verified"]  # deterministic narrative is faithful by construction


def test_ledger_accumulates_and_decays():
    led = RiskLedger(half_life_hours=48, threshold=60, min_deposits=2, min_span_seconds=3600)
    base = datetime(2026, 8, 1, tzinfo=UTC)
    last = base
    for i in range(5):
        last = base + timedelta(days=i)
        led.observe(_det(f"R{i}", 40, last, host="WS-1"))
    # accumulation: many spread-out medium signals sum past the threshold no single one reaches
    assert led.balance("host:WS-1", last) > 60
    cands = led.slow_burn_candidates(last)
    assert any(c["entity"] == "host:WS-1" for c in cands)
    # a single deposit must never be a candidate
    led2 = RiskLedger(min_deposits=2)
    led2.observe(_det("X", 90, base, host="WS-9"))
    assert led2.slow_burn_candidates(base) == []


def test_ledger_decay_forgets_old_isolated_signal():
    led = RiskLedger(half_life_hours=24, threshold=80)
    base = datetime(2026, 8, 1, tzinfo=UTC)
    led.observe(_det("R", 50, base, host="WS-2"))
    # 10 days later, one deposit has decayed to near-zero
    assert led.balance("host:WS-2", base + timedelta(days=10)) < 1.0


def test_low_and_slow_scenario_detected():
    from aegis_sim.benign import BenignGenerator
    from aegis_sim.enterprise import Enterprise
    from aegis_sim.scenarios import generate_scenario

    ent = Enterprise(seed=9)
    p = Platform(enable_anomaly=True)
    gen = BenignGenerator(ent, random.Random(9))
    base = datetime(2026, 8, 1, tzinfo=UTC)
    for d in range(2):
        p.ingest_many(gen.day(base + timedelta(days=d), density=0.5), correlate=False)
    p.correlate(force=True)
    sc = generate_scenario("I", ent, random.Random(5), base + timedelta(days=5))
    assert (sc.events[-1].timestamp - sc.events[0].timestamp).days >= 4  # genuinely spread out
    p.ingest_many(sc.events, correlate=True)
    sc_ids = {e.event_id for e in sc.events}
    hit = [i for i in p.incidents.values() if set(i.event_ids) & sc_ids]
    assert hit, "low-and-slow campaign was not detected"
    assert any("slow_burn" in i.tags for i in hit), "no ledger-driven slow-burn incident formed"
