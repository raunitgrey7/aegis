from datetime import UTC, datetime, timedelta

from aegis.graph.attack_graph import critical_path
from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import Severity
from aegis.scoring.risk import score_incident


def det(rule_id, score, phase, techniques, ts, kind=DetectionKind.RULE, sev=Severity.HIGH, **entities):
    return Detection(kind=kind, rule_id=rule_id, title=rule_id, severity=sev, score=score, confidence=0.9,
                     techniques=techniques, phase=phase, timestamp=ts, entities=entities,
                     evidence_event_ids=[f"evt_{rule_id.lower()}"])


def test_noisy_or_caps_at_100():
    ts = datetime(2026, 8, 30, tzinfo=UTC)
    dets = [det(f"R{i}", 80, "execution", ["T1059"], ts) for i in range(5)]
    risk, conf, sev, breakdown = score_incident(dets, ["execution"], ["WS-1"], ["alice"])
    assert risk <= 100.0
    assert breakdown["raw_total"] >= risk or risk == 100.0


def test_kill_chain_bonus_raises_multi_phase():
    ts = datetime(2026, 8, 30, tzinfo=UTC)
    single = [det("R1", 40, "execution", ["T1059"], ts)]
    multi = [det("R1", 40, "execution", ["T1059"], ts),
             det("R2", 40, "exfiltration", ["T1041"], ts, host="WS-1")]
    r1, *_ = score_incident(single, ["execution"], ["WS-1"], ["alice"])
    r2, _, _, bd = score_incident(multi, ["execution", "exfiltration"], ["WS-1"], ["alice"])
    assert r2 > r1
    assert bd["kill_chain_bonus"] > 0


def test_threat_intel_bonus():
    ts = datetime(2026, 8, 30, tzinfo=UTC)
    dets = [det("R1", 40, "command_and_control", ["T1071"], ts),
            det("TI-IP", 55, "command_and_control", ["T1071"], ts, kind=DetectionKind.THREAT_INTEL)]
    _, _, _, bd = score_incident(dets, ["command_and_control"], ["WS-1"], ["alice"])
    assert bd["threat_intel_bonus"] > 0


def test_severity_thresholds():
    ts = datetime(2026, 8, 30, tzinfo=UTC)
    _, _, sev, _ = score_incident([det("R", 90, "impact", ["T1486"], ts, sev=Severity.CRITICAL)], ["impact"], ["DB-1"], ["x"])
    assert sev == Severity.CRITICAL


def test_pipeline_builds_incident_with_graph(platform, base_time):
    from aegis.schemas.events import SecurityEvent

    E = lambda **kw: SecurityEvent(source="windows", user="bob", host="WS-9", **kw)
    events = [E(timestamp=base_time + timedelta(seconds=i), event_type="authentication", action="login_failure", src_ip="5.188.86.172") for i in range(6)]
    events.append(E(timestamp=base_time + timedelta(seconds=70), event_type="authentication", action="login_success", src_ip="5.188.86.172", geo_country="RU", privilege="rdp"))
    events.append(E(timestamp=base_time + timedelta(seconds=120), event_type="process_start", action="start", process_name="powershell.exe", parent_process_name="explorer.exe", command_line="powershell -enc AAAABBBBCCCCDDDDEEEE"))
    events.append(E(timestamp=base_time + timedelta(seconds=180), event_type="network_connection", action="connect", process_name="powershell.exe", dst_ip="45.155.205.233", dst_port=443, bytes_out=2000))
    platform.ingest_many(events)
    assert len(platform.incidents) >= 1
    inc = max(platform.incidents.values(), key=lambda i: i.risk_score)
    assert inc.risk_score > 50
    assert inc.graph.nodes and inc.graph.edges
    # graph must reference an IOC node for the malicious IP
    assert any(n.type == "ioc" for n in inc.graph.nodes)
    # critical path is a valid ordering
    cp = critical_path(inc.graph)
    assert isinstance(cp, list)


def test_lone_anomaly_not_incident(trained_platform):
    p, ent, gen = trained_platform

    before = len(p.incidents)
    # a single off-hours login for a well-established user -> anomaly, but no corroboration
    u = ent.users[0]
    base = datetime(2026, 8, 20, 3, 17, tzinfo=UTC)
    p.ingest_many([gen.login(u, base, country="IN")], correlate=True)
    # should not create a brand-new incident from one lone anomaly
    assert len(p.incidents) <= before + 0 or all(
        len(i.detections) > 1 or i.detections[0].kind != DetectionKind.ANOMALY
        for i in p.incidents.values()
    )
