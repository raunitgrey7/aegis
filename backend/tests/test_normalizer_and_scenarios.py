import random
from datetime import UTC, datetime

from aegis.ingestion.normalizer import normalize
from aegis.pipeline import Platform
from aegis.schemas.events import EventType, SourceType
from aegis_sim.enterprise import Enterprise
from aegis_sim.scenarios import SCENARIOS, generate_scenario


def test_normalize_windows_4625():
    rec = {"EventID": 4625, "Computer": "WS-1", "TimeCreated": "2026-08-30T02:00:00Z",
           "EventData": {"TargetUserName": "alice", "IpAddress": "5.188.86.172", "LogonType": 10}}
    e = normalize(rec, "windows")
    assert e.event_type == EventType.AUTHENTICATION
    assert e.action == "login_failure"
    assert e.user == "alice"
    assert e.privilege == "rdp"
    assert e.source == SourceType.WINDOWS


def test_normalize_sysmon_process():
    rec = {"collector": "sysmon", "EventID": 1, "Computer": "WS-1", "TimeCreated": "2026-08-30T02:00:00Z",
           "EventData": {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami",
                         "ParentImage": r"C:\Program Files\Office\winword.exe", "User": "bob"}}
    e = normalize(rec)
    assert e.event_type == EventType.PROCESS_START
    assert e.process_name == "cmd.exe"
    assert e.parent_process_name == "winword.exe"


def test_normalize_zeek_conn():
    rec = {"collector": "zeek", "id.orig_h": "10.0.0.5", "id.resp_h": "45.155.205.233",
           "id.resp_p": 443, "orig_bytes": 1000, "resp_bytes": 2000, "ts": "2026-08-30T02:00:00Z"}
    e = normalize(rec)
    assert e.event_type == EventType.NETWORK_CONNECTION
    assert e.dst_ip == "45.155.205.233"
    assert e.bytes_out == 1000


def test_normalize_autodetect_dns():
    rec = {"id.orig_h": "10.0.0.5", "query": "evil.example.com", "rcode_name": "NXDOMAIN", "ts": "2026-08-30T02:00:00Z"}
    e = normalize(rec)
    assert e.event_type == EventType.DNS_QUERY
    assert e.domain == "evil.example.com"
    assert e.outcome == "nxdomain"


def _detect_scenario(sid: str) -> bool:
    ent = Enterprise(seed=5)
    p = Platform(enable_anomaly=True)
    sc = generate_scenario(sid, ent, random.Random(ord(sid)), datetime(2026, 8, 30, 3, 0, tzinfo=UTC))
    p.ingest_many(sc.events, correlate=True)
    sc_ids = {e.event_id for e in sc.events}
    return any(set(i.event_ids) & sc_ids for i in p.incidents.values())


def test_every_scenario_detected():
    for sid in SCENARIOS:
        assert _detect_scenario(sid), f"scenario {sid} not detected"


def test_scenario_c_full_chain():
    ent = Enterprise(seed=5)
    p = Platform(enable_anomaly=True)
    sc = generate_scenario("C", ent, random.Random(3), datetime(2026, 8, 30, 3, 0, tzinfo=UTC))
    p.ingest_many(sc.events, correlate=True)
    sc_ids = {e.event_id for e in sc.events}
    inc = max(p.incidents.values(), key=lambda i: len(set(i.event_ids) & sc_ids))
    assert inc.severity.value in ("high", "critical")
    assert "execution" in inc.present_phases
    assert "command_and_control" in inc.present_phases
