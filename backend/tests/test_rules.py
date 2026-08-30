from datetime import timedelta

from aegis.detection.rules import RuleSpec, build_rule
from aegis.schemas.events import EventType, SecurityEvent, SourceType


def ev(ts, **kw):
    kw.setdefault("source", SourceType.WINDOWS)
    return SecurityEvent(timestamp=ts, **kw)


def test_match_rule_fires_once_within_cooldown(base_time):
    spec = RuleSpec(id="T", title="t", kind="match", severity="high", score=50, techniques=[], phase="execution",
                    group_by=["host"], where={"process_name": "powershell.exe"}, cooldown_seconds=600)
    rule = build_rule(spec)
    e1 = ev(base_time, event_type=EventType.PROCESS_START, action="start", host="H", process_name="powershell.exe")
    e2 = ev(base_time + timedelta(seconds=10), event_type=EventType.PROCESS_START, action="start", host="H", process_name="powershell.exe")
    assert len(rule.process(e1)) == 1
    assert len(rule.process(e2)) == 0  # cooldown


def test_threshold_rule_with_then(base_time):
    spec = RuleSpec(id="BF", title="brute", kind="threshold", severity="high", score=55, techniques=[], phase="credential_access",
                    group_by=["user"], window_seconds=180, where={"event_type": "authentication", "action": "login_failure"},
                    count_gte=5, then={"event_type": "authentication", "action": "login_success"})
    rule = build_rule(spec)
    out = []
    for i in range(5):
        out += rule.process(ev(base_time + timedelta(seconds=i), event_type=EventType.AUTHENTICATION, action="login_failure", user="alice"))
    assert out == []
    out += rule.process(ev(base_time + timedelta(seconds=10), event_type=EventType.AUTHENTICATION, action="login_success", user="alice"))
    assert len(out) == 1
    assert out[0].rule_id == "BF"


def test_threshold_distinct_count(base_time):
    spec = RuleSpec(id="SPRAY", title="spray", kind="threshold", severity="high", score=50, techniques=[], phase="credential_access",
                    group_by=["src_ip"], window_seconds=300, where={"event_type": "authentication", "action": "login_failure"},
                    distinct="user", count_gte=3)
    rule = build_rule(spec)
    out = []
    for i, u in enumerate(["a", "b", "c"]):
        out += rule.process(ev(base_time + timedelta(seconds=i), event_type=EventType.AUTHENTICATION, action="login_failure", user=u, src_ip="5.5.5.5"))
    assert len(out) == 1


def test_sequence_rule_ordered(base_time):
    spec = RuleSpec(id="SEQ", title="seq", kind="sequence", severity="critical", score=65, techniques=[], phase="execution",
                    group_by=["host"], window_seconds=600, steps=[
                        {"event_type": "process_start", "process_name": "winword.exe"},
                        {"event_type": "process_start", "process_name": "powershell.exe"},
                    ])
    rule = build_rule(spec)
    assert rule.process(ev(base_time, event_type=EventType.PROCESS_START, action="start", host="H", process_name="winword.exe")) == []
    out = rule.process(ev(base_time + timedelta(seconds=5), event_type=EventType.PROCESS_START, action="start", host="H", process_name="powershell.exe"))
    assert len(out) == 1
    assert len(out[0].evidence_event_ids) == 2


def test_sequence_respects_window(base_time):
    spec = RuleSpec(id="SEQ", title="seq", kind="sequence", severity="critical", score=65, techniques=[], phase="execution",
                    group_by=["host"], window_seconds=60, steps=[
                        {"event_type": "process_start", "process_name": "winword.exe"},
                        {"event_type": "process_start", "process_name": "powershell.exe"},
                    ])
    rule = build_rule(spec)
    rule.process(ev(base_time, event_type=EventType.PROCESS_START, action="start", host="H", process_name="winword.exe"))
    out = rule.process(ev(base_time + timedelta(seconds=120), event_type=EventType.PROCESS_START, action="start", host="H", process_name="powershell.exe"))
    assert out == []  # second step outside window


def test_all_shipped_rules_load():
    from aegis.config import get_settings
    from aegis.detection.rules import load_rules

    specs = load_rules(get_settings().rules_dir)
    assert len(specs) >= 45
    ids = {s.id for s in specs}
    assert "AUTH-001" in ids and "BEHAV-002" in ids and "EXFIL-001" in ids
    # every rule builds without error
    for s in specs:
        build_rule(s)
