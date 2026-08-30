from datetime import UTC, datetime

from aegis.detection.conditions import Condition, is_private_ip, shannon_entropy
from aegis.schemas.events import EventType, SecurityEvent, SourceType


def test_event_fingerprint_stable():
    kw = dict(source=SourceType.WINDOWS, event_type=EventType.AUTHENTICATION, action="login_success",
              user="alice", host="WS-1", timestamp=datetime(2026, 8, 30, tzinfo=UTC))
    a = SecurityEvent(**kw)
    b = SecurityEvent(**kw)
    assert a.fingerprint() == b.fingerprint()
    c = SecurityEvent(**{**kw, "user": "bob"})
    assert a.fingerprint() != c.fingerprint()


def test_entity_keys_excludes_private_ip():
    e = SecurityEvent(source="network", event_type="network_connection", action="connect",
                      host="WS-1", dst_ip="10.0.0.5")
    assert "host:WS-1" in e.entity_keys()
    assert not any(k.startswith("ip:") for k in e.entity_keys())
    e2 = SecurityEvent(source="network", event_type="network_connection", action="connect",
                       host="WS-1", dst_ip="45.155.205.233")
    assert "ip:45.155.205.233" in e2.entity_keys()


def test_timestamp_made_tz_aware():
    e = SecurityEvent(source="windows", event_type="authentication", action="login_success",
                      timestamp=datetime(2026, 8, 30, 2, 0))
    assert e.timestamp.tzinfo is not None


def test_is_private_ip():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("45.155.205.233")
    assert is_private_ip(None)  # unknown treated as private/safe
    assert is_private_ip("not-an-ip")


def test_shannon_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.9
    assert shannon_entropy("") == 0.0


def _ev(**kw):
    kw.setdefault("source", "windows")
    kw.setdefault("event_type", "process_start")
    kw.setdefault("action", "start")
    return SecurityEvent(**kw)


def test_condition_equality_case_insensitive():
    c = Condition({"process_name": "PowerShell.exe"})
    assert c(_ev(process_name="powershell.exe"))
    assert not c(_ev(process_name="cmd.exe"))


def test_condition_in_and_regex():
    c = Condition({"process_name": {"in": ["powershell.exe", "pwsh.exe"]},
                   "command_line": {"regex": r"(?i)-enc\s+[A-Za-z0-9+/=]{10,}"}})
    assert c(_ev(process_name="pwsh.exe", command_line="pwsh -enc AAAABBBBCCCCDDDD"))
    assert not c(_ev(process_name="pwsh.exe", command_line="pwsh -File build.ps1"))


def test_condition_private_and_gte():
    c = Condition({"dst_ip": {"private": False}, "bytes_out": {"gte": 1000}})
    assert c(_ev(event_type="network_connection", action="connect", dst_ip="8.8.8.8", bytes_out=5000))
    assert not c(_ev(event_type="network_connection", action="connect", dst_ip="10.0.0.1", bytes_out=5000))


def test_condition_any_of_and_not():
    c = Condition({"any_of": [{"process_name": "cmd.exe"}, {"process_name": "powershell.exe"}],
                   "not": {"command_line": {"contains": "safe"}}})
    assert c(_ev(process_name="cmd.exe", command_line="cmd /c evil"))
    assert not c(_ev(process_name="cmd.exe", command_line="cmd /c safe-thing"))
    assert not c(_ev(process_name="explorer.exe"))


def test_condition_endswith_list():
    c = Condition({"file_path": {"endswith": [".zip", ".7z"]}})
    assert c(_ev(event_type="file_create", action="create", file_path="C:/x/export.ZIP"))
    assert not c(_ev(event_type="file_create", action="create", file_path="C:/x/doc.txt"))


def test_regex_input_capped_no_redos():
    # A classic catastrophic-backtracking pattern against a non-matching tail.
    # Two defences: the schema caps strings at 8192 chars, and the matcher caps regex
    # input to MAX_REGEX_INPUT (4096). This must return quickly, never hang.
    import time

    c = Condition({"command_line": {"regex": r"(a+)+$"}})
    big = "a" * 8000 + "!"  # within schema limit, would be catastrophic uncapped
    t0 = time.perf_counter()
    result = c(_ev(command_line=big))
    assert time.perf_counter() - t0 < 1.0  # capped input -> fast
    assert result in (True, False)  # completes fast regardless

def test_regex_input_cap_constant():
    from aegis.detection.conditions import MAX_REGEX_INPUT
    assert MAX_REGEX_INPUT <= 8192
