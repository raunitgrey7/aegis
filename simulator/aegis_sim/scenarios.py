"""Harmless attack scenarios (A–H). Each returns synthetic telemetry plus ground truth
(expected techniques, kill-chain phases, target host/user) for the evaluation harness.

Nothing here attacks anything — every function only *emits events* describing an attack. The events
are crafted to exercise the deterministic detectors, not to game a specific rule ID.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aegis.schemas.events import EventType, SecurityEvent, SourceType

from aegis_sim.enterprise import Enterprise

MALICIOUS_IPS = ["45.155.205.233", "194.26.29.14", "91.219.236.166", "193.142.146.35", "45.155.205.12"]
EXFIL_IPS = ["23.106.223.55", "179.43.175.44"]
BRUTE_IPS = ["5.188.86.172", "45.227.255.190"]
C2_DOMAINS = ["update-cdn-service.net", "cdn.statistics-collect.com"]
FOREIGN = ["RU", "KP", "IR", "CN", "BR", "NG"]


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    description: str
    events: list[SecurityEvent]
    target_user: str
    target_host: str
    expected_techniques: list[str]
    expected_phases: list[str]
    severity: str
    tags: list[str] = field(default_factory=list)


def _e(ent: Enterprise, ts: datetime, user: str, host: str, tenant: str, **kw) -> SecurityEvent:
    kw.setdefault("source", SourceType.EDR)
    raw = kw.pop("raw", {})
    raw = {"sim": {"kind": "attack", **raw.get("sim", raw)}}
    return SecurityEvent(tenant_id=tenant, timestamp=ts, user=user, host=host, raw=raw, **kw)


# ---------------------------------------------------------------------------- Scenario A: brute force
def scenario_brute_force(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    ip = rng.choice(BRUTE_IPS)
    evs = []
    t = start
    for i in range(rng.randint(8, 14)):
        evs.append(_e(ent, t, victim.name, victim.host, tenant, source=SourceType.WINDOWS,
                      event_type=EventType.AUTHENTICATION, action="login_failure", outcome="failure",
                      src_ip=ip, geo_country=rng.choice(FOREIGN), privilege="rdp", protocol="ntlm"))
        t += timedelta(seconds=rng.randint(3, 12))
    evs.append(_e(ent, t, victim.name, victim.host, tenant, source=SourceType.WINDOWS,
                  event_type=EventType.AUTHENTICATION, action="login_success", outcome="success",
                  src_ip=ip, geo_country=FOREIGN[0], privilege="rdp", protocol="ntlm"))
    return ScenarioResult("A", "Brute-force authentication", "Repeated failed logins then success from a hostile IP",
                          evs, victim.name, victim.host, ["T1110.001", "T1078"],
                          ["credential_access", "initial_access"], "high", ["brute_force"])


# ---------------------------------------------------------------------------- Scenario B: suspicious login
def scenario_suspicious_login(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    country = rng.choice(FOREIGN)
    ip = f"{rng.randint(80, 200)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    t = start.replace(hour=3, minute=rng.randint(0, 40))
    evs = [
        _e(ent, t, victim.name, victim.host, tenant, source=SourceType.WINDOWS, event_type=EventType.AUTHENTICATION,
           action="login_success", outcome="success", src_ip=ip, geo_country=country, privilege="rdp"),
        _e(ent, t + timedelta(minutes=1), victim.name, victim.host, tenant, event_type=EventType.PROCESS_START,
           action="start", process_name="powershell.exe", parent_process_name="explorer.exe",
           command_line="powershell.exe -NoProfile -Command Get-Process", file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ]
    return ScenarioResult("B", "Suspicious off-hours login", "Login from a foreign IP at 03:00 followed by scripting",
                          evs, victim.name, victim.host, ["T1078", "T1133", "T1059.001"],
                          ["initial_access", "execution"], "high", ["suspicious_login"])


# ---------------------------------------------------------------------------- Scenario C: malicious execution
def scenario_malicious_execution(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    t = start
    b64 = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(rng.randint(120, 240)))
    dom = rng.choice(C2_DOMAINS)
    ip = rng.choice(MALICIOUS_IPS)
    evs = [
        _e(ent, t, victim.name, victim.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="winword.exe", parent_process_name="outlook.exe", file_path=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
           command_line=rf'"winword.exe" /n "C:\Users\{victim.name}\Downloads\Invoice_2026.docm"'),
        _e(ent, t + timedelta(seconds=8), victim.name, victim.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="powershell.exe", parent_process_name="winword.exe", file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           command_line=f"powershell.exe -nop -w hidden -enc {b64}"),
        _e(ent, t + timedelta(seconds=20), victim.name, victim.host, tenant, source=SourceType.DNS,
           event_type=EventType.DNS_QUERY, action="query", outcome="success", domain=dom, dst_ip=ip, protocol="A"),
        _e(ent, t + timedelta(seconds=22), victim.name, victim.host, tenant, source=SourceType.NETWORK,
           event_type=EventType.NETWORK_CONNECTION, action="connect", process_name="powershell.exe",
           dst_ip=ip, dst_port=443, domain=dom, bytes_out=4096, protocol="tcp"),
    ]
    return ScenarioResult("C", "Malicious document execution", "Office macro spawns encoded PowerShell that beacons out",
                          evs, victim.name, victim.host, ["T1566.001", "T1059.001", "T1027.010", "T1071.001"],
                          ["execution", "command_and_control"], "critical", ["malware", "macro"])


# ---------------------------------------------------------------------------- Scenario D: privilege escalation
def scenario_privilege_escalation(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    t = start
    evs = [
        _e(ent, t, victim.name, victim.host, tenant, source=SourceType.WINDOWS, event_type=EventType.AUTHENTICATION,
           action="login_success", outcome="success", src_ip=victim.ip, privilege="interactive"),
        _e(ent, t + timedelta(minutes=2), victim.name, victim.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="cmd.exe", parent_process_name="fodhelper.exe", file_path=r"C:\Windows\System32\cmd.exe",
           command_line="cmd.exe /c whoami /priv"),
        _e(ent, t + timedelta(minutes=3), victim.name, victim.host, tenant, source=SourceType.WINDOWS,
           event_type=EventType.PRIVILEGE_CHANGE, action="special_privileges_assigned", privilege="administrator"),
        _e(ent, t + timedelta(minutes=5), victim.name, victim.host, tenant, source=SourceType.WINDOWS,
           event_type=EventType.USER_CREATED, action="created", target_user="svc-helpdesk2"),
        _e(ent, t + timedelta(minutes=6), victim.name, victim.host, tenant, source=SourceType.WINDOWS,
           event_type=EventType.GROUP_CHANGE, action="member_added", target_user="svc-helpdesk2", privilege="Administrators"),
    ]
    return ScenarioResult("D", "Privilege escalation & backdoor account", "UAC bypass then a new admin account is created",
                          evs, victim.name, victim.host, ["T1548.002", "T1068", "T1136.001", "T1098"],
                          ["privilege_escalation", "persistence"], "critical", ["privesc", "persistence"])


# ---------------------------------------------------------------------------- Scenario E: lateral movement
def scenario_lateral_movement(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    attacker = ent.random_user(rng, admin=True)
    t = start
    evs = [
        _e(ent, t, attacker.name, attacker.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="whoami.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\whoami.exe", command_line="whoami /all"),
        _e(ent, t + timedelta(seconds=20), attacker.name, attacker.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="net.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\net.exe", command_line="net group \"Domain Admins\" /domain"),
        _e(ent, t + timedelta(seconds=40), attacker.name, attacker.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="nltest.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\nltest.exe", command_line="nltest /dclist:corp"),
        _e(ent, t + timedelta(minutes=2), attacker.name, attacker.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="powershell.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           command_line="powershell.exe -c \"rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Temp\\lsass.dmp full\""),
    ]
    targets = rng.sample([s for s in ent.servers if s.role in ("file", "db", "api", "dc")], k=4)
    for i, srv in enumerate(targets):
        tt = t + timedelta(minutes=4 + i)
        evs.append(_e(ent, tt, attacker.name, attacker.host, tenant, source=SourceType.WINDOWS, event_type=EventType.AUTHENTICATION,
                      action="login_success", outcome="success", privilege="network", protocol="ntlm",
                      src_ip=attacker.ip, dst_ip=srv.ip, raw={"sim": {"target": srv.name}}))
        evs.append(_e(ent, tt + timedelta(seconds=15), attacker.name, attacker.host, tenant, event_type=EventType.PROCESS_START, action="start",
                      process_name="wmic.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\wbem\wmic.exe",
                      command_line=f"wmic /node:{srv.ip} process call create \"cmd /c powershell -enc SQBFAFgA\""))
    return ScenarioResult("E", "Hands-on-keyboard lateral movement", "Discovery, credential dumping and remote execution across servers",
                          evs, attacker.name, attacker.host, ["T1087.002", "T1003.001", "T1021.002", "T1047"],
                          ["discovery", "credential_access", "lateral_movement"], "critical", ["lateral_movement", "credential_dumping"])


# ---------------------------------------------------------------------------- Scenario F: suspicious file activity / ransomware
def scenario_ransomware(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    t = start
    evs = [
        _e(ent, t, victim.name, victim.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="vssadmin.exe", parent_process_name="cmd.exe", file_path=r"C:\Windows\System32\vssadmin.exe",
           command_line="vssadmin.exe delete shadows /all /quiet"),
        _e(ent, t + timedelta(seconds=10), victim.name, victim.host, tenant, source=SourceType.WINDOWS,
           event_type=EventType.SERVICE_STOPPED, action="stopped", service_name="WinDefend"),
    ]
    for i in range(rng.randint(180, 260)):
        evs.append(_e(ent, t + timedelta(seconds=20 + i * 0.2), victim.name, victim.host, tenant, event_type=EventType.FILE_MODIFY,
                      action="modify", process_name="lockbit.exe",
                      file_path=f"C:\\Users\\{victim.name}\\Documents\\file_{i}.docx.lockbit", file_size=rng.randint(10_000, 500_000)))
    evs.append(_e(ent, t + timedelta(seconds=90), victim.name, victim.host, tenant, event_type=EventType.FILE_CREATE, action="create",
                  process_name="lockbit.exe", file_path=f"C:\\Users\\{victim.name}\\Documents\\RESTORE-MY-FILES.txt", file_size=1400))
    return ScenarioResult("F", "Ransomware detonation", "Shadow copies deleted, AV stopped, mass file encryption and ransom note",
                          evs, victim.name, victim.host, ["T1490", "T1562.001", "T1486"],
                          ["defense_evasion", "impact"], "critical", ["ransomware"])


# ---------------------------------------------------------------------------- Scenario G: DNS anomaly / tunnelling
def scenario_dns_tunnel(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False)
    base = rng.choice(["tunnel-x.duckdns.org", "data.cdn-metrics.net", "q.dns-exfil.top"])
    t = start
    evs = []
    for i in range(rng.randint(60, 90)):
        label = "".join(rng.choice("abcdef0123456789ghjklmnpqrstuvwxyz") for _ in range(rng.randint(28, 52)))
        evs.append(_e(ent, t, victim.name, victim.host, tenant, source=SourceType.DNS, event_type=EventType.DNS_QUERY,
                      action="query", outcome="success" if rng.random() > 0.3 else "nxdomain",
                      domain=f"{label}.{base}", protocol="TXT" if rng.random() < 0.6 else "A", src_ip=victim.ip))
        t += timedelta(seconds=rng.uniform(0.5, 2.0))
    return ScenarioResult("G", "DNS tunnelling / exfiltration channel", "High-entropy TXT-record query storm to a tunnelling domain",
                          evs, victim.name, victim.host, ["T1071.004", "T1568.002", "T1048.003"],
                          ["command_and_control"], "medium", ["dns_tunnel", "exfiltration"])


# ---------------------------------------------------------------------------- Scenario H: data exfiltration
def scenario_exfiltration(ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    victim = ent.random_user(rng, admin=False, dev=False)
    t = start
    ip = rng.choice(EXFIL_IPS)
    evs = [
        _e(ent, t, victim.name, victim.host, tenant, event_type=EventType.FILE_READ, action="read", process_name="7z.exe",
           file_path=r"\\FS-01\shared\finance\payroll-2026.xlsx", file_size=4_000_000),
        _e(ent, t + timedelta(seconds=30), victim.name, victim.host, tenant, event_type=EventType.PROCESS_START, action="start",
           process_name="7z.exe", parent_process_name="powershell.exe", file_path=r"C:\Program Files\7-Zip\7z.exe",
           command_line=r"7z.exe a -p{pw} -mhe C:\Users\{u}\AppData\Local\Temp\archive.7z \\FS-01\shared\finance".replace("{u}", victim.name).replace("{pw}", "S3cr3t!")),
        _e(ent, t + timedelta(seconds=90), victim.name, victim.host, tenant, event_type=EventType.FILE_CREATE, action="create",
           process_name="7z.exe", file_path=f"C:\\Users\\{victim.name}\\AppData\\Local\\Temp\\archive.7z", file_size=320_000_000),
        _e(ent, t + timedelta(minutes=3), victim.name, victim.host, tenant, source=SourceType.NETWORK, event_type=EventType.NETWORK_CONNECTION,
           action="connect", process_name="powershell.exe", dst_ip=ip, dst_port=443, bytes_out=320_000_000, protocol="tcp",
           domain="files-share-drop.ru"),
    ]
    return ScenarioResult("H", "Data collection & exfiltration", "Sensitive share archived with a password then uploaded externally",
                          evs, victim.name, victim.host, ["T1039", "T1560.001", "T1048", "T1567.002"],
                          ["collection", "exfiltration"], "high", ["exfiltration", "insider"])


SCENARIOS = {
    "A": scenario_brute_force,
    "B": scenario_suspicious_login,
    "C": scenario_malicious_execution,
    "D": scenario_privilege_escalation,
    "E": scenario_lateral_movement,
    "F": scenario_ransomware,
    "G": scenario_dns_tunnel,
    "H": scenario_exfiltration,
}


def generate_scenario(sid: str, ent: Enterprise, rng: random.Random, start: datetime, tenant: str = "default") -> ScenarioResult:
    return SCENARIOS[sid](ent, rng, start, tenant)
