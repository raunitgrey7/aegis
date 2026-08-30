"""Benign telemetry generator — the 'normal day' every detector must learn to ignore.

Includes deliberately *hard negatives*: admins running admin tools, developers running PowerShell,
travellers logging in from abroad, big backups to internal servers, typo'd passwords, Office documents
opened from email. A detector that flags these is a detector that gets switched off in production.
"""

from __future__ import annotations

import math
import random
from datetime import datetime, timedelta

from aegis.schemas.events import EventType, SecurityEvent, SourceType

from aegis_sim.enterprise import (
    COUNTRY_HOME,
    DEV_PROCESSES,
    DOC_DIRS,
    DOC_EXT,
    IT_ADMIN_PROCESSES,
    SAAS,
    USER_PROCESSES,
    Enterprise,
    User,
)


def _sim_tag(kind: str, **extra) -> dict:
    return {"sim": {"kind": kind, **extra}}


class BenignGenerator:
    def __init__(self, ent: Enterprise, rng: random.Random, tenant: str = "default"):
        self.ent = ent
        self.rng = rng
        self.tenant = tenant
        self._pid = 1000

    def _pid_next(self) -> int:
        self._pid += self.rng.randint(1, 40)
        return self._pid

    def _bytes_out(self) -> int:
        # log-normal with a fat tail: most requests small, some uploads (OneDrive sync, video calls) in the MBs
        mu, sigma = 9.5, 1.7
        v = int(math.exp(self.rng.gauss(mu, sigma)))
        if self.rng.random() < 0.02:
            v = self.rng.randint(5_000_000, 30_000_000)
        return max(200, min(v, 40_000_000))

    # ------------------------------------------------------------------ single-event builders
    def login(self, user: User, ts: datetime, *, host: str | None = None, ok: bool = True, country: str | None = None,
              src_ip: str | None = None, privilege: str = "interactive", tag: str = "benign") -> SecurityEvent:
        return SecurityEvent(
            tenant_id=self.tenant,
            timestamp=ts,
            source=SourceType.WINDOWS,
            event_type=EventType.AUTHENTICATION,
            action="login_success" if ok else "login_failure",
            outcome="success" if ok else "failure",
            host=host or user.host,
            user=user.name,
            session_id=f"0x{self.rng.randint(0x10000, 0xFFFFF):x}",
            src_ip=src_ip or user.ip,
            geo_country=country or COUNTRY_HOME,
            privilege=privilege,
            protocol="kerberos" if (src_ip or user.ip).startswith("10.") else "ntlm",
            raw=_sim_tag(tag, logon_type=2 if privilege == "interactive" else 10),
        )

    def process(self, user: User, ts: datetime, name: str, parent: str, path: str, cmd: str | None = None,
                host: str | None = None, tag: str = "benign") -> SecurityEvent:
        return SecurityEvent(
            tenant_id=self.tenant,
            timestamp=ts,
            source=SourceType.EDR,
            event_type=EventType.PROCESS_START,
            action="start",
            outcome="success",
            host=host or user.host,
            user=user.name,
            process_name=name,
            process_id=self._pid_next(),
            parent_process_name=parent,
            parent_process_id=self._pid_next(),
            command_line=cmd or name,
            file_path=path.replace("{u}", user.name),
            raw=_sim_tag(tag),
        )

    def file(self, user: User, ts: datetime, action: EventType, path: str, proc: str, size: int | None = None,
             host: str | None = None, tag: str = "benign") -> SecurityEvent:
        return SecurityEvent(
            tenant_id=self.tenant,
            timestamp=ts,
            source=SourceType.EDR,
            event_type=action,
            action=action.value.split("_")[1],
            host=host or user.host,
            user=user.name,
            process_name=proc,
            file_path=path,
            file_size=size,
            raw=_sim_tag(tag),
        )

    def dns(self, user: User, ts: datetime, domain: str, answer: str | None, ok: bool = True, qtype: str = "A",
            host: str | None = None, tag: str = "benign") -> SecurityEvent:
        return SecurityEvent(
            tenant_id=self.tenant,
            timestamp=ts,
            source=SourceType.DNS,
            event_type=EventType.DNS_QUERY,
            action="query",
            outcome="success" if ok else "nxdomain",
            host=host or user.host,
            user=user.name,
            src_ip=user.ip,
            domain=domain,
            dst_ip=answer if ok else None,
            protocol=qtype,
            raw=_sim_tag(tag),
        )

    def conn(self, user: User, ts: datetime, dst_ip: str, dst_port: int, proc: str, bytes_out: int | None = None,
             domain: str | None = None, host: str | None = None, outcome: str = "success", tag: str = "benign") -> SecurityEvent:
        return SecurityEvent(
            tenant_id=self.tenant,
            timestamp=ts,
            source=SourceType.NETWORK,
            event_type=EventType.NETWORK_CONNECTION,
            action="connect",
            outcome=outcome,
            host=host or user.host,
            user=user.name,
            process_name=proc,
            src_ip=user.ip,
            src_port=self.rng.randint(49152, 65535),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="tcp",
            domain=domain,
            bytes_out=bytes_out if bytes_out is not None else self._bytes_out(),
            bytes_in=self.rng.randint(1_000, 5_000_000),
            raw=_sim_tag(tag),
        )

    # ------------------------------------------------------------------ composite generators
    def user_session(self, user: User, day: datetime, *, density: float = 1.0, window: tuple[datetime, datetime] | None = None) -> list[SecurityEvent]:
        """One user's activity for a day (or restricted to a window). Density scales event count."""
        rng = self.rng
        evs: list[SecurityEvent] = []
        start = day.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(hours=user.start_hour + rng.gauss(0, 0.25))
        end = day.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(hours=user.end_hour + rng.gauss(0, 0.3))
        if window:
            w0, w1 = window
            # only emit the login if the window contains it
            if w0 <= start <= w1:
                evs.extend(self._login_sequence(user, start))
            lo, hi = max(start, w0), min(end, w1)
        else:
            evs.extend(self._login_sequence(user, start))
            lo, hi = start, end
        if hi <= lo:
            return evs
        span = (hi - lo).total_seconds()
        n = max(1, int(span / 3600 * 14 * density))
        for _ in range(n):
            ts = lo + timedelta(seconds=rng.uniform(0, span))
            evs.extend(self._activity(user, ts))
        return evs

    def _login_sequence(self, user: User, ts: datetime) -> list[SecurityEvent]:
        rng = self.rng
        evs: list[SecurityEvent] = []
        country, src_ip, priv = COUNTRY_HOME, user.ip, "interactive"
        if user.traveller and rng.random() < 0.25:
            country = rng.choice(user.travel_countries)
            src_ip = f"{rng.randint(20, 60)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            priv = "rdp"  # VPN + RDP to own workstation
        # occasional typo
        fails = 0 if rng.random() < 0.8 else rng.randint(1, 3)
        for i in range(fails):
            evs.append(self.login(user, ts - timedelta(seconds=(fails - i) * rng.randint(4, 15)), ok=False, country=country, src_ip=src_ip, privilege=priv))
        evs.append(self.login(user, ts, ok=True, country=country, src_ip=src_ip, privilege=priv))
        name, parent, path = USER_PROCESSES[6]
        evs.append(self.process(user, ts + timedelta(seconds=2), name, parent, path))
        for name, parent, path in (USER_PROCESSES[0], USER_PROCESSES[5], USER_PROCESSES[7]):
            evs.append(self.process(user, ts + timedelta(seconds=rng.randint(5, 90)), name, parent, path))
        return evs

    def _activity(self, user: User, ts: datetime) -> list[SecurityEvent]:
        rng = self.rng
        r = rng.random()
        evs: list[SecurityEvent] = []
        if r < 0.30:  # web / SaaS
            domain, ip, port = rng.choice(SAAS)
            evs.append(self.dns(user, ts, domain, ip))
            evs.append(self.conn(user, ts + timedelta(seconds=1), ip, port, rng.choice(["chrome.exe", "msedge.exe", "teams.exe", "outlook.exe", "onedrive.exe"]), domain=domain))
        elif r < 0.50:  # documents
            d = rng.choice(DOC_DIRS).replace("{u}", user.name).replace("{d}", user.department)
            path = f"{d}\\{rng.choice(['Q3-report', 'notes', 'budget', 'roadmap', 'customer-list', 'invoice', 'minutes'])}-{rng.randint(1, 99)}{rng.choice(DOC_EXT)}"
            action = rng.choice([EventType.FILE_READ, EventType.FILE_MODIFY, EventType.FILE_CREATE])
            evs.append(self.file(user, ts, action, path, rng.choice(["winword.exe", "excel.exe", "explorer.exe", "powerpnt.exe", "notepad.exe"]), size=rng.randint(10_000, 8_000_000)))
        elif r < 0.65:  # launch an app
            name, parent, path = rng.choice(USER_PROCESSES)
            evs.append(self.process(user, ts, name, parent, path))
        elif r < 0.75:  # email attachment opened (Office child of Outlook) — must NOT alert
            evs.append(self.process(user, ts, rng.choice(["winword.exe", "excel.exe", "acrord32.exe"]), "outlook.exe", USER_PROCESSES[1][2]))
            evs.append(self.file(user, ts + timedelta(seconds=2), EventType.FILE_CREATE, f"C:\\Users\\{user.name}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{rng.randint(1000, 9999)}.docx", "outlook.exe", size=rng.randint(20_000, 3_000_000)))
        elif r < 0.85 and user.is_dev:  # developer tooling incl. PowerShell and 7z — hard negatives
            name, parent, path, cmd = rng.choice(DEV_PROCESSES)
            evs.append(self.process(user, ts, name, parent, path, cmd))
            if name in ("git.exe", "node.exe", "python.exe"):
                domain, ip, port = rng.choice(SAAS[5:7] + SAAS[18:20])
                evs.append(self.conn(user, ts + timedelta(seconds=2), ip, port, name, bytes_out=rng.randint(2_000, 4_000_000), domain=domain))
        elif r < 0.85 and user.is_admin:  # IT admin doing admin things — hard negatives
            name, parent, path, cmd = rng.choice(IT_ADMIN_PROCESSES)
            evs.append(self.process(user, ts, name, parent, path, cmd))
            if rng.random() < 0.3:
                srv = rng.choice(self.ent.servers)
                evs.append(self.login(user, ts + timedelta(seconds=5), host=srv.name, privilege="rdp"))
        elif r < 0.92:  # internal services: file share, DB, API
            srv = rng.choice([s for s in self.ent.servers if s.role in ("file", "db", "api", "web")])
            port = {"file": 445, "db": 1433, "api": 8443, "web": 443}[srv.role]
            evs.append(self.conn(user, ts, srv.ip, port, "explorer.exe" if port == 445 else "chrome.exe", bytes_out=rng.randint(1_000, 20_000_000)))
        else:  # OneDrive/backup sync bursts to internal backup or cloud
            if rng.random() < 0.5:
                evs.append(self.conn(user, ts, self.ent.server("backup").ip, 443, "veeam.agent.exe", bytes_out=rng.randint(100_000_000, 900_000_000)))
            else:
                domain, ip, port = SAAS[16]
                evs.append(self.conn(user, ts, ip, port, "onedrive.exe", bytes_out=rng.randint(3_000_000, 35_000_000), domain=domain))
        return evs

    def server_noise(self, day: datetime, window: tuple[datetime, datetime] | None = None, density: float = 1.0) -> list[SecurityEvent]:
        rng = self.rng
        evs: list[SecurityEvent] = []
        lo = window[0] if window else day.replace(hour=0, minute=0, second=0, microsecond=0)
        hi = window[1] if window else lo + timedelta(days=1)
        span = (hi - lo).total_seconds()
        svc_user = User(name="svc-backup", department="it", host="BKP-01", ip="10.0.2.70")
        for _ in range(max(1, int(span / 3600 * 6 * density))):
            ts = lo + timedelta(seconds=rng.uniform(0, span))
            srv = rng.choice(self.ent.servers)
            evs.append(self.process(svc_user, ts, "svchost.exe", "services.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", host=srv.name))
            if rng.random() < 0.3:
                evs.append(self.login(svc_user, ts, host=srv.name, privilege="service"))
        return evs

    def day(self, day: datetime, *, density: float = 1.0, window: tuple[datetime, datetime] | None = None, users: list[User] | None = None) -> list[SecurityEvent]:
        evs: list[SecurityEvent] = []
        for u in users or self.ent.users:
            evs.extend(self.user_session(u, day, density=density, window=window))
        evs.extend(self.server_noise(day, window, density))
        evs.sort(key=lambda e: e.timestamp)
        return evs
