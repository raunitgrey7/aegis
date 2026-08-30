"""Specialised investigation agents.

Each agent has ONE responsibility and works only from the incident's own evidence. Agents are
deterministic analysers first; the LLM (when available) is used to phrase their finding in natural
language. Their structured output feeds the synthesizer. This is 'multi-agent' in the useful sense —
division of labour — not agents chatting for the sake of it.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from aegis.investigation.report import AgentFinding
from aegis.schemas.detections import Detection
from aegis.schemas.events import EventType, SecurityEvent


@dataclass
class AgentContext:
    incident_id: str
    events: list[SecurityEvent]
    detections: list[Detection]

    def by_type(self, *types: EventType) -> list[SecurityEvent]:
        s = set(types)
        return [e for e in self.events if e.event_type in s]


class BaseAgent:
    name = "base"
    focus = ""

    def analyse(self, ctx: AgentContext) -> AgentFinding | None:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def _finding(name: str, headline: str, detail: str, confidence: float, ids: list[str]) -> AgentFinding:
        return AgentFinding(agent=name, headline=headline, detail=detail, confidence=confidence, evidence_event_ids=ids[:20])


class IdentityAgent(BaseAgent):
    name = "identity"
    focus = "authentication, accounts, privilege"

    def analyse(self, ctx: AgentContext) -> AgentFinding | None:
        auths = ctx.by_type(EventType.AUTHENTICATION)
        privs = ctx.by_type(EventType.PRIVILEGE_CHANGE, EventType.GROUP_CHANGE, EventType.USER_CREATED)
        if not auths and not privs:
            return None
        fails = [e for e in auths if e.action == "login_failure"]
        succ = [e for e in auths if e.action == "login_success"]
        countries = sorted({e.geo_country for e in succ if e.geo_country})
        ips = sorted({e.src_ip for e in succ if e.src_ip})
        users = sorted({e.user for e in auths if e.user})
        bits = []
        conf = 0.6
        ids: list[str] = []
        if fails:
            bits.append(f"{len(fails)} failed authentication attempt(s)")
            ids += [e.event_id for e in fails[:5]]
            conf += 0.15
        if succ:
            bits.append(f"{len(succ)} successful login(s) for {', '.join(users)}")
            ids += [e.event_id for e in succ[:3]]
        if countries and set(countries) - {"IN"}:
            bits.append(f"authentication geolocated to {', '.join(countries)}")
            conf += 0.15
        if privs:
            newp = [e for e in privs if e.event_type in (EventType.PRIVILEGE_CHANGE, EventType.GROUP_CHANGE, EventType.USER_CREATED)]
            bits.append(f"{len(newp)} privilege / account change(s), including "
                        + ", ".join(sorted({(e.privilege or e.action or "change") for e in newp}))[:120])
            ids += [e.event_id for e in newp[:3]]
            conf += 0.1
        headline = "Compromised or misused identity" if (fails and succ) or countries else "Identity activity of interest"
        detail = (
            "Account activity shows " + "; ".join(bits) + "."
            + (f" Source IP(s): {', '.join(ips[:4])}." if ips else "")
        )
        return self._finding(self.name, headline, detail, min(conf, 0.95), ids)


class ProcessAgent(BaseAgent):
    name = "process"
    focus = "process execution, scripts, LOLBins"

    SUSPECT = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
               "rundll32.exe", "regsvr32.exe", "certutil.exe", "wmic.exe", "vssadmin.exe", "psexec.exe"}

    def analyse(self, ctx: AgentContext) -> AgentFinding | None:
        procs = ctx.by_type(EventType.PROCESS_START)
        if not procs:
            return None
        suspects = [e for e in procs if (e.process_name or "").lower() in self.SUSPECT]
        chains = [e for e in procs if (e.parent_process_name or "").lower() in
                  {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}]
        encoded = [e for e in procs if e.command_line and ("-enc" in e.command_line.lower() or "encodedcommand" in e.command_line.lower())]
        if not suspects and not chains:
            common = Counter((e.process_name or "?") for e in procs).most_common(3)
            return self._finding(self.name, "Routine process activity",
                                 f"{len(procs)} process starts observed; most frequent: "
                                 + ", ".join(f"{n} (x{c})" for n, c in common) + ".", 0.4,
                                 [e.event_id for e in procs[:5]])
        bits = []
        ids: list[str] = []
        conf = 0.7
        if chains:
            e = chains[0]
            bits.append(f"{e.parent_process_name} spawned {e.process_name} (macro/exploit execution)")
            ids.append(e.event_id)
            conf += 0.15
        if encoded:
            bits.append("PowerShell executed a Base64-encoded command (obfuscation)")
            ids.append(encoded[0].event_id)
            conf += 0.15
        if suspects:
            names = sorted({e.process_name for e in suspects if e.process_name})
            bits.append(f"execution of {', '.join(names[:6])}")
            ids += [e.event_id for e in suspects[:4]]
        return self._finding(self.name, "Suspicious command execution",
                             "Endpoint process activity indicates " + "; ".join(bits) + ".",
                             min(conf, 0.95), ids)


class NetworkAgent(BaseAgent):
    name = "network"
    focus = "connections, C2, DNS, exfiltration"

    def analyse(self, ctx: AgentContext) -> AgentFinding | None:
        conns = ctx.by_type(EventType.NETWORK_CONNECTION)
        dns = ctx.by_type(EventType.DNS_QUERY)
        ti = [d for d in ctx.detections if d.kind.value == "threat_intel"]
        if not conns and not dns:
            return None
        ext = [e for e in conns if e.dst_ip and not e.dst_ip.startswith(("10.", "192.168.", "172."))]
        egress = max((e.bytes_out or 0) for e in conns) if conns else 0
        bits = []
        ids: list[str] = []
        conf = 0.6
        if ext:
            dests = sorted({f"{e.dst_ip}:{e.dst_port}" for e in ext})
            bits.append(f"{len(ext)} outbound connection(s) to {', '.join(dests[:4])}")
            ids += [e.event_id for e in ext[:4]]
        if ti:
            bits.append(f"{len(ti)} destination(s) matched threat intelligence ("
                        + ", ".join(sorted({d.details.get('threat', 'malicious') for d in ti}))[:100] + ")")
            ids += [i for d in ti for i in d.evidence_event_ids[:2]]
            conf += 0.25
        if egress >= 10_000_000:
            bits.append(f"largest single transfer was {egress / 1e6:.0f} MB outbound")
            conf += 0.1
        if dns:
            odd = [e for e in dns if e.domain and (e.protocol == "TXT" or len(e.domain.split('.')[0]) > 30)]
            if odd:
                bits.append(f"{len(odd)} anomalous DNS quer(ies) (possible tunnelling)")
                ids += [e.event_id for e in odd[:3]]
                conf += 0.1
        if not bits:
            return None
        headline = "Command-and-control / exfiltration activity" if (ti or egress >= 10_000_000) else "Notable network activity"
        return self._finding(self.name, headline, "Network telemetry shows " + "; ".join(bits) + ".",
                             min(conf, 0.96), ids)


class FileAgent(BaseAgent):
    name = "file"
    focus = "file access, staging, encryption"

    def analyse(self, ctx: AgentContext) -> AgentFinding | None:
        files = ctx.by_type(EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_READ, EventType.FILE_DELETE)
        if not files:
            return None
        archives = [e for e in files if e.file_path and e.file_path.lower().endswith((".zip", ".7z", ".rar", ".tar.gz", ".tgz"))]
        encrypted = [e for e in files if e.file_path and any(e.file_path.lower().endswith(x) for x in (".locked", ".encrypted", ".lockbit", ".crypt"))]
        notes = [e for e in files if e.file_path and "restore" in e.file_path.lower() or (e.file_path and "decrypt" in e.file_path.lower())]
        sensitive = [e for e in files if e.file_path and any(k in e.file_path.lower() for k in ("finance", "payroll", "credentials", "id_rsa", "shadow", ".kdbx"))]
        bits = []
        ids: list[str] = []
        conf = 0.55
        if encrypted:
            bits.append(f"{len(encrypted)} file(s) with ransomware extensions")
            ids += [e.event_id for e in encrypted[:3]]
            conf += 0.3
        if notes:
            bits.append("a ransom note was dropped")
            ids += [e.event_id for e in notes[:1]]
            conf += 0.1
        if archives:
            big = max(archives, key=lambda e: e.file_size or 0)
            bits.append(f"data staged into archive {big.file_path.split(chr(92))[-1]} ({(big.file_size or 0) / 1e6:.0f} MB)")
            ids.append(big.event_id)
            conf += 0.15
        if sensitive:
            bits.append(f"access to sensitive path(s): {', '.join(sorted({e.file_path.split(chr(92))[-1] for e in sensitive})[:3])}")
            ids += [e.event_id for e in sensitive[:2]]
            conf += 0.1
        if not bits:
            return None
        return self._finding(self.name, "File-system activity of concern",
                             "File telemetry shows " + "; ".join(bits) + ".", min(conf, 0.96), ids)


ALL_AGENTS: list[BaseAgent] = [IdentityAgent(), ProcessAgent(), NetworkAgent(), FileAgent()]
