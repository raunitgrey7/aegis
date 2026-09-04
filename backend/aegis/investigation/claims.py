"""Claim Verifier — semantic fact-checking of the AI narrative against the deterministic record.

Reference integrity (``grounding.py``) proves that cited event IDs *exist*. It does NOT prove that what
the narrative *says about them* is true: a model can cite three real events and invent their meaning.
This module closes that gap for everything machine-checkable:

* **Entities** — every IP, hostname, domain, process and user the narrative names must appear in the
  incident's evidence. A named entity that is not in the evidence is an unsupported claim.
* **Techniques** — every ATT&CK ID the narrative asserts must be carried by a deterministic detection.
* **Phases** — every kill-chain phase the narrative asserts ("exfiltration", "lateral movement", ...)
  must be present in the incident's detection record. Negated mentions ("no exfiltration observed") are
  recognised and skipped.

What this still cannot do — and the UI must say so — is verify *causal interpretation* ("A led to B").
That remains the analyst's job. The honest guarantee is: the narrative names nothing the deterministic
layer did not observe, and asserts no technique or phase the detectors did not raise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.schemas.events import SecurityEvent
from aegis.schemas.incidents import Incident

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
HOST_RE = re.compile(r"\b(?!SEC-)[A-Z]{2,5}-\d{2,4}\b")
PROC_RE = re.compile(r"\b[\w.-]+\.(?:exe|dll|ps1|vbs|bat|sh)\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|xyz|top|nz|sh|info|co|app|dev|cloud|local|biz|me|cc|tk)\b",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(r"\b(no|not|without|never|absence of|neither|nor|didn't|did not|wasn't|was not)\b", re.IGNORECASE)

# narrative vocabulary -> kill-chain phase it asserts
PHASE_LEXICON: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bexfiltrat\w*|data (?:was )?(?:stolen|transferred out|uploaded externally)", re.I), "exfiltration"),
    (re.compile(r"\blateral(?:ly)? mov\w*|moved laterally|pivot(?:ed|ing)?\b", re.I), "lateral_movement"),
    (re.compile(r"\bpersist\w*|backdoor account|scheduled task|run key", re.I), "persistence"),
    (re.compile(r"\bprivilege[s]? (?:escalat\w*|elevat\w*)|escalated (?:its |their )?privileges|uac bypass", re.I), "privilege_escalation"),
    (re.compile(r"\bcredential (?:dump\w*|theft|access|harvest\w*)|dumped (?:credentials|lsass)|mimikatz|password spray\w*|brute[- ]forc\w*", re.I), "credential_access"),
    (re.compile(r"\bransom\w*|encrypt(?:ed|ing) files|mass encryption|shadow cop(?:y|ies) deleted|wiped", re.I), "impact"),
    (re.compile(r"\bcommand[- ]and[- ]control|\bc2\b|beacon\w*|callback to", re.I), "command_and_control"),
    (re.compile(r"\breconnaissance|enumerat\w*|discover(?:y|ed) (?:the )?(?:domain|hosts|accounts|network)", re.I), "discovery"),
    (re.compile(r"\bstaged (?:data|an archive|into)|archived? (?:the |sensitive )?(?:data|files)|collected (?:data|files)", re.I), "collection"),
    (re.compile(r"\bdefen[cs]e evasion|disabled (?:defender|antivirus|av|logging)|cleared (?:the )?(?:event )?logs", re.I), "defense_evasion"),
]

PHASE_ALIASES = {"c2": "command_and_control", "cnc": "command_and_control"}


@dataclass
class Claim:
    kind: str  # ip | host | domain | process | user | technique | phase
    value: str
    supported: bool
    note: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "supported": self.supported, "note": self.note}


@dataclass
class EvidenceVocabulary:
    ips: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    technique_parents: set[str] = field(default_factory=set)
    phases: set[str] = field(default_factory=set)

    @classmethod
    def from_incident(cls, incident: Incident, events: list[SecurityEvent]) -> EvidenceVocabulary:
        v = cls()
        for e in events:
            for ip in (e.src_ip, e.dst_ip):
                if ip:
                    v.ips.add(ip)
            if e.host:
                v.hosts.add(e.host.upper())
            if e.user:
                v.users.add(e.user.lower())
            if e.target_user:
                v.users.add(e.target_user.lower())
            if e.domain:
                v.domains.add(e.domain.lower())
            if e.url:
                try:
                    v.domains.add(e.url.split("//", 1)[1].split("/", 1)[0].lower())
                except IndexError:
                    pass
            for p in (e.process_name, e.parent_process_name):
                if p:
                    v.processes.add(p.lower())
            if e.file_path:
                v.files.add(e.file_path.replace("\\", "/").rsplit("/", 1)[-1].lower())
        v.hosts.update(h.upper() for h in incident.affected_hosts)
        v.users.update(u.lower() for u in incident.affected_users)
        v.ips.update(incident.external_ips)
        v.domains.update(d.lower() for d in incident.domains)
        for t in incident.techniques:
            v.techniques.add(t)
            v.technique_parents.add(t.split(".")[0])
        for d in incident.detections:
            for t in d.techniques:
                v.techniques.add(t)
                v.technique_parents.add(t.split(".")[0])
            if d.phase:
                v.phases.add(d.phase)
        v.phases.update(incident.present_phases)
        return v


def _negated(text: str, start: int, window: int = 60) -> bool:
    """True if a negation word appears shortly before ``start`` in the same sentence."""
    ctx = text[max(0, start - window) : start]
    ctx = ctx.rsplit(".", 1)[-1]  # same sentence only
    return bool(NEGATION_RE.search(ctx))


def verify_claims(narrative: str, incident: Incident, events: list[SecurityEvent]) -> dict:
    """Fact-check every machine-checkable assertion in ``narrative`` against the evidence."""
    vocab = EvidenceVocabulary.from_incident(incident, events)
    text = narrative or ""
    claims: list[Claim] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, supported: bool, note: str = "") -> None:
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        claims.append(Claim(kind, value, supported, note))

    for m in IP_RE.finditer(text):
        ip = m.group(0)
        if all(0 <= int(o) <= 255 for o in ip.split(".")):
            add("ip", ip, ip in vocab.ips, "" if ip in vocab.ips else "IP not present in any cited event")

    for m in TECH_RE.finditer(text):
        t = m.group(0)
        ok = t in vocab.techniques or t.split(".")[0] in vocab.technique_parents
        add("technique", t, ok, "" if ok else "technique not raised by any detection")

    for m in HOST_RE.finditer(text):
        h = m.group(0).upper()
        add("host", h, h in vocab.hosts, "" if h in vocab.hosts else "host not present in evidence")

    for m in PROC_RE.finditer(text):
        p = m.group(0).lower()
        ok = p in vocab.processes or p in vocab.files
        add("process", p, ok, "" if ok else "process/file not present in evidence")

    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        if IP_RE.fullmatch(d):
            continue
        ok = d in vocab.domains or any(d.endswith("." + k) or k.endswith("." + d) for k in vocab.domains)
        add("domain", d, ok, "" if ok else "domain not present in evidence")

    # users: we can only positively confirm known users (any word could be a name)
    lowered = text.lower()
    for u in vocab.users:
        if re.search(rf"\b{re.escape(u)}\b", lowered):
            add("user", u, True)

    for rx, phase in PHASE_LEXICON:
        for m in rx.finditer(text):
            if _negated(text, m.start()):
                continue
            ok = phase in vocab.phases
            add("phase", phase, ok, "" if ok else f"narrative asserts '{phase}' but no detection raised that phase")
            break  # one claim per phase

    supported = [c for c in claims if c.supported]
    unsupported = [c for c in claims if not c.supported]
    total = len(claims)
    return {
        "method": (
            "entity + technique + kill-chain-phase fact-check of the narrative against deterministic "
            "detections and cited events; negated mentions are ignored. Does NOT verify causal interpretation."
        ),
        "claims": [c.to_dict() for c in claims],
        "total": total,
        "supported": len(supported),
        "unsupported": len(unsupported),
        "unsupported_claims": [c.to_dict() for c in unsupported],
        "fidelity": round(len(supported) / total, 3) if total else 1.0,
        "verified": len(unsupported) == 0,
    }
