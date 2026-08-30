"""IOC extraction from events and matching against the local store."""

from __future__ import annotations

from datetime import datetime, timedelta

from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import SecurityEvent, Severity
from aegis.threat_intel.store import IOC, IOCType, ThreatIntelStore

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}
_SCORE = {Severity.LOW: 20.0, Severity.MEDIUM: 35.0, Severity.HIGH: 55.0, Severity.CRITICAL: 75.0}
_PHASE = {
    IOCType.IP: "command_and_control",
    IOCType.CIDR: "command_and_control",
    IOCType.DOMAIN: "command_and_control",
    IOCType.URL: "initial_access",
    IOCType.HASH: "execution",
}
_TECH = {
    IOCType.IP: ["T1071.001"],
    IOCType.CIDR: ["T1071.001"],
    IOCType.DOMAIN: ["T1071.001", "T1568"],
    IOCType.URL: ["T1105", "T1566.002"],
    IOCType.HASH: ["T1204.002"],
}


class ThreatIntelMatcher:
    def __init__(self, store: ThreatIntelStore, cooldown_seconds: int = 900):
        self.store = store
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._last: dict[str, datetime] = {}

    @staticmethod
    def extract(event: SecurityEvent) -> list[tuple[IOCType, str]]:
        found: list[tuple[IOCType, str]] = []
        if event.dst_ip:
            found.append((IOCType.IP, event.dst_ip))
        if event.src_ip:
            found.append((IOCType.IP, event.src_ip))
        if event.domain:
            found.append((IOCType.DOMAIN, event.domain))
        if event.url:
            found.append((IOCType.URL, event.url))
            try:
                host = event.url.split("//", 1)[1].split("/", 1)[0]
                found.append((IOCType.DOMAIN, host))
            except IndexError:
                pass
        if event.file_hash:
            found.append((IOCType.HASH, event.file_hash))
        return found

    def _lookup(self, t: IOCType, v: str) -> IOC | None:
        if t == IOCType.IP:
            return self.store.lookup_ip(v)
        if t == IOCType.DOMAIN:
            return self.store.lookup_domain(v)
        if t == IOCType.URL:
            return self.store.lookup_url(v)
        if t == IOCType.HASH:
            return self.store.lookup_hash(v)
        return None

    def process(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        for t, v in self.extract(event):
            ioc = self._lookup(t, v)
            if ioc is None:
                continue
            key = f"{event.host}|{ioc.value}"
            last = self._last.get(key)
            if last and event.timestamp - last < self.cooldown:
                continue
            self._last[key] = event.timestamp
            sev = _SEV.get(ioc.severity, Severity.HIGH)
            out.append(
                Detection(
                    tenant_id=event.tenant_id,
                    kind=DetectionKind.THREAT_INTEL,
                    rule_id=f"TI-{ioc.type.value.upper()}",
                    title=f"Known malicious {ioc.type.value}: {ioc.threat}",
                    description=(
                        f"{v} matched indicator {ioc.value} from {ioc.source} "
                        f"(confidence {ioc.confidence:.0%})"
                    ),
                    severity=sev,
                    score=_SCORE[sev] * (0.7 + 0.3 * ioc.confidence),
                    confidence=ioc.confidence,
                    techniques=_TECH[ioc.type],
                    phase=_PHASE[ioc.type],
                    timestamp=event.timestamp,
                    entities={
                        k: val
                        for k, val in {
                            "user": event.user,
                            "host": event.host,
                            "dst_ip": event.dst_ip if t == IOCType.IP else None,
                            "domain": event.domain,
                        }.items()
                        if val
                    },
                    evidence_event_ids=[event.event_id],
                    details={
                        "ioc_value": ioc.value,
                        "ioc_type": ioc.type.value,
                        "source": ioc.source,
                        "threat": ioc.threat,
                        "tags": list(ioc.tags),
                        "reference": ioc.reference,
                    },
                )
            )
        return out
