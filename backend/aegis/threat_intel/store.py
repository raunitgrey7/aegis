"""Local threat-intelligence store.

Indicators come from *public* feeds cached on disk (abuse.ch Feodo Tracker, URLhaus, ThreatFox exports,
Spamhaus DROP, plus a curated local list). No commercial API is ever called. ``feeds.py`` knows how to
parse each public format; the store only cares about normalised ``IOC`` records.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CIDR = "cidr"


@dataclass(frozen=True)
class IOC:
    value: str
    type: IOCType
    threat: str  # e.g. "Cobalt Strike C2", "Emotet", "TOR exit"
    source: str  # feed name
    confidence: float = 0.8  # 0..1
    severity: str = "high"
    first_seen: str | None = None
    tags: tuple[str, ...] = ()
    reference: str | None = None


@dataclass
class ThreatIntelStore:
    ips: dict[str, IOC] = field(default_factory=dict)
    domains: dict[str, IOC] = field(default_factory=dict)
    hashes: dict[str, IOC] = field(default_factory=dict)
    urls: dict[str, IOC] = field(default_factory=dict)
    cidrs: list[tuple[int, int, IOC]] = field(default_factory=list)  # (network_int, mask_int, ioc)
    loaded_feeds: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------ mutation
    def add(self, ioc: IOC) -> None:
        v = ioc.value.strip().lower()
        if ioc.type == IOCType.IP:
            self.ips[v] = ioc
        elif ioc.type == IOCType.DOMAIN:
            self.domains[v.rstrip(".")] = ioc
        elif ioc.type == IOCType.HASH:
            self.hashes[v] = ioc
        elif ioc.type == IOCType.URL:
            self.urls[v] = ioc
        elif ioc.type == IOCType.CIDR:
            import ipaddress

            net = ipaddress.ip_network(v, strict=False)
            self.cidrs.append((int(net.network_address), int(net.netmask), ioc))

    def add_many(self, iocs: list[IOC], feed_name: str) -> None:
        for i in iocs:
            self.add(i)
        self.loaded_feeds.append({"feed": feed_name, "count": len(iocs), "loaded_at": datetime.now(UTC).isoformat()})

    # ------------------------------------------------------------------ lookup
    def lookup_ip(self, ip: str | None) -> IOC | None:
        if not ip:
            return None
        hit = self.ips.get(ip)
        if hit:
            return hit
        if self.cidrs:
            import ipaddress

            try:
                x = int(ipaddress.ip_address(ip))
            except ValueError:
                return None
            for net, mask, ioc in self.cidrs:
                if x & mask == net:
                    return ioc
        return None

    def lookup_domain(self, domain: str | None) -> IOC | None:
        if not domain:
            return None
        d = domain.lower().rstrip(".")
        # exact then parent-domain walk (evil.example.com -> example.com)
        labels = d.split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            hit = self.domains.get(cand)
            if hit:
                return hit
        return None

    def lookup_hash(self, h: str | None) -> IOC | None:
        return self.hashes.get(h.lower()) if h else None

    def lookup_url(self, url: str | None) -> IOC | None:
        return self.urls.get(url.lower()) if url else None

    def stats(self) -> dict:
        return {
            "ips": len(self.ips),
            "domains": len(self.domains),
            "hashes": len(self.hashes),
            "urls": len(self.urls),
            "cidrs": len(self.cidrs),
            "feeds": self.loaded_feeds,
        }

    # ------------------------------------------------------------------ persistence
    @classmethod
    def from_directory(cls, directory: Path) -> ThreatIntelStore:
        from aegis.threat_intel.feeds import load_feed_file

        store = cls()
        if not directory.exists():
            return store
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() in {".csv", ".json", ".txt"}:
                iocs = load_feed_file(path)
                store.add_many(iocs, path.name)
        return store

    def export_json(self, path: Path) -> None:
        data = [i.__dict__ | {"type": i.type.value, "tags": list(i.tags)} for i in self.all()]
        path.write_text(json.dumps(data, indent=2))

    def all(self) -> list[IOC]:
        return [*self.ips.values(), *self.domains.values(), *self.hashes.values(), *self.urls.values()]

    def to_csv(self, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["value", "type", "threat", "source", "confidence", "severity"])
            for i in self.all():
                w.writerow([i.value, i.type.value, i.threat, i.source, i.confidence, i.severity])
