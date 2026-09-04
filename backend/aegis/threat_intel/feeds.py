"""Parsers for public threat-intel feed formats plus an offline refresh script.

Supported formats (all free, no API key):

* **abuse.ch Feodo Tracker** ``ipblocklist.csv`` — botnet C2 IPs
* **abuse.ch URLhaus** ``urlhaus.csv`` — malware distribution URLs / hosts
* **abuse.ch ThreatFox** JSON export — mixed IOC types
* **Spamhaus DROP** ``drop.txt`` — hijacked netblocks (CIDR)
* **Aegis local** ``*.json`` — curated list in our own schema

``python -m aegis.threat_intel.feeds refresh`` downloads the live feeds into the data directory.
The repository ships with an offline snapshot so the platform runs with zero network access.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from aegis.threat_intel.store import IOC, IOCType

PUBLIC_FEEDS = {
    "feodo_ipblocklist.csv": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "urlhaus.csv": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox.json": "https://threatfox.abuse.ch/export/json/recent/",
    "spamhaus_drop.txt": "https://www.spamhaus.org/drop/drop.txt",
}


def _parse_feodo(path: Path) -> list[IOC]:
    out: list[IOC] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for row in csv.reader(line for line in fh if not line.startswith("#")):
            if len(row) < 3 or row[0] == "first_seen_utc":
                continue
            first_seen, ip, _port, *rest = row
            malware = rest[1] if len(rest) > 1 else "botnet C2"
            out.append(
                IOC(
                    value=ip,
                    type=IOCType.IP,
                    threat=f"{malware} C2",
                    source="abuse.ch Feodo Tracker",
                    confidence=0.9,
                    severity="critical",
                    first_seen=first_seen,
                    tags=("c2", "botnet"),
                )
            )
    return out


def _parse_urlhaus(path: Path) -> list[IOC]:
    out: list[IOC] = []
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for row in csv.reader(line for line in fh if not line.startswith("#")):
            if len(row) < 7 or row[0] == "id":
                continue
            _id, added, url, status, _last, threat, tags, *_ = row
            out.append(
                IOC(
                    value=url,
                    type=IOCType.URL,
                    threat=threat or "malware_download",
                    source="abuse.ch URLhaus",
                    confidence=0.85,
                    severity="high",
                    first_seen=added,
                    tags=tuple(t for t in tags.split(",") if t),
                )
            )
            try:
                host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
                if host and not host.replace(".", "").isdigit():
                    out.append(
                        IOC(
                            value=host,
                            type=IOCType.DOMAIN,
                            threat=threat or "malware_download",
                            source="abuse.ch URLhaus",
                            confidence=0.7,
                            severity="high",
                            first_seen=added,
                        )
                    )
            except IndexError:
                pass
    return out


def _parse_threatfox(path: Path) -> list[IOC]:
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    out: list[IOC] = []
    entries = data.values() if isinstance(data, dict) else data
    for group in entries:
        for e in group if isinstance(group, list) else [group]:
            ioc_type = e.get("ioc_type", "")
            value = e.get("ioc_value") or e.get("ioc", "")
            t: IOCType | None = None
            if ioc_type.startswith("ip"):
                value = value.split(":")[0]
                t = IOCType.IP
            elif ioc_type == "domain":
                t = IOCType.DOMAIN
            elif ioc_type == "url":
                t = IOCType.URL
            elif "hash" in ioc_type:
                t = IOCType.HASH
            if t and value:
                out.append(
                    IOC(
                        value=value,
                        type=t,
                        threat=e.get("malware_printable") or e.get("threat_type", "malware"),
                        source="abuse.ch ThreatFox",
                        confidence=float(e.get("confidence_level", 75)) / 100.0,
                        severity="high",
                        first_seen=e.get("first_seen_utc"),
                        tags=tuple(e.get("tags") or ()),
                        reference=e.get("reference"),
                    )
                )
    return out


def _parse_spamhaus(path: Path) -> list[IOC]:
    out: list[IOC] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";")[0].strip()
        sbl = line.split(";")[1].strip() if ";" in line else ""
        out.append(
            IOC(
                value=cidr,
                type=IOCType.CIDR,
                threat="Spamhaus DROP hijacked netblock",
                source="Spamhaus DROP",
                confidence=0.8,
                severity="high",
                reference=sbl or None,
                tags=("drop",),
            )
        )
    return out


def _parse_local_json(path: Path) -> list[IOC]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[IOC] = []
    for e in data:
        out.append(
            IOC(
                value=e["value"],
                type=IOCType(e["type"]),
                threat=e.get("threat", "malicious"),
                source=e.get("source", path.stem),
                confidence=float(e.get("confidence", 0.8)),
                severity=e.get("severity", "high"),
                first_seen=e.get("first_seen"),
                tags=tuple(e.get("tags", ())),
                reference=e.get("reference"),
                country=e.get("country"),
            )
        )
    return out


def load_feed_file(path: Path) -> list[IOC]:
    name = path.name.lower()
    try:
        if name.startswith("feodo"):
            return _parse_feodo(path)
        if name.startswith("urlhaus"):
            return _parse_urlhaus(path)
        if name.startswith("threatfox"):
            return _parse_threatfox(path)
        if name.startswith("spamhaus"):
            return _parse_spamhaus(path)
        if path.suffix == ".json":
            return _parse_local_json(path)
    except Exception as exc:  # feeds are untrusted input; never crash the platform on a bad file
        print(f"[threat_intel] failed to parse {path.name}: {exc}", file=sys.stderr)
    return []


def refresh(directory: Path) -> dict[str, int]:
    """Download the public feeds into ``directory``. Requires network access; safe to skip."""
    import httpx

    directory.mkdir(parents=True, exist_ok=True)
    results: dict[str, int] = {}
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "aegis-ti/0.1"}) as client:
        for filename, url in PUBLIC_FEEDS.items():
            try:
                r = client.get(url)
                r.raise_for_status()
                (directory / filename).write_bytes(r.content)
                results[filename] = len(load_feed_file(directory / filename))
            except Exception as exc:
                print(f"[threat_intel] {filename}: {exc}", file=sys.stderr)
                results[filename] = -1
    return results


if __name__ == "__main__":
    from aegis.config import get_settings

    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        print(json.dumps(refresh(get_settings().threat_intel_dir), indent=2))
    else:
        print("usage: python -m aegis.threat_intel.feeds refresh")
