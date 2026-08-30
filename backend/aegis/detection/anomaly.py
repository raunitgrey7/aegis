"""Statistical anomaly detection.

Baselines are learned online from benign history. Each detector is deliberately simple, explainable
and cheap: circular-hour histograms, first-seen sets, robust z-scores (median / MAD), and rarity counts.
An analyst can always see *why* something is anomalous — there are no opaque models here.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

from aegis.detection.conditions import is_private_ip, shannon_entropy
from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import EventType, SecurityEvent, Severity


def _det(
    rule_id: str,
    title: str,
    event: SecurityEvent,
    score: float,
    severity: Severity,
    techniques: list[str],
    phase: str | None,
    details: dict,
    confidence: float = 0.7,
) -> Detection:
    return Detection(
        tenant_id=event.tenant_id,
        kind=DetectionKind.ANOMALY,
        rule_id=rule_id,
        title=title,
        description=details.pop("reason", ""),
        severity=severity,
        score=round(min(100.0, score), 1),
        confidence=confidence,
        techniques=techniques,
        phase=phase,
        timestamp=event.timestamp,
        entities={k: v for k, v in {"user": event.user, "host": event.host, "dst_ip": event.dst_ip}.items() if v},
        evidence_event_ids=[event.event_id],
        details=details,
    )


@dataclass
class LoginHourBaseline:
    """Circular hour-of-day histogram per user. Flags logins in hours the user essentially never uses."""

    min_history: int = 12
    rarity_threshold: float = 0.03
    hist: dict[str, np.ndarray] = field(default_factory=lambda: defaultdict(lambda: np.zeros(24)))

    def observe(self, event: SecurityEvent) -> Detection | None:
        if event.event_type != EventType.AUTHENTICATION or event.action != "login_success" or not event.user:
            return None
        user = event.user.lower()
        h = self.hist[user]
        total = h.sum()
        hour = event.timestamp.hour
        det = None
        if total >= self.min_history:
            # smooth with neighbouring hours so 08:55 vs 09:05 doesn't trip
            kernel = (h[(hour - 1) % 24] * 0.5 + h[hour] + h[(hour + 1) % 24] * 0.5) / (total * 2.0)
            if kernel < self.rarity_threshold:
                rarity = 1.0 - kernel / self.rarity_threshold
                busiest = int(h.argmax())
                det = _det(
                    "ANOM-LOGIN-HOUR",
                    "Authentication outside the user's normal hours",
                    event,
                    score=25 + 20 * rarity,
                    severity=Severity.MEDIUM,
                    techniques=["T1078"],
                    phase="initial_access",
                    details={
                        "reason": (
                            f"{event.user} has {int(total)} historical logins, "
                            f"{kernel * 100:.1f}% around {hour:02d}:00 (peak hour {busiest:02d}:00)"
                        ),
                        "hour": hour,
                        "history": int(total),
                        "share_pct": round(kernel * 100, 2),
                    },
                )
        h[hour] += 1
        return det


@dataclass
class FirstSeenBaseline:
    """Per-user set of previously seen source IPs / countries for successful logins."""

    min_history: int = 5
    seen_ip: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    seen_country: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    logins: Counter = field(default_factory=Counter)

    def observe(self, event: SecurityEvent) -> Detection | None:
        if event.event_type != EventType.AUTHENTICATION or event.action != "login_success" or not event.user:
            return None
        user = event.user.lower()
        det = None
        n = self.logins[user]
        new_country = event.geo_country and n >= self.min_history and event.geo_country not in self.seen_country[user]
        new_public_ip = (
            event.src_ip
            and not is_private_ip(event.src_ip)
            and n >= self.min_history
            and event.src_ip not in self.seen_ip[user]
        )
        if new_country or new_public_ip:
            score = 45.0 if new_country else 30.0
            det = _det(
                "ANOM-LOGIN-LOCATION",
                "Login from a never-before-seen location",
                event,
                score=score,
                severity=Severity.MEDIUM,
                techniques=["T1078", "T1133"],
                phase="initial_access",
                details={
                    "reason": (
                        f"{event.user} has never authenticated from "
                        f"{event.geo_country or event.src_ip} (known: {sorted(self.seen_country[user])[:5]})"
                    ),
                    "new_country": event.geo_country if new_country else None,
                    "new_ip": event.src_ip if new_public_ip else None,
                },
                confidence=0.75,
            )
        if event.src_ip:
            self.seen_ip[user].add(event.src_ip)
        if event.geo_country:
            self.seen_country[user].add(event.geo_country)
        self.logins[user] += 1
        return det


@dataclass
class VolumeBaseline:
    """Robust z-score (median/MAD) on outbound bytes per host. Flags large external transfers."""

    min_history: int = 20
    z_threshold: float = 3.5
    history: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    max_history: int = 2000
    SANCTIONED = (
        "onedrive.live.com", "sharepoint.com", "office365.com", "microsoftonline.com",
        "googleapis.com", "drive.google.com", "docs.google.com", "dropbox.com", "box.com",
        "amazonaws.com", "blob.core.windows.net", "icloud.com",
    )

    def observe(self, event: SecurityEvent) -> Detection | None:
        if event.event_type != EventType.NETWORK_CONNECTION or not event.bytes_out or not event.host:
            return None
        if event.domain and event.domain.lower().endswith(self.SANCTIONED):
            self.history[event.host.upper()].append(math.log1p(event.bytes_out))
            return None
        host = event.host.upper()
        hist = self.history[host]
        det = None
        x = math.log1p(event.bytes_out)
        if len(hist) >= self.min_history and not is_private_ip(event.dst_ip):
            arr = np.asarray(hist)
            med = float(np.median(arr))
            mad = float(np.median(np.abs(arr - med))) or 0.35
            z = 0.6745 * (x - med) / mad
            if z >= self.z_threshold:
                det = _det(
                    "ANOM-EGRESS-VOLUME",
                    "Outbound data volume far above host baseline",
                    event,
                    score=min(70.0, 35 + 6.0 * (z - self.z_threshold)),
                    severity=Severity.HIGH,
                    techniques=["T1048", "T1041"],
                    phase="exfiltration",
                    details={
                        "reason": (
                            f"{event.host} sent {event.bytes_out:,} bytes to {event.dst_ip}; "
                            f"robust z-score {z:.1f} vs baseline median {math.expm1(med):,.0f} bytes"
                        ),
                        "z_score": round(z, 2),
                        "baseline_median_bytes": int(math.expm1(med)),
                    },
                    confidence=0.8,
                )
        hist.append(x)
        if len(hist) > self.max_history:
            del hist[: len(hist) - self.max_history]
        return det


@dataclass
class ProcessRarityBaseline:
    """Flags processes never before seen on a host *and* rare across the organisation."""

    min_host_history: int = 40
    org_rarity_max: int = 2
    host_procs: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    org_procs: Counter = field(default_factory=Counter)
    hosts_seen: Counter = field(default_factory=Counter)

    SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrord32.exe"}

    def observe(self, event: SecurityEvent) -> Detection | None:
        if event.event_type != EventType.PROCESS_START or not event.host or not event.process_name:
            return None
        host = event.host.upper()
        proc = event.process_name.lower()
        det = None
        if self.hosts_seen[host] >= self.min_host_history and self.host_procs[host][proc] == 0:
            org_count = self.org_procs[proc]
            if org_count <= self.org_rarity_max:
                parent = (event.parent_process_name or "").lower()
                bonus = 15 if parent in self.SUSPICIOUS_PARENTS else 0
                det = _det(
                    "ANOM-RARE-PROCESS",
                    "Rare process executed for the first time on host",
                    event,
                    score=20 + bonus,
                    severity=Severity.MEDIUM if bonus else Severity.LOW,
                    techniques=["T1204"],
                    phase="execution",
                    details={
                        "reason": (
                            f"{event.process_name} has never run on {event.host} and is seen on "
                            f"{org_count} other host(s) org-wide"
                        ),
                        "org_hosts": org_count,
                        "parent": event.parent_process_name,
                    },
                    confidence=0.6,
                )
        if self.host_procs[host][proc] == 0:
            self.org_procs[proc] += 1
        self.host_procs[host][proc] += 1
        self.hosts_seen[host] += 1
        return det


@dataclass
class DnsEntropyBaseline:
    """DGA / tunnelling heuristic: high-entropy or very long labels, and query-rate bursts per host."""

    entropy_threshold: float = 3.9
    label_len_threshold: int = 40
    burst_window_s: int = 60
    burst_count: int = 40
    recent: dict[str, list[datetime]] = field(default_factory=lambda: defaultdict(list))
    fired_burst: dict[str, datetime] = field(default_factory=dict)

    def observe(self, event: SecurityEvent) -> Detection | None:
        if event.event_type != EventType.DNS_QUERY or not event.domain:
            return None
        labels = event.domain.lower().split(".")
        sub = labels[0] if len(labels) > 2 else ""
        ent = shannon_entropy(sub) if sub else 0.0
        if sub and (ent >= self.entropy_threshold and len(sub) >= 12 or len(sub) >= self.label_len_threshold):
            return _det(
                "ANOM-DNS-ENTROPY",
                "High-entropy DNS label (possible DGA or DNS tunnelling)",
                event,
                score=35.0,
                severity=Severity.MEDIUM,
                techniques=["T1071.004", "T1568.002"],
                phase="command_and_control",
                details={
                    "reason": f"subdomain label {sub[:48]!r} has entropy {ent:.2f} and length {len(sub)}",
                    "entropy": round(ent, 2),
                    "label_len": len(sub),
                },
                confidence=0.7,
            )
        if event.host:
            host = event.host.upper()
            lst = self.recent[host]
            lst.append(event.timestamp)
            cutoff = event.timestamp.timestamp() - self.burst_window_s
            self.recent[host] = lst = [t for t in lst if t.timestamp() >= cutoff]
            last = self.fired_burst.get(host)
            if len(lst) >= self.burst_count and (last is None or (event.timestamp - last).total_seconds() > 600):
                self.fired_burst[host] = event.timestamp
                return _det(
                    "ANOM-DNS-BURST",
                    "DNS query burst from a single host",
                    event,
                    score=30.0,
                    severity=Severity.MEDIUM,
                    techniques=["T1071.004"],
                    phase="command_and_control",
                    details={"reason": f"{len(lst)} DNS queries in {self.burst_window_s}s from {event.host}"},
                    confidence=0.65,
                )
        return None


class AnomalyEngine:
    def __init__(self) -> None:
        self.detectors = [
            LoginHourBaseline(),
            FirstSeenBaseline(),
            VolumeBaseline(),
            ProcessRarityBaseline(),
            DnsEntropyBaseline(),
        ]

    def process(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        for d in self.detectors:
            det = d.observe(event)
            if det is not None:
                out.append(det)
        return out

    def snapshot(self) -> dict[str, int]:
        return {
            "users_with_login_baseline": len(self.detectors[0].hist),
            "hosts_with_volume_baseline": len(self.detectors[2].history),
            "processes_known": len(self.detectors[3].org_procs),
        }
