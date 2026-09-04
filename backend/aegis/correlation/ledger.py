"""Risk Ledger — entity-anchored risk that accumulates and decays over long horizons.

Window-based correlation (``CorrelationEngine.cluster``) answers "did these signals happen together?".
A patient adversary defeats it by spacing actions days apart, each one too weak to admit on its own.
The ledger answers a different question: "has this identity or host been quietly accruing risk?"

Every detection deposits risk on each entity it touches. Deposits decay exponentially (configurable
half-life), so one odd login is forgotten in a week — but a run-key here, a dyn-DNS lookup two days
later and a staged archive the day after that *compound*. When an entity's decayed balance crosses the
threshold, the ledger emits a **slow-burn incident** built from the contributing detections, regardless
of how far apart they are in time. This is the mechanism that catches low-and-slow / living-off-the-land
campaigns that never cluster into a tidy chain.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from aegis.schemas.detections import Detection, DetectionKind

KIND_WEIGHT = {
    DetectionKind.RULE: 1.0,
    DetectionKind.THRESHOLD: 1.0,
    DetectionKind.SEQUENCE: 1.1,
    DetectionKind.THREAT_INTEL: 1.0,
    DetectionKind.ANOMALY: 0.6,  # weak signals count, but less
}


@dataclass
class Deposit:
    timestamp: datetime
    detection_id: str
    amount: float
    rule_id: str


@dataclass
class LedgerEntry:
    entity: str
    balance: float = 0.0
    updated: datetime | None = None
    deposits: list[Deposit] = field(default_factory=list)
    first_seen: datetime | None = None
    peak: float = 0.0

    def decayed_balance(self, now: datetime, half_life: timedelta) -> float:
        if self.updated is None or self.balance <= 0:
            return 0.0
        dt = (now - self.updated).total_seconds()
        if dt <= 0:
            return self.balance
        return self.balance * math.pow(0.5, dt / half_life.total_seconds())


class RiskLedger:
    def __init__(
        self,
        half_life_hours: float = 96.0,
        threshold: float = 80.0,
        lookback_days: float = 30.0,
        min_deposits: int = 2,
        min_span_seconds: float = 3600.0,
    ):
        self.half_life = timedelta(hours=half_life_hours)
        self.threshold = threshold
        self.lookback = timedelta(days=lookback_days)
        self.min_deposits = min_deposits
        self.min_span = timedelta(seconds=min_span_seconds)
        self.entries: dict[str, LedgerEntry] = {}
        self._seen: set[str] = set()
        self.emitted: dict[str, dict] = {}  # entity -> sticky slow-burn group
        self.stats: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ deposits
    def observe(self, det: Detection) -> None:
        if det.detection_id in self._seen:
            return
        self._seen.add(det.detection_id)
        amount = det.score * KIND_WEIGHT.get(det.kind, 1.0) * (0.6 + 0.4 * det.confidence)
        for key in det.entity_keys():
            if key.startswith("ip:") or key.startswith("session:"):
                continue  # anchor on identities and hosts only
            entry = self.entries.get(key)
            if entry is None:
                entry = LedgerEntry(entity=key, first_seen=det.timestamp)
                self.entries[key] = entry
            entry.balance = entry.decayed_balance(det.timestamp, self.half_life) + amount
            entry.updated = det.timestamp if entry.updated is None else max(entry.updated, det.timestamp)
            entry.peak = max(entry.peak, entry.balance)
            entry.deposits.append(Deposit(det.timestamp, det.detection_id, amount, det.rule_id))
            # bound memory
            horizon = det.timestamp - self.lookback
            entry.deposits = [d for d in entry.deposits if d.timestamp >= horizon][-500:]
            self.stats["deposits"] += 1

    def observe_many(self, dets: list[Detection]) -> None:
        for d in sorted(dets, key=lambda x: x.timestamp):
            self.observe(d)

    # ------------------------------------------------------------------ queries
    def balance(self, entity: str, now: datetime) -> float:
        e = self.entries.get(entity)
        return e.decayed_balance(now, self.half_life) if e else 0.0

    def hot_entities(self, now: datetime) -> list[tuple[str, float, LedgerEntry]]:
        out = []
        for key, e in self.entries.items():
            b = e.decayed_balance(now, self.half_life)
            if b >= self.threshold:
                out.append((key, b, e))
        out.sort(key=lambda t: -t[1])
        return out

    def contributing(self, entity: str, now: datetime) -> list[Deposit]:
        e = self.entries.get(entity)
        if not e:
            return []
        horizon = now - self.lookback
        return [d for d in e.deposits if d.timestamp >= horizon]

    def slow_burn_candidates(self, now: datetime) -> list[dict]:
        """Entities whose accumulated risk crossed the threshold via *spread-out* deposits.

        Emitted groups are *sticky*: once an entity has crossed the line the incident persists across
        re-correlation even after its balance decays — an intrusion does not un-happen because the
        attacker went quiet. New deposits extend the sticky group.
        """
        cands: dict[str, dict] = {}
        for entity, info in self.emitted.items():
            cands[entity] = dict(info)
        for key, bal, entry in self.hot_entities(now):
            deps = self.contributing(key, now)
            if len(deps) < self.min_deposits:
                continue
            span = max(d.timestamp for d in deps) - min(d.timestamp for d in deps)
            if span < self.min_span:
                continue  # everything happened at once — the window correlator owns that
            ids = [d.detection_id for d in deps]
            prev = cands.get(key)
            if prev:
                ids = list(dict.fromkeys(prev["detection_ids"] + ids))
            cands[key] = {
                "entity": key,
                "balance": round(max(bal, prev["balance"] if prev else 0.0), 1),
                "peak": round(entry.peak, 1),
                "span_hours": round(span.total_seconds() / 3600, 1),
                "detection_ids": ids,
                "rules": sorted({d.rule_id for d in deps} | set(prev["rules"] if prev else [])),
                "first_seen": min(d.timestamp for d in deps),
                "last_seen": max(d.timestamp for d in deps),
            }
        return list(cands.values())

    def mark_emitted(self, entity: str, info: dict) -> None:
        if entity not in self.emitted:
            self.stats["slow_burn_incidents"] += 1
        self.emitted[entity] = dict(info)

    def snapshot(self, now: datetime, top: int = 20) -> dict:
        rows = []
        for key, e in self.entries.items():
            b = e.decayed_balance(now, self.half_life)
            if b > 0.5:
                rows.append({
                    "entity": key,
                    "balance": round(b, 1),
                    "peak": round(e.peak, 1),
                    "deposits": len(e.deposits),
                    "hot": b >= self.threshold,
                    "last_update": e.updated.isoformat() if e.updated else None,
                })
        rows.sort(key=lambda r: -r["balance"])
        return {
            "half_life_hours": self.half_life.total_seconds() / 3600,
            "threshold": self.threshold,
            "entities_tracked": len(self.entries),
            "hot": sum(1 for r in rows if r["hot"]),
            "top": rows[:top],
            "stats": dict(self.stats),
        }
