"""Rule loading and the three stateful rule types: match, threshold, sequence."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from aegis.detection.conditions import Condition
from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import SecurityEvent, Severity

SEVERITY_DEFAULT_SCORE = {
    Severity.INFO: 5,
    Severity.LOW: 15,
    Severity.MEDIUM: 30,
    Severity.HIGH: 50,
    Severity.CRITICAL: 75,
}


@dataclass
class RuleSpec:
    id: str
    title: str
    kind: str  # match | threshold | sequence
    severity: Severity
    score: float
    techniques: list[str]
    phase: str | None
    description: str = ""
    group_by: list[str] = field(default_factory=lambda: ["user"])
    window_seconds: int = 300
    where: dict[str, Any] | None = None
    count_gte: int = 1
    then: dict[str, Any] | None = None
    steps: list[dict[str, Any]] = field(default_factory=list)
    distinct: str | None = None  # threshold on distinct values of this field
    cooldown_seconds: int = 600
    confidence: float = 0.85
    tags: list[str] = field(default_factory=list)
    enabled: bool = True
    source_file: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any], source_file: str = "") -> RuleSpec:
        sev = Severity(d.get("severity", "medium"))
        return cls(
            id=d["id"],
            title=d["title"],
            kind=d.get("kind", "match"),
            severity=sev,
            score=float(d.get("score", SEVERITY_DEFAULT_SCORE[sev])),
            techniques=list(d.get("techniques", [])),
            phase=d.get("phase"),
            description=d.get("description", ""),
            group_by=list(d.get("group_by", ["user"])),
            window_seconds=int(d.get("window_seconds", 300)),
            where=d.get("where"),
            count_gte=int(d.get("count_gte", 1)),
            then=d.get("then"),
            steps=list(d.get("steps", [])),
            distinct=d.get("distinct"),
            cooldown_seconds=int(d.get("cooldown_seconds", 600)),
            confidence=float(d.get("confidence", 0.85)),
            tags=list(d.get("tags", [])),
            enabled=bool(d.get("enabled", True)),
            source_file=source_file,
        )


def load_rules(rules_dir: Path) -> list[RuleSpec]:
    specs: list[RuleSpec] = []
    for path in sorted(rules_dir.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            docs = yaml.safe_load(fh) or []
        if isinstance(docs, dict):
            docs = docs.get("rules", [docs])
        for d in docs:
            spec = RuleSpec.from_dict(d, source_file=path.name)
            if spec.enabled:
                specs.append(spec)
    return specs


def _group_key(spec: RuleSpec, event: SecurityEvent) -> str | None:
    parts = []
    for f in spec.group_by:
        v = getattr(event, f, None)
        if v is None:
            return None
        parts.append(str(v).lower())
    return "|".join(parts)


def _entities(spec: RuleSpec, events: list[SecurityEvent]) -> dict[str, str]:
    ents: dict[str, str] = {}
    for e in events:
        if e.user and "user" not in ents:
            ents["user"] = e.user
        if e.host and "host" not in ents:
            ents["host"] = e.host
        if e.dst_ip and "dst_ip" not in ents:
            ents["dst_ip"] = e.dst_ip
        if e.src_ip and "src_ip" not in ents:
            ents["src_ip"] = e.src_ip
        if e.domain and "domain" not in ents:
            ents["domain"] = e.domain
        if e.process_name and "process" not in ents:
            ents["process"] = e.process_name
        if e.session_id and "session" not in ents:
            ents["session"] = e.session_id
    return ents


class BaseRule:
    kind = DetectionKind.RULE

    def __init__(self, spec: RuleSpec):
        self.spec = spec
        self._last_fire: dict[str, datetime] = {}

    def _in_cooldown(self, key: str, ts: datetime) -> bool:
        last = self._last_fire.get(key)
        if last and (ts - last) < timedelta(seconds=self.spec.cooldown_seconds):
            return True
        self._last_fire[key] = ts
        return False

    def _detection(self, events: list[SecurityEvent], details: dict[str, Any] | None = None) -> Detection:
        last = events[-1]
        return Detection(
            tenant_id=last.tenant_id,
            kind=self.kind,
            rule_id=self.spec.id,
            title=self.spec.title,
            description=self.spec.description,
            severity=self.spec.severity,
            score=self.spec.score,
            confidence=self.spec.confidence,
            techniques=self.spec.techniques,
            phase=self.spec.phase,
            timestamp=last.timestamp,
            entities=_entities(self.spec, events),
            evidence_event_ids=[e.event_id for e in events],
            details={"rule_kind": self.spec.kind, **(details or {})},
        )

    def process(self, event: SecurityEvent) -> list[Detection]:  # pragma: no cover - abstract
        raise NotImplementedError

    def reset(self) -> None:
        self._last_fire.clear()


class MatchRule(BaseRule):
    kind = DetectionKind.RULE

    def __init__(self, spec: RuleSpec):
        super().__init__(spec)
        self.cond = Condition(spec.where)

    def process(self, event: SecurityEvent) -> list[Detection]:
        if not self.cond(event):
            return []
        key = _group_key(self.spec, event) or event.event_id
        if self._in_cooldown(key, event.timestamp):
            return []
        return [self._detection([event])]


class ThresholdRule(BaseRule):
    """N matching events within a window (optionally followed by a ``then`` event)."""

    kind = DetectionKind.THRESHOLD

    def __init__(self, spec: RuleSpec):
        super().__init__(spec)
        self.cond = Condition(spec.where)
        self.then = Condition(spec.then) if spec.then else None
        self.windows: dict[str, deque[SecurityEvent]] = defaultdict(deque)
        self.armed: dict[str, list[SecurityEvent]] = {}

    def _prune(self, dq: deque[SecurityEvent], now: datetime) -> None:
        horizon = now - timedelta(seconds=self.spec.window_seconds)
        while dq and dq[0].timestamp < horizon:
            dq.popleft()

    def _count(self, dq: deque[SecurityEvent]) -> int:
        if self.spec.distinct:
            return len({getattr(e, self.spec.distinct, None) for e in dq})
        return len(dq)

    def process(self, event: SecurityEvent) -> list[Detection]:
        key = _group_key(self.spec, event)
        if key is None:
            return []
        out: list[Detection] = []
        if self.then is not None and key in self.armed and self.then(event):
            seed = self.armed.pop(key)
            horizon = seed[0].timestamp + timedelta(seconds=self.spec.window_seconds)
            if event.timestamp <= horizon and not self._in_cooldown(key, event.timestamp):
                out.append(self._detection(seed + [event], {"count": len(seed), "followed_by": event.action}))
            return out
        if self.cond(event):
            dq = self.windows[key]
            dq.append(event)
            self._prune(dq, event.timestamp)
            if self._count(dq) >= self.spec.count_gte:
                evs = list(dq)
                dq.clear()
                if self.then is not None:
                    self.armed[key] = evs
                elif not self._in_cooldown(key, event.timestamp):
                    out.append(self._detection(evs, {"count": len(evs)}))
        return out

    def reset(self) -> None:
        super().reset()
        self.windows.clear()
        self.armed.clear()


class SequenceRule(BaseRule):
    """Ordered steps that must all occur, in order, inside ``window_seconds`` for one group."""

    kind = DetectionKind.SEQUENCE

    def __init__(self, spec: RuleSpec):
        super().__init__(spec)
        self.steps = [Condition(s) for s in spec.steps]
        if not self.steps:
            raise ValueError(f"sequence rule {spec.id} has no steps")
        # group -> list of partial matches [(events_so_far)]
        self.partials: dict[str, list[list[SecurityEvent]]] = defaultdict(list)

    def process(self, event: SecurityEvent) -> list[Detection]:
        key = _group_key(self.spec, event)
        if key is None:
            return []
        out: list[Detection] = []
        window = timedelta(seconds=self.spec.window_seconds)
        partials = self.partials[key]
        # drop expired
        partials[:] = [p for p in partials if event.timestamp - p[0].timestamp <= window]
        advanced: list[list[SecurityEvent]] = []
        completed = False
        for p in partials:
            idx = len(p)
            if idx < len(self.steps) and self.steps[idx](event):
                np = p + [event]
                if len(np) == len(self.steps):
                    if not self._in_cooldown(key, event.timestamp):
                        out.append(self._detection(np, {"steps": len(self.steps)}))
                    completed = True
                else:
                    advanced.append(np)
            else:
                advanced.append(p)
        if completed:
            advanced = [p for p in advanced if len(p) == 0]
        if self.steps[0](event) and not completed:
            advanced.append([event])
        # bound memory on hostile input
        self.partials[key] = advanced[-64:]
        return out

    def reset(self) -> None:
        super().reset()
        self.partials.clear()


def build_rule(spec: RuleSpec) -> BaseRule:
    if spec.kind == "match":
        return MatchRule(spec)
    if spec.kind == "threshold":
        return ThresholdRule(spec)
    if spec.kind == "sequence":
        return SequenceRule(spec)
    raise ValueError(f"unknown rule kind {spec.kind!r} in {spec.id}")
