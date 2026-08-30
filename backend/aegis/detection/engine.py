"""The detection engine: rules + statistical anomaly detectors + threat-intel matching.

Deterministic first, statistical second — the LLM is never in this loop.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path

from aegis.detection.anomaly import AnomalyEngine
from aegis.detection.rules import BaseRule, RuleSpec, build_rule, load_rules
from aegis.schemas.detections import Detection
from aegis.schemas.events import SecurityEvent
from aegis.threat_intel.matcher import ThreatIntelMatcher
from aegis.threat_intel.store import ThreatIntelStore


class DetectionEngine:
    def __init__(
        self,
        rules_dir: Path,
        ti_store: ThreatIntelStore | None = None,
        enable_anomaly: bool = True,
    ):
        self.specs: list[RuleSpec] = load_rules(rules_dir)
        self.rules: list[BaseRule] = [build_rule(s) for s in self.specs]
        self.anomaly = AnomalyEngine() if enable_anomaly else None
        self.ti = ThreatIntelMatcher(ti_store) if ti_store is not None else None
        self.stats: Counter[str] = Counter()
        self.events_seen = 0
        self._elapsed = 0.0

    # ------------------------------------------------------------------ processing
    def process(self, event: SecurityEvent) -> list[Detection]:
        t0 = time.perf_counter()
        out: list[Detection] = []
        for rule in self.rules:
            try:
                dets = rule.process(event)
            except Exception as exc:  # a broken rule must never take down the pipeline
                self.stats[f"rule_error:{rule.spec.id}"] += 1
                dets = []
                if self.stats[f"rule_error:{rule.spec.id}"] == 1:
                    import logging

                    logging.getLogger(__name__).warning("rule %s failed: %s", rule.spec.id, exc)
            out.extend(dets)
        if self.anomaly is not None:
            out.extend(self.anomaly.process(event))
        if self.ti is not None:
            out.extend(self.ti.process(event))
        for d in out:
            self.stats[d.rule_id] += 1
        self.events_seen += 1
        self._elapsed += time.perf_counter() - t0
        return out

    def process_many(self, events: list[SecurityEvent]) -> list[Detection]:
        out: list[Detection] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            out.extend(self.process(e))
        return out

    def reset_state(self) -> None:
        for r in self.rules:
            r.reset()
        if self.anomaly is not None:
            self.anomaly = AnomalyEngine()

    # ------------------------------------------------------------------ introspection
    def rule_catalog(self) -> list[dict]:
        return [
            {
                "id": s.id,
                "title": s.title,
                "kind": s.kind,
                "severity": s.severity.value,
                "score": s.score,
                "techniques": s.techniques,
                "phase": s.phase,
                "description": s.description,
                "group_by": s.group_by,
                "window_seconds": s.window_seconds,
                "source_file": s.source_file,
                "fired": self.stats.get(s.id, 0),
            }
            for s in self.specs
        ]

    def techniques_by_rule(self) -> dict[str, list[str]]:
        m = {s.id: s.techniques for s in self.specs}
        m.update(
            {
                "ANOM-LOGIN-HOUR": ["T1078"],
                "ANOM-LOGIN-LOCATION": ["T1078", "T1133"],
                "ANOM-EGRESS-VOLUME": ["T1048", "T1041"],
                "ANOM-RARE-PROCESS": ["T1204"],
                "ANOM-DNS-ENTROPY": ["T1071.004", "T1568.002"],
                "ANOM-DNS-BURST": ["T1071.004"],
                "TI-IP": ["T1071.001"],
                "TI-DOMAIN": ["T1071.001", "T1568"],
                "TI-URL": ["T1105", "T1566.002"],
                "TI-HASH": ["T1204.002"],
            }
        )
        return m

    def metrics(self) -> dict:
        return {
            "events_processed": self.events_seen,
            "avg_latency_us": round(self._elapsed / self.events_seen * 1e6, 1) if self.events_seen else 0.0,
            "rules_loaded": len(self.rules),
            "detections_by_rule": dict(self.stats),
            "anomaly_baselines": self.anomaly.snapshot() if self.anomaly else {},
        }
