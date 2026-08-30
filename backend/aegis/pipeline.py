"""The Aegis processing pipeline — one object that owns every engine.

    events -> normalise -> detection (rules / anomaly / TI) -> knowledge graph
           -> correlation -> attack graph -> risk scoring -> incidents -> (AI investigation on demand)

``Platform`` is intentionally synchronous and side-effect free apart from its own state, so the same
code path serves the evaluation harness, unit tests, the stream worker and the API.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aegis.config import Settings, get_settings
from aegis.correlation.engine import CorrelationEngine
from aegis.detection.engine import DetectionEngine
from aegis.graph.knowledge_graph import SecurityKnowledgeGraph
from aegis.mitre.catalog import MitreCatalog
from aegis.schemas.detections import Detection
from aegis.schemas.events import SecurityEvent
from aegis.schemas.incidents import Incident
from aegis.threat_intel.store import ThreatIntelStore


@dataclass
class PlatformStats:
    events_ingested: int = 0
    events_deduplicated: int = 0
    detections: int = 0
    incidents: int = 0
    last_event_at: datetime | None = None
    started_at: float = field(default_factory=time.time)


class Platform:
    """In-memory security analytics core with bounded event retention."""

    def __init__(
        self,
        settings: Settings | None = None,
        rules_dir: Path | None = None,
        ti_dir: Path | None = None,
        max_events: int = 500_000,
        enable_anomaly: bool = True,
    ):
        self.settings = settings or get_settings()
        self.ti_store = ThreatIntelStore.from_directory(ti_dir or self.settings.threat_intel_dir)
        self.catalog = MitreCatalog.load(self.settings.mitre_catalog)
        self.detector = DetectionEngine(rules_dir or self.settings.rules_dir, self.ti_store, enable_anomaly=enable_anomaly)
        self.kg = SecurityKnowledgeGraph(self.ti_store)
        self.correlator = CorrelationEngine(
            self.kg,
            self.catalog,
            window_seconds=self.settings.correlation_window_seconds,
            min_score=self.settings.incident_min_score,
        )
        self.events: OrderedDict[str, SecurityEvent] = OrderedDict()
        self.max_events = max_events
        self._fingerprints: deque[str] = deque(maxlen=200_000)
        self._fp_set: set[str] = set()
        self.detections: list[Detection] = []
        self.incidents: dict[str, Incident] = {}
        self.stats = PlatformStats()
        self._lock = threading.RLock()
        self._dirty = False
        self.recent_detections: deque[Detection] = deque(maxlen=2000)

    # ------------------------------------------------------------------ ingestion
    def ingest(self, event: SecurityEvent) -> list[Detection]:
        with self._lock:
            fp = event.fingerprint()
            if fp in self._fp_set:
                self.stats.events_deduplicated += 1
                return []
            if len(self._fingerprints) == self._fingerprints.maxlen:
                self._fp_set.discard(self._fingerprints[0])
            self._fingerprints.append(fp)
            self._fp_set.add(fp)

            self.events[event.event_id] = event
            if len(self.events) > self.max_events:
                old_id, _ = self.events.popitem(last=False)
            self.kg.add_event(event)
            dets = self.detector.process(event)
            if dets:
                self.detections.extend(dets)
                self.recent_detections.extend(dets)
                self.stats.detections += len(dets)
                self._dirty = True
            self.stats.events_ingested += 1
            self.stats.last_event_at = event.timestamp
            return dets

    def ingest_many(self, events: list[SecurityEvent], correlate: bool = True) -> list[Detection]:
        out: list[Detection] = []
        for e in sorted(events, key=lambda x: x.timestamp):
            out.extend(self.ingest(e))
        if correlate:
            self.correlate()
        return out

    # ------------------------------------------------------------------ correlation
    def correlate(self, force: bool = False) -> list[Incident]:
        with self._lock:
            if not self._dirty and not force:
                return list(self.incidents.values())
            self.correlator._seq = 0
            incidents = self.correlator.correlate(self.detections, self.events)
            # preserve analyst status/summary across re-correlation by matching on detection overlap
            new: dict[str, Incident] = {}
            old_by_det = {}
            for inc in self.incidents.values():
                for d in inc.detections:
                    old_by_det[d.detection_id] = inc
            for inc in incidents:
                prev = next((old_by_det[d.detection_id] for d in inc.detections if d.detection_id in old_by_det), None)
                if prev is not None:
                    inc.status = prev.status
                    inc.summary = prev.summary
                    inc.incident_id = prev.incident_id
                new[inc.incident_id] = inc
            self.incidents = new
            self.stats.incidents = len(new)
            self._dirty = False
            return list(new.values())

    # ------------------------------------------------------------------ queries
    def get_incident(self, incident_id: str) -> Incident | None:
        return self.incidents.get(incident_id)

    def incident_events(self, incident: Incident) -> list[SecurityEvent]:
        return sorted((self.events[e] for e in incident.event_ids if e in self.events), key=lambda x: x.timestamp)

    def events_for(self, ids: list[str]) -> list[SecurityEvent]:
        return [self.events[i] for i in ids if i in self.events]

    def overview(self) -> dict:
        incs = list(self.incidents.values())
        open_incs = [i for i in incs if i.status.value in ("open", "investigating")]
        crit = [i for i in open_incs if i.severity.value == "critical"]
        high = [i for i in open_incs if i.severity.value == "high"]
        users = sorted({u for i in open_incs for u in i.affected_users})
        hosts = sorted({h for i in open_incs for h in i.affected_hosts})
        if crit:
            level = "CRITICAL"
        elif high:
            level = "HIGH"
        elif open_incs:
            level = "ELEVATED"
        else:
            level = "LOW"
        return {
            "threat_level": level,
            "active_incidents": len(open_incs),
            "critical": len(crit),
            "high": len(high),
            "suspicious_users": len(users),
            "affected_hosts": len(hosts),
            "events_ingested": self.stats.events_ingested,
            "events_deduplicated": self.stats.events_deduplicated,
            "detections": self.stats.detections,
            "last_event_at": self.stats.last_event_at.isoformat() if self.stats.last_event_at else None,
            "uptime_seconds": round(time.time() - self.stats.started_at),
            "graph": self.kg.stats(),
            "threat_intel": {k: v for k, v in self.ti_store.stats().items() if k != "feeds"},
            "detector": self.detector.metrics(),
        }

    def reset(self) -> None:
        with self._lock:
            self.detector.reset_state()
            self.kg = SecurityKnowledgeGraph(self.ti_store)
            self.correlator.kg = self.kg
            self.events.clear()
            self._fingerprints.clear()
            self._fp_set.clear()
            self.detections.clear()
            self.recent_detections.clear()
            self.incidents.clear()
            self.stats = PlatformStats()
            self._dirty = False
