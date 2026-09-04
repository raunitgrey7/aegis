"""Correlation engine: detections -> incidents.

Detections that share an entity (user, host, session, external IP) inside a sliding time window are
merged with union-find into one cluster. A cluster becomes an incident when its combined risk crosses
the threshold *or* it contains a single high/critical detection. Phases are ordered along the kill chain
and the attack graph is extracted from the knowledge graph using only the incident's own evidence.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from aegis.correlation.ledger import RiskLedger
from aegis.graph.attack_graph import build_attack_graph
from aegis.graph.knowledge_graph import SecurityKnowledgeGraph, node_id
from aegis.mitre.catalog import MitreCatalog
from aegis.schemas.detections import Detection, DetectionKind
from aegis.schemas.events import SecurityEvent, Severity
from aegis.schemas.incidents import PHASE_LABEL, PHASE_ORDER, Incident, PhaseEvidence
from aegis.scoring.risk import score_incident

WEAK_ENTITY_PREFIXES = ("ip:",)  # a shared external IP alone should not merge two hosts' clusters


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


class CorrelationEngine:
    def __init__(
        self,
        kg: SecurityKnowledgeGraph,
        catalog: MitreCatalog,
        window_seconds: int = 3600,
        min_score: float = 20.0,
        ledger: RiskLedger | None = None,
        graph_merge: bool = True,
        graph_merge_days: float = 14.0,
    ):
        self.kg = kg
        self.catalog = catalog
        self.window = timedelta(seconds=window_seconds)
        self.min_score = min_score
        self.ledger = ledger
        self.graph_merge = graph_merge
        self.graph_merge_window = timedelta(days=graph_merge_days)
        self._seq = 0
        self.stats: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ clustering
    def cluster(self, detections: list[Detection]) -> list[list[Detection]]:
        dets = sorted(detections, key=lambda d: d.timestamp)
        uf = _UnionFind()
        last_seen: dict[str, list[tuple[datetime, int]]] = defaultdict(list)
        for i, d in enumerate(dets):
            for key in d.entity_keys():
                weak = key.startswith(WEAK_ENTITY_PREFIXES)
                for ts, j in last_seen[key]:
                    if d.timestamp - ts <= self.window:
                        # weak keys only merge when the other detection also has a strong overlap
                        if weak and not (d.entity_keys() & dets[j].entity_keys() - {key}):
                            continue
                        uf.union(i, j)
                last_seen[key].append((d.timestamp, i))
                # prune
                horizon = d.timestamp - self.window
                last_seen[key] = [(ts, j) for ts, j in last_seen[key] if ts >= horizon]
        # --- second pass: graph-path merge -------------------------------------------------------
        # Two clusters on different hosts are the same intrusion if the knowledge graph shows one host
        # reaching the other (authenticated_to / connected_to an IP the other host owns). This is
        # correlation by *topology*, not by time: it links a beachhead to the server it pivoted to even
        # when the pivot happened days later.
        if self.graph_merge and len(dets) > 1:
            roots = {i: uf.find(i) for i in range(len(dets))}
            host_of: dict[str, set[int]] = defaultdict(set)  # host -> cluster roots touching it
            root_time: dict[int, tuple[datetime, datetime]] = {}
            for i, d in enumerate(dets):
                r = roots[i]
                lo, hi = root_time.get(r, (d.timestamp, d.timestamp))
                root_time[r] = (min(lo, d.timestamp), max(hi, d.timestamp))
                h = d.entities.get("host")
                if h:
                    host_of[h.upper()].add(r)
            for host, rset in list(host_of.items()):
                for nb in self.kg.lateral_neighbors(host):
                    for ra in rset:
                        for rb in host_of.get(nb, ()):
                            if ra == rb:
                                continue
                            (a0, a1), (b0, b1) = root_time[ra], root_time[rb]
                            gap = max(a0, b0) - min(a1, b1)
                            if gap <= self.graph_merge_window:
                                uf.union(ra, rb)
                                self.stats["graph_merges"] += 1
        groups: dict[int, list[Detection]] = defaultdict(list)
        for i, d in enumerate(dets):
            groups[uf.find(i)].append(d)
        return list(groups.values())

    # ------------------------------------------------------------------ incident creation
    def _phases(self, dets: list[Detection]) -> list[PhaseEvidence]:
        by_phase: dict[str, list[Detection]] = defaultdict(list)
        for d in dets:
            phase = d.phase
            if phase is None and d.techniques:
                phase = self.catalog.tactic_for(d.techniques[0])
            if phase:
                by_phase[phase].append(d)
        out: list[PhaseEvidence] = []
        for p in PHASE_ORDER:
            ds = by_phase.get(p.value, [])
            techs = sorted({t for d in ds for t in d.techniques})
            out.append(
                PhaseEvidence(
                    phase=p.value,
                    label=PHASE_LABEL[p.value],
                    present=bool(ds),
                    techniques=techs,
                    detection_ids=[d.detection_id for d in ds],
                    first_seen=min((d.timestamp for d in ds), default=None),
                )
            )
        return out

    def _title(self, dets: list[Detection], phases: list[str], users: list[str], hosts: list[str]) -> str:
        top = max(dets, key=lambda d: d.score)
        who = users[0] if users else (hosts[0] if hosts else "unknown")
        where = f" on {hosts[0]}" if hosts and users else ""
        if {"exfiltration", "collection"} & set(phases) and "execution" in phases:
            return f"Credential compromise → execution → data exfiltration ({who}{where})"
        if "impact" in phases:
            return f"Ransomware behaviour on {hosts[0] if hosts else who}"
        if "lateral_movement" in phases:
            return f"Lateral movement by {who} across {len(hosts)} host(s)"
        if "credential_access" in phases and "initial_access" in phases:
            return f"Brute-force compromise of {who}"
        if "exfiltration" in phases:
            return f"Data exfiltration from {hosts[0] if hosts else who}"
        if "persistence" in phases or "privilege_escalation" in phases:
            return f"Privilege escalation & persistence on {hosts[0] if hosts else who}"
        if "command_and_control" in phases:
            return f"Command-and-control activity from {hosts[0] if hosts else who}"
        return f"{top.title} ({who}{where})"

    def build_incident(self, dets: list[Detection], events_by_id: dict[str, SecurityEvent]) -> Incident | None:
        if not dets:
            return None
        users = sorted({d.entities["user"] for d in dets if d.entities.get("user")})
        hosts = sorted({d.entities["host"] for d in dets if d.entities.get("host")})
        ev_ids = sorted({eid for d in dets for eid in d.evidence_event_ids})
        events = [events_by_id[e] for e in ev_ids if e in events_by_id]
        ext_ips = sorted({e.dst_ip for e in events if e.dst_ip and not _is_private(e.dst_ip)})
        for d in dets:
            ip = d.entities.get("dst_ip")
            if ip and not _is_private(ip):
                ext_ips.append(ip)
        ext_ips = sorted(set(ext_ips))
        domains = sorted({e.domain for e in events if e.domain})
        phases = self._phases(dets)
        present = [p.phase for p in phases if p.present]
        techniques = sorted({t for d in dets for t in d.techniques})
        risk, confidence, sev, breakdown = score_incident(dets, present, hosts, users)

        # Incident admission policy (documented in docs/DETECTION.md):
        #  - a lone statistical anomaly is a *signal*, never an incident (needs corroboration)
        #  - a single medium/low rule hit below the risk floor stays an alert, not an incident
        #  - any high/critical detection, or corroborated evidence above the floor, becomes an incident
        max_sev = max((d.severity for d in dets), key=lambda s: list(Severity).index(s))
        distinct_rules = {d.rule_id for d in dets}
        if len(dets) == 1 and dets[0].kind == DetectionKind.ANOMALY:
            return None
        if risk < self.min_score and max_sev not in (Severity.HIGH, Severity.CRITICAL) and len(distinct_rules) < 2:
            return None

        graph = build_attack_graph(self.kg, events, dets)
        for n in graph.nodes:
            self.kg.touch_risk(n.id, n.risk)
        for u in users:
            self.kg.touch_risk(node_id("user", u), risk)
        for h in hosts:
            self.kg.touch_risk(node_id("host", h), risk)

        self._seq += 1
        first = min(d.timestamp for d in dets)
        last = max(d.timestamp for d in dets)
        if events:
            first = min(first, min(e.timestamp for e in events))
            last = max(last, max(e.timestamp for e in events))
        return Incident(
            incident_id=f"SEC-{self._seq:04d}",
            tenant_id=dets[0].tenant_id,
            title=self._title(dets, present, users, hosts),
            severity=sev,
            risk_score=risk,
            confidence=confidence,
            created_at=last,
            first_event_at=first,
            last_event_at=last,
            affected_users=users,
            affected_hosts=hosts,
            external_ips=ext_ips,
            domains=domains,
            techniques=techniques,
            phases=phases,
            detections=sorted(dets, key=lambda d: d.timestamp),
            event_ids=ev_ids,
            graph=graph,
            score_breakdown=breakdown,
            tags=sorted({t for d in dets for t in d.details.get("tags", [])} | {d.kind.value for d in dets}),
        )

    def correlate(self, detections: list[Detection], events_by_id: dict[str, SecurityEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        admitted: set[str] = set()
        for group in self.cluster(detections):
            inc = self.build_incident(group, events_by_id)
            if inc is not None:
                incidents.append(inc)
                admitted.update(d.detection_id for d in inc.detections)
        incidents.extend(self._slow_burn_incidents(detections, events_by_id, admitted))
        incidents.sort(key=lambda i: (-i.risk_score, i.first_event_at))
        return incidents

    # ------------------------------------------------------------------ slow-burn (ledger) incidents
    def _slow_burn_incidents(
        self, detections: list[Detection], events_by_id: dict[str, SecurityEvent], admitted: set[str]
    ) -> list[Incident]:
        """Low-and-slow campaigns: signals too weak/spread-out for the window correlator, but whose
        decayed risk on one identity or host has crossed the ledger threshold."""
        if self.ledger is None or not detections:
            return []
        by_id = {d.detection_id: d for d in detections}
        now = max(d.timestamp for d in detections)
        out: list[Incident] = []
        for cand in self.ledger.slow_burn_candidates(now):
            dets = [by_id[i] for i in cand["detection_ids"] if i in by_id]
            fresh = [d for d in dets if d.detection_id not in admitted]
            # need at least two contributions that the window correlator did NOT already explain
            if len(fresh) < self.ledger.min_deposits:
                continue
            inc = self._build_unfiltered(dets, events_by_id)
            if inc is None:
                continue
            entity = cand["entity"]
            inc.title = f"Low-and-slow activity on {entity.split(':', 1)[1]} ({cand['span_hours']:.0f}h, {len(dets)} signals)"
            inc.tags = sorted(set(inc.tags) | {"slow_burn", "ledger"})
            inc.score_breakdown["ledger_balance"] = cand["balance"]
            inc.score_breakdown["ledger_span_hours"] = cand["span_hours"]
            # the ledger balance is the evidence of intent here; let it lift the score
            inc.risk_score = round(min(100.0, max(inc.risk_score, min(95.0, cand["balance"]))), 1)
            if inc.risk_score >= 85:
                inc.severity = Severity.CRITICAL
            elif inc.risk_score >= 65:
                inc.severity = Severity.HIGH
            elif inc.risk_score >= 40:
                inc.severity = Severity.MEDIUM
            self.ledger.mark_emitted(entity, cand)
            self.stats["slow_burn_incidents"] += 1
            out.append(inc)
            admitted.update(d.detection_id for d in dets)
        return out

    def _build_unfiltered(self, dets: list[Detection], events_by_id: dict[str, SecurityEvent]) -> Incident | None:
        """build_incident without the admission policy (the ledger already justified admission)."""
        saved = self.min_score
        self.min_score = -1.0
        try:
            # temporarily relax the lone-anomaly rule too by padding kinds check: build_incident only
            # rejects a *single* anomaly; ledger candidates always have >=2 deposits.
            return self.build_incident(dets, events_by_id)
        finally:
            self.min_score = saved


def _is_private(ip: str) -> bool:
    from aegis.detection.conditions import is_private_ip

    return is_private_ip(ip)
