"""Attack-graph extraction: incident evidence -> layered, phase-annotated graph for the UI.

Layers follow the natural intrusion flow: identity -> host -> process -> file/service -> ip/domain -> ioc.
Every node and edge carries the event IDs that justify it so the analyst can click through to raw evidence.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

from aegis.graph.knowledge_graph import SecurityKnowledgeGraph
from aegis.schemas.detections import Detection
from aegis.schemas.events import SecurityEvent
from aegis.schemas.incidents import AttackGraph, GraphEdge, GraphNode

LAYER = {"user": 0, "ip_src": 0, "host": 1, "process": 2, "file": 3, "service": 3, "domain": 4, "ip": 4, "ioc": 5}

RELATION_PHASE = {
    "logged_into": "initial_access",
    "failed_login": "credential_access",
    "authenticated_as": "initial_access",
    "spawned": "execution",
    "executed": "execution",
    "ran": "execution",
    "wrote": "collection",
    "modified": "impact",
    "read": "collection",
    "connected_to": "command_and_control",
    "resolved": "command_and_control",
    "resolves_to": "command_and_control",
    "escalated_on": "privilege_escalation",
    "granted_privilege": "privilege_escalation",
    "created_account": "persistence",
    "installed": "persistence",
    "created": "persistence",
    "known_as": "command_and_control",
}


def build_attack_graph(
    kg: SecurityKnowledgeGraph,
    events: list[SecurityEvent],
    detections: list[Detection],
) -> AttackGraph:
    ev_ids = {e.event_id for e in events}
    sg = kg.subgraph_for_events(ev_ids)
    if sg.number_of_nodes() == 0:
        return AttackGraph()

    # event -> detections that cite it (for phase/technique annotations on edges)
    ev_to_det: dict[str, list[Detection]] = defaultdict(list)
    for d in detections:
        for eid in d.evidence_event_ids:
            ev_to_det[eid].append(d)

    node_risk: dict[str, float] = defaultdict(float)
    node_evidence: dict[str, set[str]] = defaultdict(set)
    for u, v, d in sg.edges(data=True):
        eid = d.get("event_id")
        if eid:
            node_evidence[u].add(eid)
            node_evidence[v].add(eid)
            for det in ev_to_det.get(eid, []):
                node_risk[u] = max(node_risk[u], det.score)
                node_risk[v] = max(node_risk[v], det.score)

    nodes: list[GraphNode] = []
    for nid, data in sg.nodes(data=True):
        kind = data.get("kind", "?")
        layer = LAYER.get(kind, 2)
        # source IPs (that authenticated) sit on the left with identities
        if kind == "ip" and any(d.get("relation") == "authenticated_as" for _, _, d in sg.out_edges(nid, data=True)):
            layer = 0
        attrs = {k: v for k, v in data.items() if k not in ("kind", "label", "first_seen", "last_seen") and v is not None}
        nodes.append(
            GraphNode(
                id=nid,
                type=kind,
                label=str(data.get("label", nid)),
                layer=layer,
                risk=round(max(node_risk.get(nid, 0.0), float(data.get("risk", 0.0)) if kind == "ioc" else node_risk.get(nid, 0.0)), 1),
                attributes=attrs,
                evidence_event_ids=sorted(node_evidence.get(nid, set()))[:50],
            )
        )

    # collapse parallel edges of the same relation between the same pair
    grouped: dict[tuple[str, str, str], dict] = {}
    for u, v, d in sg.edges(data=True):
        rel = d.get("relation", "related")
        key = (u, v, rel)
        g = grouped.setdefault(key, {"ts": d.get("ts"), "events": [], "techniques": set(), "phase": None})
        if d.get("event_id"):
            g["events"].append(d["event_id"])
            for det in ev_to_det.get(d["event_id"], []):
                g["techniques"].update(det.techniques)
                if det.phase and g["phase"] is None:
                    g["phase"] = det.phase
        if d.get("ts") and (g["ts"] is None or d["ts"] < g["ts"]):
            g["ts"] = d["ts"]

    edges: list[GraphEdge] = []
    for i, ((u, v, rel), g) in enumerate(sorted(grouped.items(), key=lambda kv: (kv[1]["ts"] is None, kv[1]["ts"]))):
        edges.append(
            GraphEdge(
                id=f"e{i}",
                source=u,
                target=v,
                relation=rel,
                timestamp=g["ts"],
                phase=RELATION_PHASE.get(rel) or g["phase"],
                techniques=sorted(g["techniques"]),
                evidence_event_ids=g["events"][:50],
            )
        )

    # order nodes by first appearance so the UI can animate the story
    first_ts = {}
    for e in edges:
        for n in (e.source, e.target):
            if e.timestamp and (n not in first_ts or e.timestamp < first_ts[n]):
                first_ts[n] = e.timestamp
    nodes.sort(key=lambda n: (n.layer, first_ts.get(n.id) is None, first_ts.get(n.id)))
    return AttackGraph(nodes=nodes, edges=edges)


def critical_path(graph: AttackGraph) -> list[str]:
    """Longest phase-ordered path through the attack graph — the 'story spine'."""
    if not graph.edges:
        return []
    g = nx.DiGraph()
    for e in graph.edges:
        g.add_edge(e.source, e.target)
    if not nx.is_directed_acyclic_graph(g):
        # break cycles by removing the closing edge of each simple cycle
        cycles = list(nx.simple_cycles(g))
        for cyc in cycles[:50]:
            if len(cyc) > 1 and g.has_edge(cyc[-1], cyc[0]):
                g.remove_edge(cyc[-1], cyc[0])
        if not nx.is_directed_acyclic_graph(g):
            return []
    return nx.dag_longest_path(g)
