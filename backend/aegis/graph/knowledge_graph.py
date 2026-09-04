"""Security knowledge graph.

Entities (users, hosts, processes, files, IPs, domains, indicators) are nodes; telemetry becomes typed,
time-stamped edges. The graph is what makes "show me everything this machine touched" a single query
instead of a log search, and it is the substrate for attack-graph extraction.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

import networkx as nx

from aegis.detection.conditions import is_private_ip
from aegis.schemas.events import EventType, SecurityEvent
from aegis.threat_intel.store import ThreatIntelStore


def node_id(kind: str, value: str) -> str:
    v = value.upper() if kind == "host" else value.lower()
    return f"{kind}:{v}"


class SecurityKnowledgeGraph:
    MAX_EDGES_PER_PAIR = 50  # bound memory on chatty telemetry

    def __init__(self, ti_store: ThreatIntelStore | None = None):
        self.g = nx.MultiDiGraph()
        self.ti = ti_store
        self._pair_counts: dict[tuple[str, str, str], int] = defaultdict(int)

    # ------------------------------------------------------------------ nodes
    def _node(self, kind: str, value: str, **attrs: Any) -> str:
        nid = node_id(kind, value)
        if nid not in self.g:
            self.g.add_node(nid, kind=kind, label=value, first_seen=attrs.get("ts"), risk=0.0, events=0)
            if self.ti is not None:
                ioc = None
                if kind == "ip":
                    ioc = self.ti.lookup_ip(value)
                elif kind == "domain":
                    ioc = self.ti.lookup_domain(value)
                elif kind == "file" and attrs.get("hash"):
                    ioc = self.ti.lookup_hash(attrs["hash"])
                if ioc is not None:
                    ioc_id = node_id("ioc", ioc.value)
                    if ioc_id not in self.g:
                        self.g.add_node(
                            ioc_id,
                            kind="ioc",
                            label=f"{ioc.threat}",
                            threat=ioc.threat,
                            source=ioc.source,
                            confidence=ioc.confidence,
                            risk=90.0,
                            events=0,
                        )
                    self.g.add_edge(nid, ioc_id, relation="known_as", ts=None)
        n = self.g.nodes[nid]
        n["events"] = n.get("events", 0) + 1
        n["last_seen"] = attrs.get("ts")
        for k, v in attrs.items():
            if k != "ts" and v is not None:
                n[k] = v
        return nid

    def _edge(self, src: str, dst: str, relation: str, event: SecurityEvent, **attrs: Any) -> None:
        key = (src, dst, relation)
        self._pair_counts[key] += 1
        if self._pair_counts[key] > self.MAX_EDGES_PER_PAIR:
            return
        self.g.add_edge(src, dst, relation=relation, ts=event.timestamp, event_id=event.event_id, **attrs)

    # ------------------------------------------------------------------ ingestion
    def add_event(self, e: SecurityEvent) -> None:  # noqa: C901 - event-type dispatch
        ts = e.timestamp
        host = self._node("host", e.host, ts=ts) if e.host else None
        user = self._node("user", e.user, ts=ts) if e.user else None
        et = e.event_type

        # host <-> address identity: lets the correlator walk host -> ip -> other host (lateral paths)
        if host and e.src_ip and is_private_ip(e.src_ip) and et != EventType.AUTHENTICATION:
            own = self._node("ip", e.src_ip, ts=ts)
            self._edge(host, own, "has_ip", e)

        if et == EventType.AUTHENTICATION:
            if user and host:
                rel = "logged_into" if e.action == "login_success" else "failed_login"
                self._edge(user, host, rel, e, src_ip=e.src_ip, country=e.geo_country)
            if e.src_ip and user:
                ip = self._node("ip", e.src_ip, ts=ts, country=e.geo_country)
                self._edge(ip, user, "authenticated_as", e, outcome=e.action)
                if host and is_private_ip(e.src_ip):
                    self._edge(host, ip, "has_ip", e)
            if e.dst_ip and host and e.action == "login_success":
                target = self._node("ip", e.dst_ip, ts=ts)
                self._edge(host, target, "authenticated_to", e, privilege=e.privilege)

        elif et in (EventType.PROCESS_START, EventType.PROCESS_END) and e.process_name:
            proc = self._node("process", f"{e.host or '?'}/{e.process_name}", ts=ts, name=e.process_name)
            if e.parent_process_name:
                parent = self._node("process", f"{e.host or '?'}/{e.parent_process_name}", ts=ts, name=e.parent_process_name)
                self._edge(parent, proc, "spawned", e, command_line=e.command_line)
            elif host:
                self._edge(host, proc, "executed", e, command_line=e.command_line)
            if user and et == EventType.PROCESS_START:
                self._edge(user, proc, "ran", e)

        elif et in (EventType.FILE_CREATE, EventType.FILE_MODIFY, EventType.FILE_DELETE, EventType.FILE_READ) and e.file_path:
            f = self._node("file", e.file_path, ts=ts, hash=e.file_hash, size=e.file_size)
            rel = {"file_create": "wrote", "file_modify": "modified", "file_delete": "deleted", "file_read": "read"}[et.value]
            if e.process_name:
                proc = self._node("process", f"{e.host or '?'}/{e.process_name}", ts=ts, name=e.process_name)
                self._edge(proc, f, rel, e)
            elif host:
                self._edge(host, f, rel, e)

        elif et == EventType.NETWORK_CONNECTION and e.dst_ip:
            ip = self._node("ip", e.dst_ip, ts=ts)
            src = None
            if e.process_name:
                src = self._node("process", f"{e.host or '?'}/{e.process_name}", ts=ts, name=e.process_name)
            elif host:
                src = host
            if src:
                self._edge(src, ip, "connected_to", e, port=e.dst_port, bytes_out=e.bytes_out, protocol=e.protocol)
            if e.domain:
                dom = self._node("domain", e.domain, ts=ts)
                self._edge(dom, ip, "resolves_to", e)

        elif et == EventType.DNS_QUERY and e.domain:
            dom = self._node("domain", e.domain, ts=ts)
            if host:
                self._edge(host, dom, "resolved", e, outcome=e.outcome)
            if e.dst_ip:
                ip = self._node("ip", e.dst_ip, ts=ts)
                self._edge(dom, ip, "resolves_to", e)

        elif et in (EventType.PRIVILEGE_CHANGE, EventType.GROUP_CHANGE):
            if user and host:
                self._edge(user, host, "escalated_on", e, privilege=e.privilege)
            if e.target_user:
                tgt = self._node("user", e.target_user, ts=ts)
                if user:
                    self._edge(user, tgt, "granted_privilege", e, privilege=e.privilege)

        elif et in (EventType.USER_CREATED, EventType.USER_DELETED) and e.target_user:
            tgt = self._node("user", e.target_user, ts=ts)
            if user:
                self._edge(user, tgt, "created_account" if et == EventType.USER_CREATED else "deleted_account", e)
            if host:
                self._edge(tgt, host, "exists_on", e)

        elif et in (EventType.SERVICE_STARTED, EventType.SERVICE_STOPPED, EventType.SCHEDULED_TASK) and (
            e.service_name or e.file_path
        ):
            svc = self._node("service", f"{e.host or '?'}/{e.service_name or e.file_path}", ts=ts)
            if host:
                self._edge(host, svc, e.action or et.value, e, command_line=e.command_line)
            if user:
                self._edge(user, svc, "installed" if e.action in ("installed", "created") else "touched", e)

    # ------------------------------------------------------------------ queries
    def neighborhood(self, nid: str, depth: int = 1) -> nx.MultiDiGraph:
        nodes = {nid}
        frontier = {nid}
        for _ in range(depth):
            nxt: set[str] = set()
            for n in frontier:
                if n in self.g:
                    nxt.update(self.g.successors(n))
                    nxt.update(self.g.predecessors(n))
            frontier = nxt - nodes
            nodes |= nxt
        return self.g.subgraph(nodes).copy()

    def subgraph_for_events(self, event_ids: set[str]) -> nx.MultiDiGraph:
        edges = [(u, v, k) for u, v, k, d in self.g.edges(keys=True, data=True) if d.get("event_id") in event_ids]
        sg = self.g.edge_subgraph(edges).copy() if edges else nx.MultiDiGraph()
        # pull in IOC nodes linked to any node in the subgraph
        for n in list(sg.nodes):
            for _, v, d in self.g.out_edges(n, data=True):
                if d.get("relation") == "known_as":
                    sg.add_node(v, **self.g.nodes[v])
                    sg.add_edge(n, v, **d)
        return sg

    def entity(self, nid: str) -> dict | None:
        if nid not in self.g:
            return None
        d = dict(self.g.nodes[nid])
        d["id"] = nid
        d["in_degree"] = self.g.in_degree(nid)
        d["out_degree"] = self.g.out_degree(nid)
        return d

    def find(self, query: str, limit: int = 25) -> list[dict]:
        q = query.lower()
        out = []
        for nid, d in self.g.nodes(data=True):
            if q in nid.lower() or q in str(d.get("label", "")).lower():
                out.append({"id": nid, **d})
                if len(out) >= limit:
                    break
        return out

    def paths_between(self, src: str, dst: str, cutoff: int = 6) -> list[list[str]]:
        if src not in self.g or dst not in self.g:
            return []
        simple = nx.DiGraph(self.g)
        try:
            return list(nx.all_simple_paths(simple, src, dst, cutoff=cutoff))[:10]
        except nx.NetworkXNoPath:
            return []

    def hosts_touched_by_user(self, user: str) -> list[str]:
        uid = node_id("user", user)
        if uid not in self.g:
            return []
        return sorted({v.split(":", 1)[1] for _, v, d in self.g.out_edges(uid, data=True) if v.startswith("host:")})

    def external_ips_from_host(self, host: str) -> list[str]:
        hid = node_id("host", host)
        if hid not in self.g:
            return []
        ips: set[str] = set()
        for _, proc, _d in self.g.out_edges(hid, data=True):
            for _, v, d2 in self.g.out_edges(proc, data=True):
                if v.startswith("ip:") and d2.get("relation") == "connected_to":
                    ips.add(v.split(":", 1)[1])
        for _, v, _d in self.g.out_edges(hid, data=True):
            if v.startswith("ip:"):
                ips.add(v.split(":", 1)[1])
        return sorted(ips)

    def lateral_neighbors(self, host: str) -> set[str]:
        """Other hosts this one is topologically linked to — the substrate for graph-path correlation.

        Two hosts are neighbours when one reached an internal IP that the other is also associated with
        (either the other host's processes connected to it, or a user authenticated from it to that host).
        This links a beachhead to the host it pivoted to even when the two events are days apart and never
        fell in the same time window. It is a best-effort topology query over the relations the graph
        actually records; when the pivot leaves no shared internal-IP trail it returns nothing rather
        than guessing.
        """
        hid = node_id("host", host)
        if hid not in self.g:
            return set()

        def internal_ips_of(h_node: str) -> set[str]:
            ips: set[str] = set()
            for _, proc, _d in self.g.out_edges(h_node, data=True):
                if proc.startswith("process:"):
                    for _, v, d2 in self.g.out_edges(proc, data=True):
                        if v.startswith("ip:") and d2.get("relation") == "connected_to":
                            ips.add(v)
                elif proc.startswith("ip:") and _d.get("relation") == "connected_to":
                    ips.add(proc)
            return ips

        mine = internal_ips_of(hid)
        if not mine:
            return set()
        neighbors: set[str] = set()
        for other, data in self.g.nodes(data=True):
            if data.get("kind") != "host" or other == hid:
                continue
            if internal_ips_of(other) & mine:
                neighbors.add(other.split(":", 1)[1])
        return neighbors

    def stats(self) -> dict:
        kinds: dict[str, int] = defaultdict(int)
        for _, d in self.g.nodes(data=True):
            kinds[d.get("kind", "?")] += 1
        return {"nodes": self.g.number_of_nodes(), "edges": self.g.number_of_edges(), "by_kind": dict(kinds)}

    def touch_risk(self, nid: str, risk: float, ts: datetime | None = None) -> None:
        if nid in self.g:
            self.g.nodes[nid]["risk"] = max(self.g.nodes[nid].get("risk", 0.0), risk)
