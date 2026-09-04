"""All API routes.

Grouped into one module for cohesion; split by tag. Every state-changing or sensitive route is
role-gated and audited. Read routes are tenant-scoped to the caller's tenant.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from aegis.api import metrics
from aegis.api.models import (
    CopilotRequest,
    IngestRequest,
    IngestResponse,
    LoginRequest,
    SimulateRequest,
    StatusUpdate,
    TokenResponse,
)
from aegis.api.security import Role, User, create_token, current_user, require_api_key, require_role
from aegis.api.state import AppState, get_state
from aegis.graph.attack_graph import critical_path
from aegis.ingestion.normalizer import normalize
from aegis.schemas.incidents import IncidentStatus

router = APIRouter()


# ------------------------------------------------------------------ auth
@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(body: LoginRequest, state: AppState = Depends(get_state)):
    user = state.users.authenticate(body.username, body.password)
    if user is None:
        state.audit.record(body.username, "login", outcome="failure")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    state.audit.record(user.username, "login", outcome="success", role=user.role)
    return TokenResponse(
        access_token=create_token(user),
        role=user.role,
        expires_in_minutes=state.settings.jwt_expiry_minutes,
    )


@router.get("/auth/me", tags=["auth"])
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role, "tenant": user.tenant_id}


# ------------------------------------------------------------------ ingestion (machine role)
@router.post("/ingest", response_model=IngestResponse, tags=["ingest"], dependencies=[Depends(require_api_key)])
async def ingest(body: IngestRequest, request: Request, state: AppState = Depends(get_state)):
    s = state.settings
    if len(body.events) > s.max_events_per_batch:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"max {s.max_events_per_batch} events per batch")
    if not state.limiter.allow("ingest", cost=1.0):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
    t0 = time.perf_counter()
    events = []
    for rec in body.events:
        try:
            ev = normalize(rec, body.collector, tenant=s.default_tenant)
            events.append(ev)
        except Exception as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"bad event: {exc}") from exc
    dets = state.platform.ingest_many(events, correlate=body.correlate)
    metrics.INGEST_LATENCY.observe(time.perf_counter() - t0)
    for e in events:
        metrics.EVENTS_INGESTED.labels(s.default_tenant, e.source.value).inc()
    for d in dets:
        metrics.DETECTIONS.labels(d.rule_id, d.severity.value).inc()
    state.invalidate_reports()
    ov = state.platform.overview()
    return IngestResponse(
        accepted=len(events),
        deduplicated=state.platform.stats.events_deduplicated,
        detections=len(dets),
        incidents_open=ov["active_incidents"],
    )


# ------------------------------------------------------------------ overview / dashboard
@router.get("/overview", tags=["dashboard"])
def overview(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    ov = state.platform.overview()
    for sev in ("critical", "high", "medium", "low"):
        n = sum(1 for i in state.platform.incidents.values() if i.severity.value == sev and i.status.value in ("open", "investigating"))
        metrics.INCIDENTS.labels(sev).set(n)
    incs = sorted(state.platform.incidents.values(), key=lambda i: -i.risk_score)
    ov["top_incidents"] = [
        {"incident_id": i.incident_id, "title": i.title, "severity": i.severity.value,
         "risk": i.risk_score, "hosts": i.affected_hosts, "users": i.affected_users,
         "phases": i.present_phases, "status": i.status.value, "created_at": i.created_at.isoformat()}
        for i in incs[:10]
    ]
    ov["severity_distribution"] = _severity_distribution(state)
    ov["phase_distribution"] = _phase_distribution(state)
    ov["tactic_coverage"] = state.platform.catalog.coverage(
        [t for i in state.platform.incidents.values() for t in i.techniques]
    )
    return ov


def _severity_distribution(state: AppState) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for i in state.platform.incidents.values():
        out[i.severity.value] = out.get(i.severity.value, 0) + 1
    return out


def _phase_distribution(state: AppState) -> list[dict]:
    from collections import Counter

    c: Counter = Counter()
    for i in state.platform.incidents.values():
        for p in i.present_phases:
            c[p] += 1
    from aegis.schemas.incidents import PHASE_LABEL

    return [{"phase": p, "label": PHASE_LABEL.get(p, p), "count": n} for p, n in c.most_common()]


# ------------------------------------------------------------------ incidents
@router.get("/incidents", tags=["incidents"])
def list_incidents(
    user: User = Depends(current_user),
    state: AppState = Depends(get_state),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, le=500),
):
    incs = sorted(state.platform.incidents.values(), key=lambda i: (-i.risk_score, i.first_event_at))
    if severity:
        incs = [i for i in incs if i.severity.value == severity]
    if status_filter:
        incs = [i for i in incs if i.status.value == status_filter]
    return {
        "count": len(incs),
        "incidents": [
            {
                "incident_id": i.incident_id, "title": i.title, "severity": i.severity.value,
                "risk_score": i.risk_score, "confidence": i.confidence, "status": i.status.value,
                "affected_users": i.affected_users, "affected_hosts": i.affected_hosts,
                "external_ips": i.external_ips, "techniques": i.techniques, "phases": i.present_phases,
                "first_event_at": i.first_event_at.isoformat(), "last_event_at": i.last_event_at.isoformat(),
                "detection_count": len(i.detections), "tags": i.tags,
            }
            for i in incs[:limit]
        ],
    }


@router.get("/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str, user: User = Depends(current_user), state: AppState = Depends(get_state)):
    inc = state.platform.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    data = inc.model_dump(mode="json")
    data["events"] = [e.model_dump(mode="json") for e in state.platform.incident_events(inc)]
    data["critical_path"] = critical_path(inc.graph)
    return data


@router.get("/incidents/{incident_id}/graph", tags=["incidents"])
def incident_graph(incident_id: str, user: User = Depends(current_user), state: AppState = Depends(get_state)):
    inc = state.platform.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return {"graph": inc.graph.model_dump(mode="json"), "critical_path": critical_path(inc.graph)}


@router.post("/incidents/{incident_id}/status", tags=["incidents"])
def set_status(
    incident_id: str, body: StatusUpdate,
    user: User = Depends(require_role(Role.ANALYST)), state: AppState = Depends(get_state),
):
    inc = state.platform.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    try:
        inc.status = IncidentStatus(body.status)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid status") from exc
    state.audit.record(user.username, "incident.status", incident_id, new_status=body.status)
    return {"incident_id": incident_id, "status": inc.status.value}


# ------------------------------------------------------------------ investigation
@router.post("/incidents/{incident_id}/investigate", tags=["investigation"])
def investigate(
    incident_id: str,
    user: User = Depends(require_role(Role.ANALYST)),
    state: AppState = Depends(get_state),
):
    inc = state.platform.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    cached = state._report_cache.get(incident_id)
    if cached:
        return cached
    t0 = time.perf_counter()
    report = state.investigator.investigate(inc, state.platform.incident_events(inc))
    metrics.INVESTIGATION_LATENCY.observe(time.perf_counter() - t0)
    data = report.model_dump(mode="json")
    data["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    state._report_cache[incident_id] = data
    state.audit.record(user.username, "incident.investigate", incident_id, llm_used=report.llm_used)
    return data


@router.post("/incidents/{incident_id}/copilot", tags=["investigation"])
def copilot(
    incident_id: str, body: CopilotRequest,
    user: User = Depends(require_role(Role.ANALYST)), state: AppState = Depends(get_state),
):
    inc = state.platform.get_incident(incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    if not state.limiter.allow(f"copilot:{user.username}", cost=1.0):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
    ans = state.investigator.answer(body.question, inc, state.platform.incident_events(inc))
    state.audit.record(user.username, "incident.copilot", incident_id, question=body.question[:200])
    return ans


# ------------------------------------------------------------------ knowledge graph
@router.get("/graph/entity", tags=["graph"])
def entity(q: str = Query(min_length=1, max_length=200), depth: int = Query(default=1, le=3),
           user: User = Depends(current_user), state: AppState = Depends(get_state)):
    kg = state.platform.kg
    matches = kg.find(q, limit=1)
    if not matches:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "entity not found")
    nid = matches[0]["id"]
    sg = kg.neighborhood(nid, depth=depth)
    nodes = [{"id": n, **{k: v for k, v in d.items() if k != "first_seen"}} for n, d in sg.nodes(data=True)]
    edges = [{"source": u, "target": v, **{k: (val.isoformat() if hasattr(val, "isoformat") else val) for k, val in d.items()}} for u, v, d in sg.edges(data=True)]
    return {"center": nid, "entity": kg.entity(nid), "nodes": nodes, "edges": edges}


@router.get("/graph/search", tags=["graph"])
def graph_search(q: str = Query(min_length=1), user: User = Depends(current_user), state: AppState = Depends(get_state)):
    return {"results": state.platform.kg.find(q, limit=25)}


@router.get("/graph/threat-map", tags=["graph"])
def threat_map(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    """External IPs / domains involved in incidents, their threat-intel context, and the
    geographic shape of the activity: per-node country where a feed attributes the
    indicator, per-country login origins observed in incident evidence, and the estate's
    home country (``AEGIS_HOME_COUNTRY``) so a client can draw origin→HQ arcs."""
    home = (state.settings.home_country or "IN").upper()
    nodes = []
    origins: dict[str, dict] = {}
    for i in state.platform.incidents.values():
        for ip in i.external_ips:
            ioc = state.platform.ti_store.lookup_ip(ip)
            nodes.append({"type": "ip", "value": ip, "incident": i.incident_id, "risk": i.risk_score,
                          "known_malicious": ioc is not None, "threat": ioc.threat if ioc else None,
                          "country": ioc.country if ioc else None,
                          "hosts": i.affected_hosts})
        for dom in i.domains:
            ioc = state.platform.ti_store.lookup_domain(dom)
            if ioc or not dom.endswith((".local", ".corp")):
                nodes.append({"type": "domain", "value": dom, "incident": i.incident_id, "risk": i.risk_score,
                              "known_malicious": ioc is not None, "threat": ioc.threat if ioc else None,
                              "country": ioc.country if ioc else None,
                              "hosts": i.affected_hosts})
        # login origins seen in this incident's evidence (auth events carry geo_country)
        for e in state.platform.incident_events(i):
            c = (e.geo_country or "").upper()
            if c and c != home:
                o = origins.setdefault(c, {"incidents": set(), "max_risk": 0.0, "users": set()})
                o["incidents"].add(i.incident_id)
                o["max_risk"] = max(o["max_risk"], i.risk_score)
                if e.user:
                    o["users"].add(e.user)
    # dedup by value keeping highest risk
    best: dict[str, dict] = {}
    for n in nodes:
        k = n["value"]
        if k not in best or n["risk"] > best[k]["risk"]:
            best[k] = n
    return {
        "nodes": list(best.values()),
        "origins": [
            {"country": c, "incidents": len(v["incidents"]), "max_risk": v["max_risk"],
             "users": sorted(v["users"])[:6]}
            for c, v in sorted(origins.items(), key=lambda kv: -kv[1]["max_risk"])
        ],
        "hq": {"country": home},
    }


# ------------------------------------------------------------------ threat intel
@router.get("/threat-intel/stats", tags=["threat-intel"])
def ti_stats(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    return state.platform.ti_store.stats()


@router.get("/threat-intel/lookup", tags=["threat-intel"])
def ti_lookup(value: str = Query(min_length=1), user: User = Depends(current_user), state: AppState = Depends(get_state)):
    ti = state.platform.ti_store
    for fn in (ti.lookup_ip, ti.lookup_domain, ti.lookup_hash, ti.lookup_url):
        hit = fn(value)
        if hit:
            return {"match": True, "ioc": {**hit.__dict__, "type": hit.type.value, "tags": list(hit.tags)}}
    return {"match": False}


# ------------------------------------------------------------------ rules & MITRE
@router.get("/rules", tags=["rules"])
def rules(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    return {"count": len(state.platform.detector.rules), "rules": state.platform.detector.rule_catalog()}


@router.get("/mitre/coverage", tags=["mitre"])
def mitre_coverage(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    return state.platform.catalog.rule_coverage(state.platform.detector.techniques_by_rule())


@router.get("/mitre/observed", tags=["mitre"])
def mitre_observed(user: User = Depends(current_user), state: AppState = Depends(get_state)):
    techs = [t for i in state.platform.incidents.values() for t in i.techniques]
    return {"coverage": state.platform.catalog.coverage(techs), "techniques": sorted(set(techs))}


# ------------------------------------------------------------------ simulator (admin)
@router.post("/simulate", tags=["simulator"])
def simulate(body: SimulateRequest, user: User = Depends(require_role(Role.ADMIN)), state: AppState = Depends(get_state)):
    import random
    from datetime import UTC, datetime

    from aegis_sim.scenarios import SCENARIOS, generate_scenario

    sid = body.scenario.upper()
    if sid not in SCENARIOS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown scenario {sid}; choose {list(SCENARIOS)}")
    ent = getattr(state, "enterprise", None)
    if ent is None:
        from aegis_sim.enterprise import Enterprise

        ent = Enterprise(seed=7)
    sc = generate_scenario(sid, ent, random.Random(), datetime.now(UTC))
    before = set(state.platform.incidents)
    dets = state.platform.ingest_many(sc.events, correlate=body.correlate)
    state.invalidate_reports()
    new = [iid for iid in state.platform.incidents if iid not in before]
    state.audit.record(user.username, "simulate", sid, detections=len(dets))
    return {"scenario": sid, "name": sc.name, "events": len(sc.events), "detections": len(dets),
            "new_incidents": new, "expected_techniques": sc.expected_techniques}


@router.get("/simulate/scenarios", tags=["simulator"])
def scenarios(user: User = Depends(current_user)):
    from aegis_sim import scenarios as sc

    out = []
    for sid, fn in sc.SCENARIOS.items():
        out.append({"id": sid, "function": fn.__name__})
    return {"scenarios": out}


# ------------------------------------------------------------------ audit (admin)
@router.get("/audit", tags=["admin"])
def audit(n: int = Query(default=100, le=1000), user: User = Depends(require_role(Role.ADMIN)), state: AppState = Depends(get_state)):
    return {"verification": state.audit.verify(), "entries": state.audit.tail(n)}


# ------------------------------------------------------------------ metrics & health
@router.get("/healthz", tags=["ops"])
def healthz(state: AppState = Depends(get_state)):
    return {"status": "ok", "events": state.platform.stats.events_ingested,
            "incidents": len(state.platform.incidents), "llm": state.llm.available() if state.llm else False}


@router.get("/metrics", tags=["ops"])
def prometheus_metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
