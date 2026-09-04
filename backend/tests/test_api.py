import pytest
from aegis.api.audit import AuditLog
from aegis.api.security import Role, User
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from aegis.main import create_app

    app = create_app(seed_demo=True)
    with TestClient(app) as c:
        yield c


def _token(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_health(client):
    r = client.get("/api/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_bad_credentials(client):
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "wrong"})
    assert r.status_code == 401


def test_overview_requires_auth(client):
    assert client.get("/api/overview").status_code == 401
    tok = _token(client, "viewer", "viewer")
    r = client.get("/api/overview", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["threat_level"] in ("CRITICAL", "HIGH", "ELEVATED", "LOW")
    assert "severity_distribution" in body
    assert body["active_incidents"] >= 1


def test_rbac_viewer_cannot_investigate(client):
    tok = _token(client, "viewer", "viewer")
    incs = client.get("/api/incidents?limit=1", headers={"Authorization": f"Bearer {tok}"}).json()["incidents"]
    iid = incs[0]["incident_id"]
    r = client.post(f"/api/incidents/{iid}/investigate", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_analyst_can_investigate_grounded(client):
    tok = _token(client, "analyst", "analyst")
    incs = client.get("/api/incidents?limit=1", headers={"Authorization": f"Bearer {tok}"}).json()["incidents"]
    iid = incs[0]["incident_id"]
    r = client.post(f"/api/incidents/{iid}/investigate", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["grounding"]["grounded"]
    assert body["recommended_actions"]


def test_ingest_requires_api_key(client):
    assert client.post("/api/ingest", json={"events": []}).status_code == 401
    r = client.post("/api/ingest", headers={"x-api-key": "aegis-dev-ingest-key"},
                    json={"collector": "windows", "events": [
                        {"EventID": 4624, "Computer": "WS-1", "TimeCreated": "2026-08-30T09:00:00Z",
                         "EventData": {"TargetUserName": "alice", "IpAddress": "10.0.0.5"}}]})
    assert r.status_code == 200
    assert r.json()["accepted"] == 1


def test_incident_graph_endpoint(client):
    tok = _token(client, "viewer", "viewer")
    incs = client.get("/api/incidents?limit=1", headers={"Authorization": f"Bearer {tok}"}).json()["incidents"]
    iid = incs[0]["incident_id"]
    r = client.get(f"/api/incidents/{iid}/graph", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    g = r.json()["graph"]
    assert g["nodes"] and g["edges"]


def test_mitre_coverage(client):
    tok = _token(client, "viewer", "viewer")
    r = client.get("/api/mitre/coverage", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["techniques_covered"] > 40


def test_audit_hash_chain():
    log = AuditLog()
    log.record("alice", "login")
    log.record("alice", "investigate", "SEC-1")
    v = log.verify()
    assert v["valid"] and v["entries"] == 2
    # tamper
    log._entries[0]["actor"] = "mallory"
    assert not log.verify()["valid"]


def test_jwt_roundtrip():
    from aegis.api.security import create_token, decode_token

    u = User(username="x", role="analyst")
    back = decode_token(create_token(u))
    assert back.username == "x" and back.role == "analyst"
    assert back.level == int(Role.ANALYST)


def test_threat_map_geo_contract(client):
    """v2.1: threat map carries per-node country, per-country origins and the estate HQ."""
    tok = _token(client, "viewer", "viewer")
    r = client.get("/api/graph/threat-map", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["nodes"], list)
    assert body["hq"]["country"]
    assert isinstance(body["origins"], list)
    for n in body["nodes"]:
        assert "country" in n and "known_malicious" in n and "risk" in n
    for o in body["origins"]:
        assert o["country"] and o["incidents"] >= 1 and "max_risk" in o
