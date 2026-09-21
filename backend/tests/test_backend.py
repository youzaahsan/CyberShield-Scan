import pytest
from fastapi.testclient import TestClient
from backend.app.main import app, seed_initial_data

@pytest.fixture(autouse=True)
def init_data():
    seed_initial_data()

client = TestClient(app)

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "authorization_warning" in data

def test_login_admin():
    res = client.post("/api/auth/login", json={
        "username_or_email": "admin",
        "password": "AdminPass123!"
    })
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" in token_data
    assert token_data["user"]["role"] == "Admin"

def test_rbac_protection():
    # Login as viewer
    res = client.post("/api/auth/login", json={
        "username_or_email": "viewer",
        "password": "ViewerPass123!"
    })
    viewer_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer should be able to view hosts, cves, risk
    cves_res = client.get("/api/cves", headers=headers)
    assert cves_res.status_code == 200
    assert len(cves_res.json()) > 0

    # Viewer should NOT be able to create scans (Forbidden 403)
    scan_res = client.post("/api/scans", json={
        "name": "Unauthorized Scan",
        "target": "127.0.0.1",
        "profile": "Top 20"
    }, headers=headers)
    assert scan_res.status_code == 403

def test_admin_create_scan():
    res = client.post("/api/auth/login", json={
        "username_or_email": "admin",
        "password": "AdminPass123!"
    })
    admin_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    scan_res = client.post("/api/scans", json={
        "name": "Lab Scan Test",
        "target": "127.0.0.1/32",
        "profile": "Top 20"
    }, headers=headers)
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["name"] == "Lab Scan Test"
    assert scan_data["status"] == "Pending"

def test_risk_and_topology_endpoints():
    res = client.post("/api/auth/login", json={
        "username_or_email": "analyst",
        "password": "AnalystPass123!"
    })
    analyst_token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {analyst_token}"}

    risk_res = client.get("/api/risk", headers=headers)
    assert risk_res.status_code == 200
    risk_data = risk_res.json()
    assert "overall_score" in risk_data
    assert "factors" in risk_data

    topo_res = client.get("/api/topology", headers=headers)
    assert topo_res.status_code == 200
    topo_data = topo_res.json()
    assert "nodes" in topo_data
    assert "edges" in topo_data
