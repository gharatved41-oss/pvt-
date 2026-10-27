import pytest
from app.models.models import User, Asset
from app.core.security import verify_password

def test_phase1_unauthenticated_protected_routes(client):
    """Verify protected routes reject unauthenticated requests with 401."""
    protected_endpoints = [
        "/api/v1/auth/me",
        "/api/v1/dashboard/metrics",
        "/api/v1/assets",
        "/api/v1/assessments",
        "/api/v1/vulnerabilities",
        "/api/v1/twins",
        "/api/v1/audit",
        "/api/v1/settings/system"
    ]
    for endpoint in protected_endpoints:
        response = client.get(endpoint)
        assert response.status_code == 401, f"Expected 401 for unauthenticated {endpoint}, got {response.status_code}"

def test_phase1_seeded_admin_and_analyst_logins(client):
    """Verify demo accounts documented in README and frontend can authenticate."""
    # 1. Admin login
    admin_login = client.post("/api/v1/auth/login", json={
        "email": "admin@vulntwin.com",
        "password": "VulnTwin@2026!"
    })
    assert admin_login.status_code == 200
    admin_data = admin_login.json()
    assert admin_data["role"] == "admin"
    assert "access_token" in admin_data

    # 2. Analyst login (register if not yet present in isolated test db)
    analyst_login = client.post("/api/v1/auth/login", json={
        "email": "analyst@vulntwin.com",
        "password": "SecurePassword123!"
    })
    if analyst_login.status_code != 200:
        client.post("/api/v1/auth/register", json={
            "email": "analyst@vulntwin.com",
            "password": "SecurePassword123!",
            "full_name": "Senior Security Analyst",
            "role": "analyst"
        })
        analyst_login = client.post("/api/v1/auth/login", json={
            "email": "analyst@vulntwin.com",
            "password": "SecurePassword123!"
        })
    assert analyst_login.status_code == 200
    analyst_data = analyst_login.json()
    assert analyst_data["role"] == "analyst"
    assert "access_token" in analyst_data

def test_phase1_role_based_access(client):
    """Verify role authorization gates (e.g. analyst cannot delete asset or access admin-only endpoints)."""
    # Login as analyst
    analyst_res = client.post("/api/v1/auth/login", json={
        "email": "analyst@vulntwin.com",
        "password": "SecurePassword123!"
    })
    analyst_token = analyst_res.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Login as admin
    admin_res = client.post("/api/v1/auth/login", json={
        "email": "admin@vulntwin.com",
        "password": "VulnTwin@2026!"
    })
    admin_token = admin_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Create dummy asset with admin
    create_res = client.post("/api/v1/assets", headers=admin_headers, json={
        "name": "Phase1 Test Asset",
        "ip_address": "10.0.99.1",
        "hostname": "p1-test-host",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04",
        "environment": "staging",
        "criticality": "medium"
    })
    assert create_res.status_code == 201
    asset_id = create_res.json()["id"]

    # Analyst trying to delete asset should get 403 Forbidden
    del_analyst = client.delete(f"/api/v1/assets/{asset_id}", headers=analyst_headers)
    assert del_analyst.status_code == 403

    # Admin deleting asset should succeed
    del_admin = client.delete(f"/api/v1/assets/{asset_id}", headers=admin_headers)
    assert del_admin.status_code == 200

def test_phase1_dashboard_structure(client):
    """Verify dashboard metrics endpoint returns all required telemetry for the frontend charts."""
    admin_res = client.post("/api/v1/auth/login", json={
        "email": "admin@vulntwin.com",
        "password": "VulnTwin@2026!"
    })
    token = admin_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    dash = client.get("/api/v1/dashboard/metrics", headers=headers)
    assert dash.status_code == 200
    d = dash.json()

    # Core KPI counters
    assert "total_assets" in d
    assert "total_assessments" in d
    assert "total_findings" in d
    assert "critical_findings" in d
    assert "high_findings" in d
    assert "medium_findings" in d
    assert "low_findings" in d
    assert "status_breakdown" in d
    assert "remediation_breakdown" in d
    assert "average_risk_score" in d

    # Chart arrays
    assert "severity_distribution" in d
    assert isinstance(d["severity_distribution"], list)
    assert len(d["severity_distribution"]) == 4

    assert "status_distribution" in d
    assert isinstance(d["status_distribution"], list)

    assert "recent_assessments" in d
    assert "recent_findings" in d
    assert "recent_audits" in d
