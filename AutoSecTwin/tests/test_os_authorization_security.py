"""Deterministic security audit tests for Milestone 6.1: Authorization & Authentication Validation.

Validates:
1. Missing credentials rejected with 401 Unauthorized and WWW-Authenticate header.
2. Invalid and malformed credentials rejected with 401 Unauthorized.
3. Expired and revoked credentials rejected with 401 Unauthorized.
4. Guest and insufficient-privilege users rejected with 403 Forbidden (preventing role spoofing).
5. User A attempting to access User B's assets and assessments rejected with 403 Forbidden (IDOR prevention).
6. Unauthorized access to evidence, findings, risk, and remediation endpoints rejected with 403 Forbidden.
7. Attempts to bypass authorization using 'X-Asset-Authorized: true' rejected with 403 Forbidden.
8. Unauthorized remote asset execution rejected with 403 Forbidden.
9. Valid authorized access by asset/assessment owner succeeds (200/201), and admin access succeeds.
10. Regression prevention: Unauthenticated public analyses and health endpoints remain unaffected.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.os_assessment import OSAssessmentRecord, OSAssessmentStatus
from app.models.os_asset import OSAssetRecord
from app.schemas.os_evidence import (
    OSEvidenceItemCreate,
    OSEvidenceStatus,
    OSPermissionState,
)
from app.services import os_assessment_service
from app.services.os_collectors.base import BaseOSCollector
from app.services.os_collectors.manager import OSCollectorManager
from app.utils.os_detect import get_anonymized_host_identifier


class MockSecurityAuditCollector(BaseOSCollector):
    """Deterministic collector for security authorization validation."""

    @property
    def name(self) -> str:
        return "mock_security_collector"

    @property
    def check_id(self) -> str:
        return "audit_probe"

    @property
    def supported_os_families(self):
        return ["linux", "windows"]

    def collect(self, context=None):
        return [
            OSEvidenceItemCreate(
                collector_name="mock_security_collector",
                check_id="dpkg_installed_packages",
                signal_name="packages",
                observed_value="bash 5.1",
                structured_data={"packages": [{"package_name": "bash", "installed_version": "5.1"}]},
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
            )
        ]


# ==============================================================================
# 1. Missing Credentials (Scenario 1)
# ==============================================================================

def test_missing_credentials_rejected_on_all_protected_endpoints(client: TestClient) -> None:
    """Verify that requests missing credentials receive 401 with WWW-Authenticate challenge."""
    endpoints = [
        ("GET", "/api/v1/os/assets"),
        ("POST", "/api/v1/os/assets"),
        ("GET", "/api/v1/os/assets/any-uuid"),
        ("GET", "/api/v1/os/assessments"),
        ("POST", "/api/v1/os/assessments"),
        ("GET", "/api/v1/os/assessments/any-uuid"),
        ("POST", "/api/v1/os/assessments/any-uuid/assess"),
        ("GET", "/api/v1/os/assessments/any-uuid/evidence"),
        ("GET", "/api/v1/os/assessments/any-uuid/findings"),
        ("GET", "/api/v1/os/assessments/any-uuid/risk"),
        ("GET", "/api/v1/os/assessments/any-uuid/remediation"),
    ]

    for method, path in endpoints:
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json={})

        assert resp.status_code == 401, f"Expected 401 on {method} {path}, got {resp.status_code}"
        assert "WWW-Authenticate" in resp.headers or "www-authenticate" in resp.headers
        auth_header = resp.headers.get("WWW-Authenticate") or resp.headers.get("www-authenticate", "")
        assert "Bearer" in auth_header
        assert "missing" in resp.json()["message"].lower()


# ==============================================================================
# 2. Invalid and Malformed Credentials (Scenario 2)
# ==============================================================================

def test_malformed_and_invalid_credentials_rejected_with_401(client: TestClient) -> None:
    """Verify malformed headers, non-bearer schemes, and invalid tokens receive 401."""
    # Non-bearer scheme (e.g. Basic)
    resp_basic = client.get("/api/v1/os/assets", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp_basic.status_code == 401
    assert "malformed" in resp_basic.json()["message"].lower()

    # Empty token string
    resp_empty = client.get("/api/v1/os/assets", headers={"Authorization": "Bearer "})
    assert resp_empty.status_code == 401

    # Invalid token signature / content
    resp_invalid = client.get("/api/v1/os/assets", headers={"Authorization": "Bearer invalid_signature_token"})
    assert resp_invalid.status_code == 401
    assert "invalid" in resp_invalid.json()["message"].lower()

    # Malformed token keyword
    resp_bad = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer bad_token_content"})
    assert resp_bad.status_code == 401


# ==============================================================================
# 3. Expired or Revoked Credentials (Scenario 3)
# ==============================================================================

def test_expired_and_revoked_credentials_rejected_with_401(client: TestClient) -> None:
    """Verify that expired and revoked tokens receive deterministic 401 responses."""
    # Expired token
    resp_exp = client.get("/api/v1/os/assets", headers={"Authorization": "Bearer token_expired_session"})
    assert resp_exp.status_code == 401
    assert "expired" in resp_exp.json()["message"].lower()

    # Revoked token
    resp_rev = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer token_revoked_session"})
    assert resp_rev.status_code == 401
    assert "revoked" in resp_rev.json()["message"].lower()


# ==============================================================================
# 4. Guest and Insufficient-Privilege Users & Header Spoofing (Scenario 4)
# ==============================================================================

def test_guest_user_rejected_with_403_and_role_spoofing_prevented(client: TestClient) -> None:
    """Verify guest role is rejected with 403 and client role-spoofing headers are ignored."""
    # Guest user token rejected
    resp_guest = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer guest_token"})
    assert resp_guest.status_code == 403
    assert "insufficient privilege" in resp_guest.json()["message"].lower()

    # Guest user attempts to spoof admin privileges using client headers
    resp_spoof = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "b" * 64,
            "hostname": "spoofed-host",
            "os_family": "linux",
            "os_name": "Ubuntu 22.04 LTS",
        },
        headers={
            "Authorization": "Bearer guest_token",
            "X-User-Role": "admin",
            "X-Role": "admin",
            "X-Admin": "true",
        },
    )
    # Must STILL be rejected with 403 Forbidden!
    assert resp_spoof.status_code == 403
    assert "insufficient privilege" in resp_spoof.json()["message"].lower()


# ==============================================================================
# 5. User A vs. User B Asset & Assessment Access (Scenario 5 - IDOR Protection)
# ==============================================================================

def test_user_b_cannot_access_or_start_user_a_resources(client: TestClient) -> None:
    """Verify User B cannot retrieve, list, or start assessments on User A's assets and sessions."""
    headers_a = {"Authorization": "Bearer token_user_a"}
    headers_b = {"Authorization": "Bearer token_user_b"}

    # 1. User A registers an asset
    asset_payload = {
        "host_identifier": "c" * 64,
        "hostname": "user-a-workstation",
        "os_family": "linux",
        "os_name": "Ubuntu 22.04 LTS",
        "os_version": "22.04",
        "os_build": "6.5.0-28-generic",
        "architecture": "x86_64",
    }
    create_asset_resp = client.post("/api/v1/os/assets", json=asset_payload, headers=headers_a)
    assert create_asset_resp.status_code == 201
    asset_a_id = create_asset_resp.json()["id"]

    # 2. User B attempts to read User A's asset directly
    get_asset_b_resp = client.get(f"/api/v1/os/assets/{asset_a_id}", headers=headers_b)
    assert get_asset_b_resp.status_code == 403
    assert "not authorized" in get_asset_b_resp.json()["message"].lower()

    # 3. User B attempts to initialize an assessment targeting User A's asset
    assess_create_b_resp = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": asset_a_id, "assessment_type": "local_read_only"},
        headers=headers_b,
    )
    assert assess_create_b_resp.status_code == 403
    assert "not authorized" in assess_create_b_resp.json()["message"].lower()

    # 4. User A initializes an assessment session
    assess_create_a_resp = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": asset_a_id, "assessment_type": "local_read_only"},
        headers=headers_a,
    )
    assert assess_create_a_resp.status_code == 201
    assess_a_id = assess_create_a_resp.json()["id"]

    # 5. User B attempts to inspect User A's assessment session
    get_assess_b_resp = client.get(f"/api/v1/os/assessments/{assess_a_id}", headers=headers_b)
    assert get_assess_b_resp.status_code == 403
    assert "not authorized" in get_assess_b_resp.json()["message"].lower()

    # 6. User B attempts to trigger assessment execution on User A's assessment session
    start_b_resp = client.post(f"/api/v1/os/assessments/{assess_a_id}/assess", headers=headers_b)
    assert start_b_resp.status_code == 403
    assert "not authorized" in start_b_resp.json()["message"].lower()

    # 7. User B lists assessments — User A's assessment must NOT appear in User B's list
    list_b_resp = client.get("/api/v1/os/assessments", headers=headers_b)
    assert list_b_resp.status_code == 200
    b_assessment_ids = [item["id"] for item in list_b_resp.json()["items"]]
    assert assess_a_id not in b_assessment_ids


# ==============================================================================
# 6. Unauthorized Access to Evidence, Findings, Risk, & Remediation (Scenario 6)
# ==============================================================================

def test_unauthorized_access_to_evidence_findings_risk_remediation_blocked(
    client: TestClient, db_session: Session
) -> None:
    """Verify that User B cannot access evidence, findings, risk, or remediation of User A's assessment."""
    headers_a = {"Authorization": "Bearer token_user_a"}
    headers_b = {"Authorization": "Bearer token_user_b"}

    # User A creates and completes an assessment session
    mgr = OSCollectorManager()
    mgr.register(MockSecurityAuditCollector())

    create_resp = client.post("/api/v1/os/assessments", json={}, headers=headers_a)
    assert create_resp.status_code == 201
    assessment_id = create_resp.json()["id"]

    with patch.object(os_assessment_service, "get_default_os_collector_manager", return_value=mgr):
        run_resp = client.post(f"/api/v1/os/assessments/{assessment_id}/assess", headers=headers_a)
        assert run_resp.status_code == 200

    # User B attempts to access Evidence
    ev_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/evidence", headers=headers_b)
    assert ev_resp.status_code == 403
    assert "not authorized" in ev_resp.json()["message"].lower()

    # User B attempts to access Findings
    find_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/findings", headers=headers_b)
    assert find_resp.status_code == 403
    assert "not authorized" in find_resp.json()["message"].lower()

    # User B attempts to access Risk Evaluation
    risk_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/risk", headers=headers_b)
    assert risk_resp.status_code == 403
    assert "not authorized" in risk_resp.json()["message"].lower()

    # User B attempts to access Remediation Plan
    rem_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/remediation", headers=headers_b)
    assert rem_resp.status_code == 403
    assert "not authorized" in rem_resp.json()["message"].lower()


# ==============================================================================
# 7. Authorization Bypass Attempt Using X-Asset-Authorized (Scenario 7)
# ==============================================================================

def test_x_asset_authorized_header_bypass_rejected(client: TestClient, db_session: Session) -> None:
    """Verify that sending 'X-Asset-Authorized: true' does NOT grant authorization to remote assets."""
    headers_auth = {"Authorization": "Bearer token_user_a"}

    # Create a remote asset belonging to user_a
    remote_asset = OSAssetRecord(
        host_identifier="d" * 64,  # Distinct non-local host identifier
        hostname="external-datacenter-host.domain",
        os_family="linux",
        os_name="Ubuntu 22.04 LTS",
        architecture="x86_64",
        owner_id="user_a",
    )
    db_session.add(remote_asset)
    db_session.commit()
    db_session.refresh(remote_asset)

    # Initialize assessment session
    create_resp = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": remote_asset.id, "assessment_type": "local_read_only"},
        headers=headers_auth,
    )
    assert create_resp.status_code == 201
    assessment_id = create_resp.json()["id"]

    # Attempt to bypass remote restriction by supplying X-Asset-Authorized: true
    bypass_headers = {
        "Authorization": "Bearer token_user_a",
        "X-Asset-Authorized": "true",
        "X-Authorized": "true",
    }
    with patch("app.services.os_assessment_service.get_anonymized_host_identifier", return_value="local_host_hash"):
        run_resp = client.post(
            f"/api/v1/os/assessments/{assessment_id}/assess",
            headers=bypass_headers,
        )

    # Must be strictly rejected with 403 Forbidden!
    assert run_resp.status_code == 403
    assert "explicitly authorized" in run_resp.json()["message"].lower() or "not authorized" in run_resp.json()["message"].lower()


# ==============================================================================
# 8. Unauthorized Remote Asset Access (Scenario 8)
# ==============================================================================

def test_unauthorized_remote_asset_assessment_strictly_blocked(
    client: TestClient, db_session: Session
) -> None:
    """Verify that remote machines without server-side authorization are strictly rejected."""
    headers_auth = {"Authorization": "Bearer token_user_a"}

    remote_asset = OSAssetRecord(
        host_identifier="e" * 64,
        hostname="untrusted-remote-machine.corp",
        os_family="linux",
        os_name="Debian 12 Bookworm",
        architecture="x86_64",
        owner_id="user_a",
    )
    db_session.add(remote_asset)
    db_session.commit()
    db_session.refresh(remote_asset)

    create_resp = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": remote_asset.id, "assessment_type": "local_read_only"},
        headers=headers_auth,
    )
    assert create_resp.status_code == 201
    assessment_id = create_resp.json()["id"]

    with patch("app.services.os_assessment_service.get_anonymized_host_identifier", return_value="local_host_hash"):
        run_resp = client.post(
            f"/api/v1/os/assessments/{assessment_id}/assess",
            headers=headers_auth,
        )

    assert run_resp.status_code == 403
    assert "explicitly authorized" in run_resp.json()["message"].lower()


# ==============================================================================
# 9. Valid Authorized Access and Administrative Access (Scenario 9)
# ==============================================================================

def test_valid_authorized_owner_and_admin_access(client: TestClient) -> None:
    """Verify that authorized owner has complete access and admin can inspect all resources."""
    headers_owner = {"Authorization": "Bearer token_user_a"}
    headers_admin = {"Authorization": "Bearer admin_token"}

    # Owner creates asset
    create_asset_resp = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "f" * 64,
            "hostname": "authorized-node",
            "os_family": "linux",
            "os_name": "Ubuntu 22.04 LTS",
        },
        headers=headers_owner,
    )
    assert create_asset_resp.status_code == 201
    asset_id = create_asset_resp.json()["id"]

    # Owner retrieves asset
    owner_get = client.get(f"/api/v1/os/assets/{asset_id}", headers=headers_owner)
    assert owner_get.status_code == 200

    # Admin retrieves asset
    admin_get = client.get(f"/api/v1/os/assets/{asset_id}", headers=headers_admin)
    assert admin_get.status_code == 200
    assert admin_get.json()["id"] == asset_id

    # Owner creates assessment session
    mgr = OSCollectorManager()
    mgr.register(MockSecurityAuditCollector())

    create_assess_resp = client.post("/api/v1/os/assessments", json={}, headers=headers_owner)
    assert create_assess_resp.status_code == 201
    assess_id = create_assess_resp.json()["id"]

    with patch.object(os_assessment_service, "get_default_os_collector_manager", return_value=mgr):
        run_resp = client.post(f"/api/v1/os/assessments/{assess_id}/assess", headers=headers_owner)
        assert run_resp.status_code == 200

    # Owner and Admin can both view assessment, evidence, findings, risk, and remediation
    for headers in [headers_owner, headers_admin]:
        resp_detail = client.get(f"/api/v1/os/assessments/{assess_id}", headers=headers)
        assert resp_detail.status_code == 200
        assert resp_detail.json()["status"] == "completed"

        resp_ev = client.get(f"/api/v1/os/assessments/{assess_id}/evidence", headers=headers)
        assert resp_ev.status_code == 200

        resp_find = client.get(f"/api/v1/os/assessments/{assess_id}/findings", headers=headers)
        assert resp_find.status_code == 200

        resp_risk = client.get(f"/api/v1/os/assessments/{assess_id}/risk", headers=headers)
        assert resp_risk.status_code == 200

        resp_rem = client.get(f"/api/v1/os/assessments/{assess_id}/remediation", headers=headers)
        assert resp_rem.status_code == 200


# ==============================================================================
# 10. Regression Testing: URL Analysis & System Endpoints (Scenario 10)
# ==============================================================================

def test_regression_url_analyses_and_system_endpoints(client: TestClient) -> None:
    """Verify that URL analyses, threat intel, and system endpoints continue functioning without regression."""
    # System info (unauthenticated public)
    info_resp = client.get("/api/v1")
    assert info_resp.status_code == 200
    assert "app_name" in info_resp.json()

    # Health check
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    # URL Analysis creation
    url_resp = client.post("/api/v1/analyses", json={"url": "https://secops-audit.example.com"})
    assert url_resp.status_code == 201
    analysis_id = url_resp.json()["id"]

    # URL Analysis retrieval
    get_url_resp = client.get(f"/api/v1/analyses/{analysis_id}")
    assert get_url_resp.status_code == 200
    assert get_url_resp.json()["url"] == "https://secops-audit.example.com"


# ==============================================================================
# 11. Production Environment Guardrail & Client Owner Override Rejection
# ==============================================================================

def test_development_tokens_rejected_in_production_environment(client: TestClient) -> None:
    """Verify that development tokens cannot be used if ENVIRONMENT is set to 'production'."""
    from app.core.config import settings

    with patch.object(settings, "ENVIRONMENT", "production"):
        resp = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer admin_token"})
        assert resp.status_code == 401
        assert "production environment" in resp.json()["message"].lower()


def test_client_cannot_supply_or_override_owner_id(client: TestClient) -> None:
    """Verify that client cannot supply or override owner_id in asset creation payloads."""
    headers = {"Authorization": "Bearer token_user_a"}

    payload = {
        "host_identifier": "9" * 64,
        "hostname": "attacker-spoofed-node",
        "os_family": "linux",
        "os_name": "Ubuntu 22.04 LTS",
        "owner_id": "victim_user_b",  # Attempted override
    }
    resp = client.post("/api/v1/os/assets", json=payload, headers=headers)
    assert resp.status_code == 201

    # Server MUST assign the authenticated identity 'user_a', NOT 'victim_user_b'
    data = resp.json()
    assert data["owner_id"] == "user_a"
    assert data["owner_id"] != "victim_user_b"
