"""Automated integration and unit tests for Milestone 6: OS Assessment API Integration.

Validates:
1. Successful OS asset creation and retrieval.
2. Successful OS assessment creation and retrieval (with asset_id and default local asset).
3. Input validation, schema constraints, and rejection of unsupported operating systems.
4. Assessment lifecycle transitions (pending -> running -> completed) and duplicate rejection (409 Conflict).
5. Safe failure handling on collector crashes or zero evidence without false completion.
6. Incomplete inventory and advisory provider failures handled as uncertainty or safe failure.
7. Exploitability state strictly remaining UNKNOWN across all endpoints and responses.
8. Risk-score, finding, and evidence endpoints consistency and deterministic calculation.
9. Explainable remediation recommendations strictly remaining unapplied proposals (is_applied=False).
10. Access control enforcement, token validation, and blocking unauthorized assessment records.
11. Regression prevention for existing URL analyses, threat intel, health, and system endpoints.
"""

from typing import Any, Dict, List
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
from app.schemas.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)
from app.services import os_assessment_service
from app.services.os_collectors.base import BaseOSCollector
from app.services.os_collectors.manager import OSCollectorManager
from app.services.os_matcher.advisory_provider import AdvisoryEntry, MockAdvisoryProvider
from app.services.os_matcher.vulnerability_matcher import OSVulnerabilityMatcher
from app.services.os_risk_engine.engine import OSRiskEngine


# ==============================================================================
# Helper Fixtures, Mock Collectors & Providers
# ==============================================================================

@pytest.fixture(autouse=True)
def default_auth_headers(client: TestClient) -> None:
    """Ensure all Milestone 6 API test calls carry authorized bearer credentials."""
    client.headers["Authorization"] = "Bearer valid_token_user_a"

class MockLinuxCollector(BaseOSCollector):
    """Deterministic Linux mock collector providing OS release and dpkg package inventory."""

    @property
    def name(self) -> str:
        return "mock_linux_collector"

    @property
    def check_id(self) -> str:
        return "dpkg_installed_packages"

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux", "windows"]

    def collect(self, context: Any = None) -> List[OSEvidenceItemCreate]:
        return [
            OSEvidenceItemCreate(
                collector_name="mock_linux_collector",
                check_id="linux_os_release",
                signal_name="os_release_info",
                observed_value="Ubuntu 22.04 LTS (jammy)",
                structured_data={
                    "distro_id": "ubuntu",
                    "version_codename": "jammy",
                    "pretty_name": "Ubuntu 22.04.4 LTS",
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
            ),
            OSEvidenceItemCreate(
                collector_name="mock_linux_collector",
                check_id="dpkg_installed_packages",
                signal_name="installed_package",
                observed_value="libc6 2.35-0ubuntu3.1, openssl 3.0.2-0ubuntu1.10",
                structured_data={
                    "packages": [
                        {
                            "package": "libc6",
                            "version": "2.35-0ubuntu3.1",
                            "architecture": "amd64",
                        },
                        {
                            "package": "openssl",
                            "version": "3.0.2-0ubuntu1.10",
                            "architecture": "amd64",
                        },
                    ]
                },
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
            ),
            OSEvidenceItemCreate(
                collector_name="mock_linux_collector",
                check_id="linux_kernel_hardening",
                signal_name="aslr_setting",
                observed_value="randomize_va_space=0",
                structured_data={"randomize_va_space": 0},
                collection_status=OSEvidenceStatus.OBSERVED,
                permission_state=OSPermissionState.GRANTED,
            ),
        ]


class MockFailingCollector(BaseOSCollector):
    """Mock collector simulating catastrophic runtime probe crash."""

    @property
    def name(self) -> str:
        return "failing_collector"

    @property
    def check_id(self) -> str:
        return "fatal_probe"

    @property
    def supported_os_families(self) -> List[str]:
        return ["linux", "windows"]

    def collect(self, context: Any = None) -> List[OSEvidenceItemCreate]:
        raise RuntimeError("Kernel driver probe fault")


# ==============================================================================
# 1. OS Asset Creation and Retrieval Tests
# ==============================================================================

def test_create_os_asset_success(client: TestClient) -> None:
    """Verify creating an OS asset returns 201 Created with valid schema."""
    payload = {
        "host_identifier": "a" * 64,
        "hostname": "prod-web-01",
        "os_family": "linux",
        "os_name": "Ubuntu 22.04.4 LTS",
        "os_version": "22.04",
        "os_build": "6.5.0-28-generic",
        "architecture": "x86_64",
    }
    response = client.post("/api/v1/os/assets", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert len(data["id"]) == 36
    assert data["hostname"] == "prod-web-01"
    assert data["os_family"] == "linux"
    assert data["architecture"] == "x86_64"
    assert "collected_at" in data


def test_list_os_assets(client: TestClient) -> None:
    """Verify paginated listing of registered OS assets."""
    # Create two assets
    client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "1" * 64,
            "hostname": "host-alpha",
            "os_family": "linux",
            "os_name": "Ubuntu 22.04",
            "architecture": "x86_64",
        },
    )
    client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "2" * 64,
            "hostname": "host-beta",
            "os_family": "windows",
            "os_name": "Windows 11 Pro",
            "architecture": "x86_64",
        },
    )

    response = client.get("/api/v1/os/assets?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert data["total"] >= 2
    assert len(data["items"]) >= 2
    assert data["limit"] == 10
    assert data["offset"] == 0


def test_get_os_asset_by_id(client: TestClient) -> None:
    """Verify retrieving an individual OS asset by unique UUID."""
    create_resp = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "b" * 64,
            "hostname": "sec-scanner",
            "os_family": "linux",
            "os_name": "Debian 12 Bookworm",
            "architecture": "aarch64",
        },
    )
    asset_id = create_resp.json()["id"]

    response = client.get(f"/api/v1/os/assets/{asset_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == asset_id
    assert data["hostname"] == "sec-scanner"
    assert data["architecture"] == "aarch64"


def test_get_nonexistent_os_asset_returns_404(client: TestClient) -> None:
    """Verify 404 response when querying a non-existent asset ID."""
    response = client.get("/api/v1/os/assets/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["message"].lower()


# ==============================================================================
# 2. Input Validation and Unsupported Operating Systems
# ==============================================================================

def test_create_os_asset_missing_fields_validation_error(client: TestClient) -> None:
    """Verify 422 Unprocessable Entity when required fields are missing."""
    payload = {"hostname": "broken-host"}  # missing host_identifier, os_family, os_name
    response = client.post("/api/v1/os/assets", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "Validation Error"


def test_create_os_asset_unsupported_os_family(client: TestClient) -> None:
    """Verify rejection when an unsupported OS family (e.g. solaris) is submitted."""
    payload = {
        "host_identifier": "c" * 64,
        "hostname": "solaris-server",
        "os_family": "solaris",
        "os_name": "SunOS 5.11",
        "architecture": "sparc",
    }
    response = client.post("/api/v1/os/assets", json=payload)
    assert response.status_code == 422  # Caught by Pydantic field_validator
    data = response.json()
    assert "unsupported operating system family" in str(data).lower()


def test_create_os_assessment_unauthorized_type(client: TestClient) -> None:
    """Verify rejection of non-local_read_only assessment modes (e.g. remote_shell, active_attack)."""
    payload = {
        "assessment_type": "remote_shell_execution",
    }
    response = client.post("/api/v1/os/assessments", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "unauthorized assessment type" in str(data).lower()


def test_create_os_assessment_nonexistent_asset(client: TestClient) -> None:
    """Verify 404 when referencing a non-existent asset_id."""
    payload = {
        "asset_id": "00000000-0000-0000-0000-000000000000",
        "assessment_type": "local_read_only",
    }
    response = client.post("/api/v1/os/assessments", json=payload)
    assert response.status_code == 404


def test_start_assessment_unsupported_os_family_fails(client: TestClient, db_session: Session) -> None:
    """Verify that attempting to assess an asset with an unsupported OS fails with clear error."""
    # Create an asset directly in DB with an unsupported family
    unsupported_asset = OSAssetRecord(
        host_identifier="u" * 64,
        hostname="darwin-box",
        os_family="darwin",
        os_name="macOS Sonoma",
        architecture="arm64",
    )
    db_session.add(unsupported_asset)
    db_session.commit()
    db_session.refresh(unsupported_asset)

    assessment = OSAssessmentRecord(
        asset_id=unsupported_asset.id,
        assessment_type="local_read_only",
        status=OSAssessmentStatus.PENDING.value,
    )
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(assessment)

    response = client.post(f"/api/v1/os/assessments/{assessment.id}/assess")
    assert response.status_code == 400
    data = response.json()
    assert "unsupported operating system" in data["message"].lower()


# ==============================================================================
# 3. Assessment Lifecycle and Execution Tests
# ==============================================================================

def test_create_os_assessment_with_asset(client: TestClient) -> None:
    """Verify creating a pending assessment linked to an existing asset."""
    asset_resp = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "d" * 64,
            "hostname": "ubuntu-node-01",
            "os_family": "linux",
            "os_name": "Ubuntu 22.04 LTS",
            "architecture": "x86_64",
        },
    )
    asset_id = asset_resp.json()["id"]

    response = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": asset_id, "assessment_type": "local_read_only"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["asset_id"] == asset_id
    assert data["status"] == "pending"
    assert data["assessment_type"] == "local_read_only"
    assert data["exploitability_state"] == "unknown"


def test_create_os_assessment_default_local_machine(client: TestClient) -> None:
    """Verify creating an assessment without asset_id auto-discovers and registers local host."""
    response = client.post(
        "/api/v1/os/assessments",
        json={"assessment_type": "local_read_only"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"
    assert data["asset_id"] is not None


def test_list_and_get_os_assessment(client: TestClient) -> None:
    """Verify listing and retrieving assessment sessions."""
    create_resp = client.post(
        "/api/v1/os/assessments",
        json={"assessment_type": "local_read_only"},
    )
    assessment_id = create_resp.json()["id"]

    # List
    list_resp = client.get("/api/v1/os/assessments")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # Get by ID
    get_resp = client.get(f"/api/v1/os/assessments/{assessment_id}")
    assert get_resp.status_code == 200
    detail = get_resp.json()
    assert detail["id"] == assessment_id
    assert detail["status"] == "pending"
    assert "asset" in detail
    assert "evidence_items" in detail
    assert "findings" in detail


def test_run_local_assessment_success(client: TestClient) -> None:
    """Verify full end-to-end local assessment execution (pending -> running -> completed)."""
    # Create asset
    asset_resp = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "e" * 64,
            "hostname": "localhost",
            "os_family": "linux",
            "os_name": "Ubuntu 22.04 LTS",
            "architecture": "x86_64",
        },
    )
    asset_id = asset_resp.json()["id"]

    # Create assessment
    ass_resp = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": asset_id, "assessment_type": "local_read_only"},
    )
    assessment_id = ass_resp.json()["id"]

    # Setup mock manager and matcher
    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())

    mock_matcher = OSVulnerabilityMatcher()
    mock_provider = MockAdvisoryProvider("canonical_usn", "linux", [
        AdvisoryEntry(
            advisory_id="USN-6409-1",
            cve_id="CVE-2023-4911",
            package_name="libc6",
            affected_codename="jammy",
            affected_architecture="all",
            fixed_version="2.35-0ubuntu3.4",
            severity=OSSeverity.CRITICAL,
            cvss_score=9.8,
            title="GLIBC buffer overflow in ld.so",
            source="canonical_usn",
        )
    ])
    mock_matcher.register_provider(mock_provider)

    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager), \
         patch("app.services.os_assessment_service.get_default_os_vulnerability_matcher", return_value=mock_matcher):
        response = client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "completed"
    assert data["completed_at"] is not None
    assert data["risk_score"] is not None
    assert data["risk_score"] > 0
    assert data["exploitability_state"] == "unknown"  # Strictly UNKNOWN

    # Evidence items must be populated
    assert len(data["evidence_items"]) >= 3

    # Findings must include both CVE and misconfiguration
    assert len(data["findings"]) >= 2
    finding_types = [f["finding_type"] for f in data["findings"]]
    assert "cve_vulnerability" in finding_types
    assert "misconfiguration" in finding_types


def test_assessment_duplicate_trigger_rejected_with_409(client: TestClient) -> None:
    """Verify that attempting to re-trigger an already completed assessment returns 409 Conflict."""
    # Create and run
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())
    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        run_resp = client.post(f"/api/v1/os/assessments/{assessment_id}/assess")
        assert run_resp.status_code == 200

    # Second trigger must return 409 Conflict
    dup_resp = client.post(f"/api/v1/os/assessments/{assessment_id}/assess")
    assert dup_resp.status_code == 409
    assert "already in state 'completed'" in str(dup_resp.json()).lower()


def test_assessment_catastrophic_collector_failure_fails_safely(
    client: TestClient, db_session: Session
) -> None:
    """Verify that if all collectors crash or return zero evidence, assessment transitions to FAILED without reporting completion."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockFailingCollector())

    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        response = client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    assert response.status_code == 400
    data = response.json()
    assert "material incompleteness" in data["message"].lower() or "failed" in data["message"].lower()

    # Verify database state shows FAILED and never COMPLETED
    record = db_session.get(OSAssessmentRecord, assessment_id)
    assert record.status == "failed"
    assert record.completed_at is not None
    assert record.error_message is not None


# ==============================================================================
# 4. Incomplete Inventory and Provider Failures
# ==============================================================================

def test_assessment_missing_inventory_fails_safely(client: TestClient, db_session: Session) -> None:
    """Verify that materially incomplete inventory prevents false completion and records failure."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())

    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        response = client.post(
            f"/api/v1/os/assessments/{assessment_id}/assess",
            headers={"X-Missing-Inventory": "true"},
        )

    assert response.status_code == 400
    record = db_session.get(OSAssessmentRecord, assessment_id)
    assert record.status == "failed"
    assert "materially incomplete" in record.error_message.lower()


def test_assessment_provider_failure_applies_uncertainty_floor(client: TestClient) -> None:
    """Verify that advisory provider failure or timeout adds uncertainty floor and keeps confidence LOW."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())

    # Matcher with no providers -> provider failure / limitation
    mock_matcher = OSVulnerabilityMatcher()

    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager), \
         patch("app.services.os_assessment_service.get_default_os_vulnerability_matcher", return_value=mock_matcher):
        response = client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["confidence_level"] == "low"
    assert data["risk_score"] >= 30  # Uncertainty floor applied

    # Fetch risk detail
    risk_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/risk")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert risk_data["is_complete"] is False
    assert any("uncertainty" in r.lower() or "provider" in r.lower() for r in risk_data["score_rationale"] + risk_data["limitations"])


# ==============================================================================
# 5. Risk-Score and Finding Consistency
# ==============================================================================

def test_assessment_evidence_endpoint(client: TestClient) -> None:
    """Verify GET /assessments/{id}/evidence returns counts and telemetry."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())
    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    response = client.get(f"/api/v1/os/assessments/{assessment_id}/evidence")
    assert response.status_code == 200
    data = response.json()

    assert data["assessment_id"] == assessment_id
    assert data["total"] >= 3
    assert data["observed_count"] >= 3
    assert data["error_count"] == 0


def test_assessment_findings_endpoint(client: TestClient) -> None:
    """Verify GET /assessments/{id}/findings returns categorized security findings."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())
    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    response = client.get(f"/api/v1/os/assessments/{assessment_id}/findings")
    assert response.status_code == 200
    data = response.json()

    assert data["assessment_id"] == assessment_id
    assert data["total"] >= 1
    assert "items" in data
    for item in data["items"]:
        assert item["exploitability"] == "unknown"


def test_assessment_risk_endpoint_consistency(client: TestClient) -> None:
    """Verify GET /assessments/{id}/risk returns transparent score rationale matching OSRiskEngine."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())
    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        run_data = client.post(f"/api/v1/os/assessments/{assessment_id}/assess").json()

    risk_resp = client.get(f"/api/v1/os/assessments/{assessment_id}/risk")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()

    assert risk_data["risk_score"] == run_data["risk_score"]
    assert risk_data["risk_level"] == run_data["risk_level"]
    assert risk_data["confidence_level"] == run_data["confidence_level"]
    assert risk_data["exploitability_state"] == "unknown"
    assert "score_rationale" in risk_data
    assert len(risk_data["score_rationale"]) > 0


# ==============================================================================
# 6. Remediation Recommendations Unapplied Verification
# ==============================================================================

def test_assessment_remediation_plan_recommendations_unapplied(client: TestClient) -> None:
    """Verify remediation plan is recommendation-only and is_applied is strictly False."""
    ass_resp = client.post("/api/v1/os/assessments", json={"assessment_type": "local_read_only"})
    assessment_id = ass_resp.json()["id"]

    mock_manager = OSCollectorManager()
    mock_manager.register(MockLinuxCollector())
    with patch("app.services.os_assessment_service.get_default_os_collector_manager", return_value=mock_manager):
        client.post(f"/api/v1/os/assessments/{assessment_id}/assess")

    response = client.get(f"/api/v1/os/assessments/{assessment_id}/remediation")
    assert response.status_code == 200
    data = response.json()

    assert data["assessment_id"] == assessment_id
    assert data["total_recommendations"] >= 1
    assert len(data["recommendations"]) == data["total_recommendations"]
    assert "remediation_summary" in data

    # Crucial security guarantee: All recommendations must remain unapplied
    for rec in data["recommendations"]:
        assert rec["is_applied"] is False, "Recommendations must never be automatically applied"
        assert len(rec["suggested_action"]) > 0
        assert len(rec["verification_steps"]) > 0


def test_no_arbitrary_remediation_execution_endpoint(client: TestClient) -> None:
    """Verify that no endpoint exists to execute remediation or modify system state."""
    # Attempting to POST to remediation or execute remediation must return 404 or 405
    resp1 = client.post("/api/v1/os/assessments/test-id/remediation")
    assert resp1.status_code in (404, 405)

    resp2 = client.post("/api/v1/os/assessments/test-id/remediate")
    assert resp2.status_code in (404, 405)

    resp3 = client.post("/api/v1/os/assessments/test-id/execute")
    assert resp3.status_code in (404, 405)


# ==============================================================================
# 7. Access Control and Unauthorized Record Access Tests
# ==============================================================================

def test_access_with_invalid_or_unauthorized_token_blocked(client: TestClient) -> None:
    """Verify that requests with unauthorized/invalid authorization tokens receive 401 Unauthorized."""
    # Assets endpoint with unauthorized token
    resp1 = client.get("/api/v1/os/assets", headers={"Authorization": "Bearer unauthorized_token"})
    assert resp1.status_code == 401
    assert "invalid" in resp1.json()["message"].lower() or "unauthorized" in resp1.json()["message"].lower()

    # Assessments endpoint with invalid token
    resp2 = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer invalid"})
    assert resp2.status_code == 401

    # Post asset with revoked token
    resp3 = client.post(
        "/api/v1/os/assets",
        json={"hostname": "test"},
        headers={"Authorization": "Bearer revoked"},
    )
    assert resp3.status_code == 401


def test_access_with_unauthorized_role_blocked(client: TestClient) -> None:
    """Verify that requests with guest role receive 403 Forbidden."""
    resp_guest = client.get("/api/v1/os/assessments", headers={"Authorization": "Bearer guest_token"})
    assert resp_guest.status_code == 403
    assert "insufficient privilege" in resp_guest.json()["message"].lower() or "guest" in resp_guest.json()["message"].lower()


def test_access_with_missing_credentials_blocked(client: TestClient) -> None:
    """Verify that requests without credentials receive 401 Unauthorized."""
    # Clear client default authorization header
    old_auth = client.headers.pop("Authorization", None)
    try:
        resp = client.get("/api/v1/os/assessments")
        assert resp.status_code == 401
        assert "missing" in resp.json()["message"].lower()
    finally:
        if old_auth:
            client.headers["Authorization"] = old_auth


def test_assess_unauthorized_remote_asset_rejected(client: TestClient, db_session: Session) -> None:
    """Verify that attempting to assess a remote asset without authorization is blocked with 403 Forbidden."""
    # Create remote asset with a distinct host identifier
    remote_asset = OSAssetRecord(
        host_identifier="f" * 64,  # Not local machine
        hostname="remote-server.corp",
        os_family="linux",
        os_name="Ubuntu 22.04 LTS",
        architecture="x86_64",
    )
    db_session.add(remote_asset)
    db_session.commit()
    db_session.refresh(remote_asset)

    assessment = OSAssessmentRecord(
        asset_id=remote_asset.id,
        assessment_type="local_read_only",
        status=OSAssessmentStatus.PENDING.value,
    )
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(assessment)

    # Local host identifier is "0" * 64, remote asset is "f" * 64
    with patch("app.services.os_assessment_service.get_anonymized_host_identifier", return_value="0" * 64):
        response = client.post(f"/api/v1/os/assessments/{assessment.id}/assess")

    assert response.status_code == 403
    assert "explicitly authorized" in response.json()["message"].lower()


# ==============================================================================
# 8. Regression Prevention Tests
# ==============================================================================

def test_regression_url_analysis_pipeline(client: TestClient) -> None:
    """Verify existing URL analysis creation and passive analysis execution remain fully functional."""
    create_resp = client.post("/api/v1/analyses", json={"url": "https://example.com/checkout"})
    assert create_resp.status_code == 201
    analysis_id = create_resp.json()["id"]

    analyze_resp = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert analyze_resp.status_code == 200
    data = analyze_resp.json()
    assert data["status"] == "completed"
    assert "risk_assessment" in data


def test_regression_system_endpoints(client: TestClient) -> None:
    """Verify existing health, service root, and api_v1 info endpoints remain operational."""
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "app_name" in root_resp.json()

    v1_info = client.get("/api/v1")
    assert v1_info.status_code == 200
    assert v1_info.json()["status"] == "operational"
