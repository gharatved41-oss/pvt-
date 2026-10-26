import pytest
from app.services.inventory_parser import InventoryParser, InventoryParseException
from app.services.cve_service import is_version_vulnerable, cve_service
from app.services.ml_risk_engine import ml_risk_engine
from app.services.twin_engine import twin_engine
from app.services.validation_engine import validation_engine

def test_auth_workflow(client):
    """Test user registration and login token issuance."""
    # Register analyst
    reg_resp = client.post("/api/v1/auth/register", json={
        "email": "analyst@vulntwin.com",
        "password": "SecurePassword123!",
        "full_name": "Security Analyst Jane",
        "role": "analyst"
    })
    assert reg_resp.status_code == 200
    user_data = reg_resp.json()
    assert user_data["email"] == "analyst@vulntwin.com"
    assert user_data["role"] == "analyst"

    # Login
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "analyst@vulntwin.com",
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    assert token_data["role"] == "analyst"

    # Profile check with token
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_data['access_token']}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "analyst@vulntwin.com"

def test_inventory_parser_json():
    """Test parsing of valid and invalid JSON inventory."""
    valid_json = """
    {
        "hostname": "test-box",
        "packages": [
            {"name": "openssh-server", "version": "8.9p1", "architecture": "amd64"},
            {"name": "nginx", "version": "1.24.0", "architecture": "amd64"}
        ],
        "configuration_metadata": {"selinux_enforcing": false}
    }
    """
    pkgs, meta = InventoryParser.parse_json(valid_json)
    assert len(pkgs) == 2
    assert pkgs[0]["name"] == "openssh-server"
    assert meta["selinux_enforcing"] is False

    # Invalid JSON should raise InventoryParseException
    with pytest.raises(InventoryParseException):
        InventoryParser.parse_json("NOT_JSON")

def test_inventory_parser_csv():
    """Test parsing of valid CSV inventory."""
    valid_csv = "package_name,version,architecture\npolicykit-1,0.105-26,amd64\ncurl,7.81.0,amd64\n"
    pkgs, _ = InventoryParser.parse_csv(valid_csv)
    assert len(pkgs) == 2
    assert pkgs[0]["name"] == "policykit-1"

def test_cve_version_matching():
    """Test semantic version range matching logic."""
    # pkexec vulnerable 0.105-0 <= version <= 0.105-31
    assert is_version_vulnerable("0.105-26ubuntu0.1", "0.105-0", "0.105-31") is True
    assert is_version_vulnerable("0.105-32", "0.105-0", "0.105-31") is False

    # openssh vulnerable 5.5p1 <= version <= 9.3p1
    assert is_version_vulnerable("8.9p1-3ubuntu0.1", "5.5p1", "9.3p1") is True
    assert is_version_vulnerable("9.3p2", "5.5p1", "9.3p1") is False

def test_cve_service_deduplication():
    """Test CVE matching and finding deduplication."""
    pkgs = [
        {"name": "policykit-1", "version": "0.105-26ubuntu0.1", "architecture": "amd64"},
        {"name": "policykit-1", "version": "0.105-26ubuntu0.1", "architecture": "amd64"},  # duplicate pkg
        {"name": "nginx", "version": "1.24.0", "architecture": "amd64"},
    ]
    findings = cve_service.find_vulnerabilities("linux", pkgs)
    cve_ids = [f["cve_id"] for f in findings]
    # Check no duplicate CVE IDs
    assert len(cve_ids) == len(set(cve_ids))
    assert "CVE-2021-4034" in cve_ids
    assert "CVE-2023-44487" in cve_ids

def test_ml_risk_engine():
    """Test AI/ML risk scoring separation of severity, risk score, and explainability."""
    res = ml_risk_engine.evaluate_risk(
        cvss_score=9.8,
        asset_criticality="critical",
        asset_environment="production",
        exploit_maturity="high",
        patch_available=True,
        evidence_depth="confirmed",
        detection_status="confirmed"
    )
    assert 80.0 <= res["risk_score"] <= 100.0
    assert res["severity"] == "Critical"
    assert res["risk_category"] == "Critical"
    assert res["confidence_score"] >= 0.9
    assert "cvss_base_impact" in res["contributing_factors"]
    assert len(res["risk_explanation"]) > 20

def test_digital_twin_lifecycle(client, auth_headers):
    """Test provisioning digital twin replica, snapshot, and isolation check."""
    # Create asset
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "Integration Test Host",
        "ip_address": "192.168.1.50",
        "hostname": "int-test-srv",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04 LTS",
        "environment": "staging",
        "criticality": "high"
    })
    asset_id = asset_res.json()["id"]

    # Create twin
    twin_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-IntTest-Lab",
        "template_name": "ubuntu-22.04-cve-lab"
    })
    assert twin_res.status_code == 201
    twin_id = twin_res.json()["id"]
    assert twin_res.json()["network_isolated"] is True

    # Action: verify isolation
    action_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={
        "action": "verify_isolation"
    })
    assert action_res.status_code == 200
    assert action_res.json()["result"]["isolated"] is True

    # Action: reset snapshot
    reset_res = client.post(f"/api/v1/twins/{twin_id}/actions", headers=auth_headers, json={
        "action": "reset_snapshot"
    })
    assert reset_res.status_code == 200
    assert reset_res.json()["result"]["success"] is True

def test_end_to_end_assessment_validation_remediation_retest(client, auth_headers):
    """
    Test complete end-to-end 13-step cybersecurity workflow:
    Asset -> Inventory -> Assessment -> Findings -> Twin -> Validation -> Approval -> Remediation -> Retest -> Report
    """
    # 1. Create Asset
    asset_res = client.post("/api/v1/assets", headers=auth_headers, json={
        "name": "E2E Banking Gateway",
        "ip_address": "10.0.12.5",
        "hostname": "bank-gw-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04.2 LTS",
        "environment": "production",
        "criticality": "critical"
    })
    asset_id = asset_res.json()["id"]

    # 2. Import inventory
    csv_payload = "package_name,version,architecture\npolicykit-1,0.105-26ubuntu0.1,amd64\nnginx,1.24.0,amd64\n"
    inv_res = client.post(
        f"/api/v1/assets/{asset_id}/inventory",
        headers=auth_headers,
        data={"raw_content": csv_payload, "format_type": "csv"}
    )
    assert inv_res.status_code == 200
    assert inv_res.json()["packages_count"] == 2

    # 3. Run assessment
    assess_res = client.post("/api/v1/assessments", headers=auth_headers, json={
        "asset_id": asset_id,
        "title": "Banking Gateway Annual Assessment"
    })
    assert assess_res.status_code == 201
    assessment = assess_res.json()
    assert assessment["status"] == "completed"
    assert assessment["findings_count"] >= 2
    assessment_id = assessment["id"]

    # 4. Check findings
    findings_res = client.get(f"/api/v1/vulnerabilities?assessment_id={assessment_id}", headers=auth_headers)
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) >= 2
    finding = next(f for f in findings if f["cve_id"] == "CVE-2021-4034")
    assert finding["detection_status"] == "detected"
    finding_id = finding["id"]

    # 5. Create Digital Twin
    twin_res = client.post("/api/v1/twins", headers=auth_headers, json={
        "asset_id": asset_id,
        "name": "Twin-Banking-Lab",
        "template_name": "ubuntu-22.04-cve-lab"
    })
    twin_id = twin_res.json()["id"]

    # 6. Controlled validation test
    val_res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding_id,
        "twin_id": twin_id
    })
    assert val_res.status_code == 201
    val_data = val_res.json()
    assert val_data["outcome"] == "confirmed"
    assert val_data["preconditions_met"] is True

    # Check finding is now confirmed
    f_updated = client.get(f"/api/v1/vulnerabilities/{finding_id}", headers=auth_headers).json()
    assert f_updated["detection_status"] == "confirmed"

    # 7. Remediation recommendation & approval
    rec_res = client.get(f"/api/v1/remediation/recommendations?finding_id={finding_id}", headers=auth_headers)
    recs = rec_res.json()
    assert len(recs) > 0
    rec_id = recs[0]["id"]

    # Approve remediation
    appr_res = client.post(f"/api/v1/remediation/recommendations/{rec_id}/approval", headers=auth_headers, json={
        "status": "approved",
        "justification": "Approved for sandbox replication test in digital twin"
    })
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "approved"

    # Apply remediation inside twin
    apply_res = client.post(f"/api/v1/remediation/recommendations/{rec_id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": twin_id
    })
    assert apply_res.status_code == 200
    assert apply_res.json()["status"] == "applied_in_twin"

    # 8. Retest and verification
    retest_res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding_id,
        "twin_id": twin_id
    })
    assert retest_res.status_code == 201
    retest_data = retest_res.json()
    assert retest_data["post_fix_status"] == "resolved"
    assert retest_data["remaining_risk_score"] == 0.0

    # 9. Comparison view
    comp_res = client.get(f"/api/v1/retesting/comparison/{finding_id}", headers=auth_headers)
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["final_status"] == "resolved"
    assert comp_data["remaining_risk"] == 0.0

    # 10. Reports generation (PDF & CSV)
    pdf_res = client.get(f"/api/v1/reports/assessments/{assessment_id}/pdf", headers=auth_headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    csv_res = client.get(f"/api/v1/reports/assessments/{assessment_id}/csv", headers=auth_headers)
    assert csv_res.status_code == 200
    assert "CVE-2021-4034" in csv_res.text

    # 11. Dashboard metrics verification (non-hardcoded real database counts)
    dash_res = client.get("/api/v1/dashboard/metrics", headers=auth_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["total_assets"] >= 1
    assert dash_data["total_assessments"] >= 1
    assert dash_data["total_findings"] >= 2
    assert dash_data["status_breakdown"]["fixed"] >= 1
