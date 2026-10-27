import pytest
from app.models.models import (
    Asset, DigitalTwin, VulnerabilityFinding, Assessment, EvidenceRecord,
    RemediationRecommendation, RemediationApproval
)
from app.services.remediation_engine import remediation_engine

def test_phase6_evidence_backed_recommendation_generation(client, auth_headers, db_session):
    """Verify evidence-backed remediation recommendation generation using certified templates."""
    # 1. Setup asset, assessment, and finding with evidence
    asset = Asset(
        name="Phase6-Target-Asset",
        ip_address="10.0.6.10",
        hostname="p6-target",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 6 Remediation Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Local Privilege Escalation",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=75.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="High severity polkit vulnerability"
    )
    db_session.add(finding)
    db_session.commit()

    evidence = EvidenceRecord(
        finding_id=finding.id,
        evidence_type="package_manifest",
        title="Package Manifest: policykit-1",
        raw_evidence="dpkg-query: policykit-1 0.105-26 amd64 installed",
        metadata_info={"cve_id": "CVE-2021-4034"}
    )
    db_session.add(evidence)
    db_session.commit()

    # 2. Call recommendation generator endpoint
    gen_res = client.post(f"/api/v1/remediation/findings/{finding.id}/generate", headers=auth_headers)
    assert gen_res.status_code == 201
    rec_data = gen_res.json()

    assert rec_data["finding_id"] == finding.id
    assert rec_data["action_type"] == "package_update"
    assert "policykit-1" in rec_data["title"]
    assert "0.105-31" in rec_data["title"]
    assert "CVE-2021-4034" in rec_data["description"]
    assert "0.105-26" in rec_data["description"]
    assert "evidence" in rec_data["description"].lower()

    # Certified safe command template (no arbitrary shell injection)
    assert "sudo apt-get install --only-upgrade policykit-1=0.105-31 -y" == rec_data["command_preview"]
    assert "allow-downgrades" in rec_data["rollback_instructions"]
    assert "ubuntu.com" in rec_data["vendor_advisory_url"]
    assert rec_data["status"] == "recommended"

def test_phase6_approval_and_rejection_workflows(client, auth_headers, db_session):
    """Verify approval and rejection governance workflows with mandatory justifications."""
    # 1. Setup recommendation
    asset = Asset(
        name="Phase6-Governance-Asset",
        ip_address="10.0.6.20",
        hostname="p6-gov",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="staging",
        criticality="high"
    )
    db_session.add(asset)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Phase 6 Governance", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2023-38408",
        title="OpenSSH Agent PKCS11",
        affected_component="openssh-server",
        installed_version="8.9p1",
        fixed_version="9.3p1",
        cvss_v3_score=9.8,
        severity="critical",
        detection_status="detected"
    )
    db_session.add(finding)
    db_session.commit()

    rec_1 = RemediationRecommendation(
        finding_id=finding.id,
        action_type="package_update",
        title="Upgrade openssh-server to 9.3p1",
        description="Fixes RCE in ssh-agent forwarding",
        command_preview="sudo apt-get install --only-upgrade openssh-server=9.3p1 -y",
        status="recommended"
    )
    rec_2 = RemediationRecommendation(
        finding_id=finding.id,
        action_type="package_update",
        title="Upgrade openssh-server alternative",
        description="Alternative candidate",
        command_preview="sudo apt-get install --only-upgrade openssh-server=9.3p1 -y",
        status="recommended"
    )
    db_session.add_all([rec_1, rec_2])
    db_session.commit()

    # 2. Test rejection without justification -> MUST FAIL (HTTP 400)
    empty_just_res = client.post(f"/api/v1/remediation/recommendations/{rec_1.id}/approval", headers=auth_headers, json={
        "status": "approved",
        "justification": "  "
    })
    assert empty_just_res.status_code == 400
    assert "justification is required" in empty_just_res.json()["detail"].lower()

    # 3. Test successful approval with justification
    app_res = client.post(f"/api/v1/remediation/recommendations/{rec_1.id}/approval", headers=auth_headers, json={
        "status": "approved",
        "justification": "Approved for non-destructive testing inside digital twin lab."
    })
    assert app_res.status_code == 200
    assert app_res.json()["status"] == "approved"

    db_session.refresh(rec_1)
    assert rec_1.status == "approved"

    # Verify RemediationApproval record in database
    approval_rec = db_session.query(RemediationApproval).filter(
        RemediationApproval.recommendation_id == rec_1.id
    ).first()
    assert approval_rec is not None
    assert approval_rec.status == "approved"
    assert approval_rec.target_environment == "twin_lab"
    assert "digital twin lab" in approval_rec.justification

    # Query approvals history endpoint
    hist_res = client.get(f"/api/v1/remediation/recommendations/{rec_1.id}/approvals", headers=auth_headers)
    assert hist_res.status_code == 200
    assert len(hist_res.json()) >= 1
    assert hist_res.json()[0]["status"] == "approved"

    # 4. Test rejection workflow on rec_2
    rej_res = client.post(f"/api/v1/remediation/recommendations/{rec_2.id}/approval", headers=auth_headers, json={
        "status": "rejected",
        "justification": "Rejected due to service dependency freeze."
    })
    assert rej_res.status_code == 200
    assert rej_res.json()["status"] == "rejected"
    db_session.refresh(rec_2)
    assert rec_2.status == "rejected"

def test_phase6_safe_lab_remediation_adapter_application(client, auth_headers, db_session):
    """Verify predefined safe lab remediation adapter applies changes strictly in twin sandbox."""
    # 1. Setup asset, twin, finding, and approved recommendation
    asset = Asset(
        name="Phase6-Lab-Asset",
        ip_address="10.0.6.30",
        hostname="p6-lab-srv",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Remediation-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        target_config={"kernel": "5.15", "policykit-1": "0.105-26"},
        current_config={"kernel": "5.15", "policykit-1": "0.105-26"},
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Phase 6 Lab Assessment", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="detected"
    )
    db_session.add(finding)
    db_session.commit()

    rec = RemediationRecommendation(
        finding_id=finding.id,
        action_type="package_update",
        title="Upgrade policykit-1 to 0.105-31",
        description="Security patch upgrade",
        command_preview="sudo apt-get install --only-upgrade policykit-1=0.105-31 -y",
        prerequisites=["sudo apt-get update"],
        status="approved" # ALREADY APPROVED
    )
    db_session.add(rec)
    db_session.commit()

    # 2. Apply approved remediation in digital twin
    apply_res = client.post(f"/api/v1/remediation/recommendations/{rec.id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": twin.id
    })
    assert apply_res.status_code == 200
    apply_data = apply_res.json()

    assert apply_data["status"] == "applied_in_twin"
    assert apply_data["result"]["success"] is True
    assert apply_data["result"]["version_after"] == "0.105-31"
    assert "REMEDIATION ADAPTER EXECUTION" in apply_data["result"]["execution_log"]

    # Verify recommendation status is applied_in_twin
    db_session.refresh(rec)
    assert rec.status == "applied_in_twin"

    # Verify finding status is marked suspected (pending retest verification)
    db_session.refresh(finding)
    assert finding.detection_status == "suspected"

    # Verify twin's current configuration updated with patched version
    db_session.refresh(twin)
    assert twin.current_config["packages"]["policykit-1"] == "0.105-31"
    assert twin.status == "ready"

    # Verify Forensic EvidenceRecord created for the remediation execution
    ev_records = db_session.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()
    rem_evidence = next((e for e in ev_records if e.evidence_type == "remediation_log"), None)
    assert rem_evidence is not None
    assert "Lab Remediation Applied" in rem_evidence.title
    assert rem_evidence.metadata_info["version_after"] == "0.105-31"
    assert rem_evidence.metadata_info["twin_id"] == twin.id

def test_phase6_production_protection_never_auto_change_production(client, auth_headers, db_session):
    """Verify strict backend protection prevents changing production systems or applying unapproved changes."""
    # 1. Setup asset and digital twin
    asset = Asset(
        name="Phase6-Prod-Asset",
        ip_address="10.0.6.40",
        hostname="prod-critical",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Prod-Protection",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="stopped", # STOPPED TWIN
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline"
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Prod Protection", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="detected"
    )
    db_session.add(finding)
    db_session.commit()

    # Unapproved recommendation (status == recommended)
    unapproved_rec = RemediationRecommendation(
        finding_id=finding.id,
        action_type="package_update",
        title="Upgrade policykit-1",
        description="Policykit security upgrade advisory",
        command_preview="sudo apt-get install --only-upgrade policykit-1=0.105-31 -y",
        status="recommended"
    )
    db_session.add(unapproved_rec)
    db_session.commit()

    # Protection Guard 1: Applying unapproved recommendation -> MUST BE BLOCKED (HTTP 400)
    unapproved_res = client.post(f"/api/v1/remediation/recommendations/{unapproved_rec.id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": twin.id
    })
    assert unapproved_res.status_code == 400
    assert "must be explicitly approved" in unapproved_res.json()["detail"].lower()

    # Approve recommendation
    unapproved_rec.status = "approved"
    db_session.commit()

    # Protection Guard 2: Applying to stopped twin -> MUST BE BLOCKED (HTTP 400)
    stopped_res = client.post(f"/api/v1/remediation/recommendations/{unapproved_rec.id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": twin.id
    })
    assert stopped_res.status_code == 400
    assert "must be 'ready'" in stopped_res.json()["detail"].lower()

    # Set twin to ready, but unisolated
    twin.status = "ready"
    twin.network_isolated = False
    db_session.commit()

    # Protection Guard 3: Applying to unisolated environment -> MUST BE BLOCKED (HTTP 400)
    uniso_res = client.post(f"/api/v1/remediation/recommendations/{unapproved_rec.id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": twin.id
    })
    assert uniso_res.status_code == 400
    assert "airgap required" in uniso_res.json()["detail"].lower() or "not network-isolated" in uniso_res.json()["detail"].lower()

    # Protection Guard 4: Passing production asset ID instead of twin replica -> MUST BE REJECTED (HTTP 404)
    prod_target_res = client.post(f"/api/v1/remediation/recommendations/{unapproved_rec.id}/apply-in-twin", headers=auth_headers, json={
        "twin_id": asset.id # Production asset, not a twin!
    })
    assert prod_target_res.status_code == 404
