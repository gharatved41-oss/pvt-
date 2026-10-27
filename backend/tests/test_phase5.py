import pytest
from app.models.models import Asset, DigitalTwin, VulnerabilityFinding, Assessment, EvidenceRecord, ValidationRun
from app.services.validation_engine import validation_engine

def test_phase5_procedure_registry_specifications(client, auth_headers):
    """Verify registry of approved non-destructive test procedures and specifications."""
    res = client.get("/api/v1/validation/procedures", headers=auth_headers)
    assert res.status_code == 200
    procs = res.json()
    assert len(procs) >= 7

    codes = [p["procedure_code"] for p in procs]
    assert "PROC-SEC-PKEXEC-01" in codes
    assert "PROC-SEC-SSH-AGENT-02" in codes
    assert "PROC-SEC-LOG4J-03" in codes
    assert "PROC-SEC-HTTP2-04" in codes
    assert "PROC-SEC-CURL-05" in codes

    for p in procs:
        assert p["safety_level"] == "safe_non_destructive"
        assert "cve_id" in p or "target_cve" in p
        assert "component" in p or "target_component" in p
        assert len(p["safe_probe"]) > 0
        assert len(p["preconditions"]) > 0

    # Retrieve specific procedure by code
    single_res = client.get("/api/v1/validation/procedures/PROC-SEC-PKEXEC-01", headers=auth_headers)
    assert single_res.status_code == 200
    single_data = single_res.json()
    assert single_data["procedure_code"] == "PROC-SEC-PKEXEC-01"
    assert single_data["component"] == "policykit-1"

    # Nonexistent procedure returns 404
    missing_res = client.get("/api/v1/validation/procedures/NON-EXISTENT-CODE", headers=auth_headers)
    assert missing_res.status_code == 404

def test_phase5_positive_safe_validation_and_evidence_persistence(client, auth_headers, db_session):
    """Verify safe validation execution, reproduction confirmation, and evidence persistence."""
    # 1. Setup asset and digital twin
    asset = Asset(
        name="Phase5-Safe-Target",
        ip_address="10.0.5.10",
        hostname="target-p5",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Safe-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Positive Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    # Vulnerable pkexec version 0.105-26
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
        risk_score=70.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="High severity"
    )
    db_session.add(finding)
    db_session.commit()

    # 2. Execute validation
    exec_res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert exec_res.status_code == 201
    run_data = exec_res.json()
    assert run_data["status"] == "completed"
    assert run_data["outcome"] == "confirmed"
    assert run_data["preconditions_met"] is True
    assert "VULNERABILITY CONFIRMED IN ISOLATED TWIN" in run_data["test_output"]

    # 3. Verify finding detection status transitioned to confirmed
    db_session.refresh(finding)
    assert finding.detection_status == "confirmed"

    # 4. Verify Forensic Evidence Record was persisted in database
    ev_records = db_session.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()
    assert len(ev_records) >= 1
    val_evidence = next((e for e in ev_records if e.evidence_type == "validation_log"), None)
    assert val_evidence is not None
    assert "PROC-SEC-PKEXEC-01" in val_evidence.title
    assert "[CONFIRMED]" in val_evidence.title
    assert "VULNERABILITY CONFIRMED IN ISOLATED TWIN" in val_evidence.raw_evidence
    assert val_evidence.metadata_info["outcome"] == "confirmed"
    assert val_evidence.metadata_info["preconditions_met"] is True
    assert val_evidence.metadata_info["safety_level"] == "safe_non_destructive"
    assert val_evidence.metadata_info["twin_id"] == twin.id

def test_phase5_negative_safe_validation_not_reproduced(client, auth_headers, db_session):
    """Verify non-destructive probe when component is already patched returns not_reproduced."""
    asset = Asset(
        name="Phase5-Patched-Target",
        ip_address="10.0.5.20",
        hostname="target-p5-patched",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="medium"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Patched-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Patched Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    # Patched pkexec version 0.105-32 (vulnerable range is 0.105-0 to 0.105-31)
    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Local Privilege Escalation",
        affected_component="policykit-1",
        installed_version="0.105-32",
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=60.0,
        risk_category="medium",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P2",
        risk_explanation="Vulnerability finding"
    )
    db_session.add(finding)
    db_session.commit()

    exec_res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert exec_res.status_code == 201
    run_data = exec_res.json()
    assert run_data["status"] == "completed"
    assert run_data["outcome"] == "not_reproduced"
    assert run_data["preconditions_met"] is True
    assert "NOT REPRODUCED" in run_data["test_output"]

    # Verify evidence was created for negative test
    db_session.refresh(finding)
    assert finding.detection_status == "inconclusive"
    ev_records = db_session.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()
    assert len(ev_records) >= 1

def test_phase5_blocked_unapproved_procedure(client, auth_headers, db_session):
    """Verify backend safety check blocks unapproved or arbitrary procedure codes with HTTP 400."""
    asset = Asset(
        name="Phase5-Blocked-Asset",
        ip_address="10.0.5.30",
        hostname="blocked-target",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="staging",
        criticality="low"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Blocked-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Blocked Assessment",
        status="completed"
    )
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
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=70.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="Polkit"
    )
    db_session.add(finding)
    db_session.commit()

    # Attempt execution with unapproved procedure code -> MUST BE REJECTED (HTTP 400)
    res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-UNAPPROVED-CUSTOM-99"
    })
    assert res.status_code == 400
    assert "unapproved" in res.json()["detail"].lower()

def test_phase5_blocked_destructive_command_safety(client, auth_headers, db_session):
    """Verify backend safety check blocks destructive command patterns with HTTP 400."""
    asset = Asset(
        name="Phase5-Destructive-Asset",
        ip_address="10.0.5.40",
        hostname="destruct-target",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="staging",
        criticality="low"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Destruct-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Destructive Test",
        status="completed"
    )
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
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=70.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="Polkit"
    )
    db_session.add(finding)
    db_session.commit()

    # Attempt injection of destructive command in procedure_code
    res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "; rm -rf / ;"
    })
    assert res.status_code == 400
    assert "destructive" in res.json()["detail"].lower() or "forbidden" in res.json()["detail"].lower()

def test_phase5_inconclusive_missing_installed_version(client, auth_headers, db_session):
    """Verify validation handles missing installed version gracefully as inconclusive."""
    asset = Asset(
        name="Phase5-Inconclusive-Asset",
        ip_address="10.0.5.50",
        hostname="inconclusive-target",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="production",
        criticality="high"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Inconclusive-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Inconclusive Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    # Missing/unknown version
    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec",
        affected_component="policykit-1",
        installed_version="unknown", # UNKNOWN VERSION
        fixed_version="0.105-31",
        cvss_v3_score=7.8,
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=70.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8},
        recommended_priority="P1",
        risk_explanation="Polkit unknown"
    )
    db_session.add(finding)
    db_session.commit()

    exec_res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert exec_res.status_code == 201
    run_data = exec_res.json()
    assert run_data["status"] == "completed"
    assert run_data["outcome"] == "inconclusive"
    assert run_data["preconditions_met"] is False
    assert "Precondition Check: FAILED" in run_data["test_output"]
    assert "INCONCLUSIVE" in run_data["test_output"]

    # Verify finding status is inconclusive
    db_session.refresh(finding)
    assert finding.detection_status == "inconclusive"

    # Verify evidence was persisted
    ev_records = db_session.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()
    assert len(ev_records) >= 1
    assert ev_records[0].metadata_info["outcome"] == "inconclusive"
    assert ev_records[0].metadata_info["preconditions_met"] is False

def test_phase5_inconclusive_component_mismatch(client, auth_headers, db_session):
    """Verify validation handles component/CVE mismatch as inconclusive precondition failure."""
    asset = Asset(
        name="Phase5-Mismatch-Asset",
        ip_address="10.0.5.60",
        hostname="mismatch-target",
        os_type="linux",
        os_version="Ubuntu 22.04",
        environment="staging",
        criticality="medium"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Twin-Mismatch-Lab",
        provider="mock_isolated",
        template_name="ubuntu-22.04-cve-lab",
        status="ready",
        ip_address="192.168.100.105",
        network_isolated=True,
        snapshot_status="baseline",
        config_parity_score=100.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 5 Mismatch Assessment",
        status="completed"
    )
    db_session.add(assessment)
    db_session.commit()

    # Finding is for curl, but we will test with pkexec procedure
    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2023-38606",
        title="curl Hostname SOCKS5 Buffer Overflow",
        affected_component="curl",
        installed_version="7.81.0",
        fixed_version="8.3.0",
        cvss_v3_score=8.1,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=75.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 8.1},
        recommended_priority="P1",
        risk_explanation="curl buffer overflow"
    )
    db_session.add(finding)
    db_session.commit()

    # Run pkexec procedure against curl finding -> Mismatch
    exec_res = client.post("/api/v1/validation/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-PKEXEC-01"
    })
    assert exec_res.status_code == 201
    run_data = exec_res.json()
    assert run_data["status"] == "completed"
    assert run_data["outcome"] == "inconclusive"
    assert run_data["preconditions_met"] is False
    assert "mismatch" in run_data["test_output"].lower()

    # Verify evidence was persisted
    ev_records = db_session.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()
    assert len(ev_records) >= 1
