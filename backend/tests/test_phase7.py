import pytest
from app.models.models import (
    Asset, DigitalTwin, VulnerabilityFinding, Assessment, EvidenceRecord,
    RemediationRecommendation, RetestResult, AuditEvent
)

def test_phase7_successful_retest_and_evidence_persistence(client, auth_headers, db_session):
    """
    Verify complete successful retest workflow:
    1. Twin configuration reflects patched component after lab remediation.
    2. Retest re-runs scanner detection rules and non-destructive validation probes.
    3. Both confirm mitigation -> outcome is 'resolved', finding marked 'fixed', risk score drops to 0.0.
    4. Recommendation marked 'resolved'.
    5. Forensic Retest EvidenceRecord is persisted with before/after comparative data.
    """
    # 1. Setup target asset & digital twin replica
    asset = Asset(
        name="Phase7-Web-Target",
        ip_address="10.0.7.10",
        hostname="p7-target",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        environment="production",
        criticality="critical"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Phase7-Isolated-Twin",
        template_name="ubuntu-22.04-lts-lab",
        ip_address="192.168.100.107",
        network_isolated=True,
        snapshot_status="clean_baseline",
        target_config={"os": "Ubuntu 22.04 LTS", "packages": {"policykit-1": "0.105-26"}},
        # Twin config reflects patched version (0.105-31.1 > max_version 0.105-31) applied during lab remediation
        current_config={
            "os": "Ubuntu 22.04 LTS",
            "packages": {"policykit-1": "0.105-31.1"},
            "pkg_policykit-1_version": "0.105-31.1",
            "last_remediation_applied": {
                "component": "policykit-1",
                "version": "0.105-31.1",
                "type": "package_update"
            }
        },
        config_parity_score=99.0
    )
    db_session.add(twin)
    db_session.commit()

    # 2. Setup assessment & finding
    assessment = Assessment(
        asset_id=asset.id,
        title="Phase 7 Post-Remediation Assessment",
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
        fixed_version="0.105-31.1",
        cvss_v3_score=7.8,
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="high",
        detection_status="detected",
        risk_score=75.0,
        risk_category="high",
        confidence_score=0.85,
        contributing_factors={"cvss": 7.8, "environment": "production"},
        recommended_priority="P1",
        risk_explanation="High severity polkit privilege escalation"
    )
    db_session.add(finding)
    db_session.commit()

    rec = RemediationRecommendation(
        finding_id=finding.id,
        title="Upgrade policykit-1 to safe package",
        action_type="package_update",
        description="Upgrade policykit-1 to 0.105-31.1 to resolve CVE-2021-4034",
        command_preview="apt-get install --only-upgrade policykit-1=0.105-31.1",
        status="applied_in_twin"
    )
    db_session.add(rec)
    db_session.commit()

    # 3. Trigger Retest Verification via API
    res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id
    })
    assert res.status_code == 201
    retest_data = res.json()

    # 4. Verify Retest outcome fields
    assert retest_data["post_fix_status"] == "resolved"
    assert retest_data["package_version_before"] == "0.105-26"
    assert retest_data["package_version_after"] == "0.105-31.1"
    assert retest_data["remaining_risk_score"] == 0.0
    assert "SUCCESSFUL REMEDIATION VERIFIED" in retest_data["conclusion"]
    assert "NO VULNERABILITY DETECTED" in retest_data["retest_detection_output"]
    assert "SECURE (VULNERABILITY MITIGATED)" in retest_data["retest_validation_output"]

    # 5. Verify database state changes
    db_session.refresh(finding)
    db_session.refresh(rec)
    assert finding.detection_status == "fixed"
    assert finding.risk_score == 0.0
    assert finding.risk_category == "Remediated"
    assert rec.status == "resolved"

    # 6. Verify Forensic Retest EvidenceRecord was persisted
    ev_records = db_session.query(EvidenceRecord).filter(
        EvidenceRecord.finding_id == finding.id,
        EvidenceRecord.evidence_type == "retest_evidence"
    ).all()
    assert len(ev_records) == 1
    retest_ev = ev_records[0]
    assert "RESOLVED" in retest_ev.title
    assert "BEFORE REMEDIATION" in retest_ev.raw_evidence
    assert "AFTER REMEDIATION" in retest_ev.raw_evidence
    assert retest_ev.metadata_info["post_fix_status"] == "resolved"
    assert retest_ev.metadata_info["version_before"] == "0.105-26"
    assert retest_ev.metadata_info["version_after"] == "0.105-31.1"
    assert retest_ev.metadata_info["remaining_risk"] == 0.0

    # 7. Verify Audit Event logged
    audit_event = db_session.query(AuditEvent).filter(
        AuditEvent.action == "retest_executed"
    ).order_by(AuditEvent.created_at.desc()).first()
    assert audit_event is not None
    assert audit_event.details["finding_id"] == finding.id
    assert audit_event.details["post_fix_status"] == "resolved"


def test_phase7_failed_retest_unresolved_status(client, auth_headers, db_session):
    """
    Verify retest outcome when vulnerability remains present in twin:
    1. Twin configuration still contains vulnerable package version (or fix failed).
    2. Retest confirms vulnerability is still reproducible.
    3. Outcome is 'remains_present', finding marked 'unresolved', recommendation marked 'failed'.
    4. Residual risk score remains active.
    5. Retest evidence record created documenting failure.
    """
    asset = Asset(
        name="Phase7-Unresolved-Asset",
        ip_address="10.0.7.20",
        hostname="p7-unres",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS"
    )
    db_session.add(asset)
    db_session.commit()

    # Twin configuration still contains vulnerable version (0.105-26)
    twin = DigitalTwin(
        asset_id=asset.id,
        name="Phase7-Vulnerable-Twin",
        template_name="ubuntu-22.04-lts-lab",
        ip_address="192.168.100.120",
        network_isolated=True,
        target_config={"packages": {"policykit-1": "0.105-26"}},
        current_config={"packages": {"policykit-1": "0.105-26"}},
        config_parity_score=95.0
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Phase 7 Failed Retest Assessment", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Vulnerability",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31.1",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="detected",
        risk_score=72.0
    )
    db_session.add(finding)
    db_session.commit()

    rec = RemediationRecommendation(
        finding_id=finding.id,
        title="Apply polkit patch",
        action_type="package_update",
        description="Upgrade polkit package",
        command_preview="apt-get install policykit-1=0.105-31.1",
        status="applied_in_twin"
    )
    db_session.add(rec)
    db_session.commit()

    # Execute retest
    res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id
    })
    assert res.status_code == 201
    data = res.json()

    assert data["post_fix_status"] == "remains_present"
    assert data["package_version_before"] == "0.105-26"
    assert data["package_version_after"] == "0.105-26"
    assert data["remaining_risk_score"] == 72.0
    assert "REMEDIATION FAILED" in data["conclusion"]
    assert "VULNERABLE PATTERN MATCHED" in data["retest_detection_output"]
    assert "TRIGGERED (VULNERABILITY PERSISTS)" in data["retest_validation_output"]

    # Verify finding and recommendation statuses updated
    db_session.refresh(finding)
    db_session.refresh(rec)
    assert finding.detection_status == "unresolved"
    assert rec.status == "failed"

    # Verify failure evidence record
    ev = db_session.query(EvidenceRecord).filter(
        EvidenceRecord.finding_id == finding.id,
        EvidenceRecord.evidence_type == "retest_evidence"
    ).first()
    assert ev is not None
    assert "REMAINS_PRESENT" in ev.title
    assert ev.metadata_info["post_fix_status"] == "remains_present"


def test_phase7_inconclusive_retest_indeterminate_telemetry(client, auth_headers, db_session):
    """
    Verify inconclusive retest when twin version telemetry is missing or indeterminate.
    """
    asset = Asset(
        name="Phase7-Inconclusive-Asset",
        ip_address="10.0.7.30",
        hostname="p7-inconcl",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS"
    )
    db_session.add(asset)
    db_session.commit()

    # Twin configuration has indeterminate package version
    twin = DigitalTwin(
        asset_id=asset.id,
        name="Phase7-Indeterminate-Twin",
        template_name="ubuntu-22.04-lts-lab",
        ip_address="192.168.100.130",
        network_isolated=True,
        target_config={},
        current_config={"packages": {"policykit-1": "unknown"}}
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Inconclusive Assessment", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Vulnerability",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31.1",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="detected",
        risk_score=70.0
    )
    db_session.add(finding)
    db_session.commit()

    rec = RemediationRecommendation(
        finding_id=finding.id,
        title="Apply polkit patch",
        action_type="package_update",
        description="Upgrade polkit package",
        command_preview="apt-get install policykit-1=0.105-31.1",
        status="applied_in_twin"
    )
    db_session.add(rec)
    db_session.commit()

    res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id
    })
    assert res.status_code == 201
    data = res.json()

    assert data["post_fix_status"] == "inconclusive"
    assert "INCONCLUSIVE" in data["conclusion"]
    assert data["remaining_risk_score"] == 35.0  # 50% baseline risk retained

    db_session.refresh(finding)
    db_session.refresh(rec)
    assert finding.detection_status == "inconclusive"
    assert rec.status == "retest_pending"

    # Verify evidence
    ev = db_session.query(EvidenceRecord).filter(
        EvidenceRecord.finding_id == finding.id,
        EvidenceRecord.evidence_type == "retest_evidence"
    ).first()
    assert ev is not None
    assert "INCONCLUSIVE" in ev.title


def test_phase7_inconclusive_retest_scanner_validation_discrepancy(client, auth_headers, db_session):
    """
    Verify inconclusive retest when there is a discrepancy between scanner rule and validation procedure.
    """
    asset = Asset(
        name="Phase7-Discrepancy-Asset",
        ip_address="10.0.7.40",
        hostname="p7-discrepancy",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS"
    )
    db_session.add(asset)
    db_session.commit()

    # Twin package is still installed version 0.105-26 (scanner evaluates CVE-2021-4034 as vulnerable -> True)
    twin = DigitalTwin(
        asset_id=asset.id,
        name="Phase7-Discrepancy-Twin",
        template_name="ubuntu-22.04-lts-lab",
        ip_address="192.168.100.140",
        network_isolated=True,
        target_config={"packages": {"policykit-1": "0.105-26"}},
        current_config={"packages": {"policykit-1": "0.105-26"}}
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Discrepancy Assessment", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit pkexec Vulnerability",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31.1",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="detected",
        risk_score=80.0
    )
    db_session.add(finding)
    db_session.commit()

    # When passing PROC-SEC-SSH-AGENT-02 (OpenSSH procedure requiring 5.5p1 to 9.3p1):
    # Detection scanner on CVE-2021-4034: version 0.105-26 is VULNERABLE (True)
    # Validation probe PROC-SEC-SSH-AGENT-02: version 0.105-26 is NOT vulnerable (False)
    # Detection=True and Validation=False -> DISCREPANCY -> inconclusive!
    res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id,
        "procedure_code": "PROC-SEC-SSH-AGENT-02"
    })
    assert res.status_code == 201
    data = res.json()

    assert data["post_fix_status"] == "inconclusive"
    assert "Discrepancy observed between detection rule and validation procedure" in data["conclusion"]
    db_session.refresh(finding)
    assert finding.detection_status == "inconclusive"


def test_phase7_before_after_comparison_endpoint(client, auth_headers, db_session):
    """
    Verify GET /api/v1/retesting/comparison/{finding_id} returns accurate comparative evidence
    both before and after retest execution.
    """
    asset = Asset(
        name="Phase7-Comparison-Asset",
        ip_address="10.0.7.50",
        hostname="p7-comp",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS"
    )
    db_session.add(asset)
    db_session.commit()

    twin = DigitalTwin(
        asset_id=asset.id,
        name="Phase7-Comparison-Twin",
        template_name="ubuntu-22.04-lts-lab",
        ip_address="192.168.100.150",
        network_isolated=True,
        current_config={"packages": {"openssh-server": "9.4p1"}}
    )
    db_session.add(twin)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Comparison Test Assessment", status="completed")
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2023-38408",
        title="OpenSSH PKCS#11 Provider RCE",
        affected_component="openssh-server",
        installed_version="8.9p1",
        fixed_version="9.4p1",
        cvss_v3_score=9.8,
        severity="critical",
        detection_status="detected",
        risk_score=90.0
    )
    db_session.add(finding)
    db_session.commit()

    rec = RemediationRecommendation(
        finding_id=finding.id,
        title="Update OpenSSH Server",
        action_type="package_update",
        description="Upgrade openssh-server package",
        command_preview="apt-get install openssh-server=9.4p1",
        status="applied_in_twin"
    )
    db_session.add(rec)
    db_session.commit()

    # 1. Query comparison BEFORE retest
    pre_comp_res = client.get(f"/api/v1/retesting/comparison/{finding.id}", headers=auth_headers)
    assert pre_comp_res.status_code == 200
    pre_data = pre_comp_res.json()
    assert pre_data["finding_id"] == finding.id
    assert pre_data["cve_id"] == "CVE-2023-38408"
    assert pre_data["original_version"] == "8.9p1"
    assert pre_data["retest_outcome"] == "Pending retest"

    # 2. Execute retest
    retest_res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": twin.id
    })
    assert retest_res.status_code == 201

    # 3. Query comparison AFTER retest
    post_comp_res = client.get(f"/api/v1/retesting/comparison/{finding.id}", headers=auth_headers)
    assert post_comp_res.status_code == 200
    post_data = post_comp_res.json()
    assert post_data["final_status"] == "resolved"
    assert post_data["original_version"] == "8.9p1"
    assert post_data["new_version"] == "9.4p1"
    assert post_data["original_risk"] == 98.0  # cvss_v3_score * 10
    assert post_data["remaining_risk"] == 0.0
    assert "RETEST DETECTION SCAN" in post_data["retest_evidence"]
    assert "RETEST VALIDATION PROCEDURE" in post_data["retest_evidence"]
    assert "SUCCESSFUL REMEDIATION VERIFIED" in post_data["retest_evidence"]


def test_phase7_query_results_and_guardrails(client, auth_headers, db_session):
    """
    Verify filtering of retest results and validation guardrails:
    1. Unauthenticated requests are rejected with 401.
    2. Non-existent finding or twin returns 404.
    3. Filtering by finding_id and twin_id works correctly.
    """
    # 1. Unauthenticated request
    unauth_res = client.post("/api/v1/retesting/execute", json={"finding_id": "non-existent", "twin_id": "non-existent"})
    assert unauth_res.status_code == 401

    # 2. Non-existent finding
    bad_finding_res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": "00000000-0000-0000-0000-000000000000",
        "twin_id": "00000000-0000-0000-0000-000000000000"
    })
    assert bad_finding_res.status_code == 404
    assert "finding not found" in bad_finding_res.json()["detail"].lower()

    # 3. Valid finding, non-existent twin
    asset = Asset(name="P7 Guard Asset", ip_address="10.0.7.60", hostname="p7-guard", os_type="linux", os_version="Ubuntu 22.04 LTS")
    db_session.add(asset)
    db_session.commit()
    assessment = Assessment(asset_id=asset.id, title="P7 Guard Assessment")
    db_session.add(assessment)
    db_session.commit()
    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2021-4034",
        title="Polkit",
        affected_component="policykit-1",
        installed_version="0.105-26",
        severity="high"
    )
    db_session.add(finding)
    db_session.commit()

    bad_twin_res = client.post("/api/v1/retesting/execute", headers=auth_headers, json={
        "finding_id": finding.id,
        "twin_id": "00000000-0000-0000-0000-000000000000"
    })
    assert bad_twin_res.status_code == 404
    assert "twin" in bad_twin_res.json()["detail"].lower()

    # 4. Results listing
    list_res = client.get("/api/v1/retesting/results", headers=auth_headers)
    assert list_res.status_code == 200
    assert isinstance(list_res.json(), list)
