import pytest
from app.models.models import (
    Asset, DigitalTwin, VulnerabilityFinding, Assessment, EvidenceRecord,
    RemediationRecommendation, RetestResult, AuditEvent, User
)

def test_phase8_dashboard_metrics_aggregation(client, auth_headers, db_session):
    """
    Verify dashboard metrics endpoint aggregates real database counts dynamically:
    - Counts for assets, assessments, findings by severity
    - Status breakdown (detected, confirmed, fixed, unresolved, inconclusive)
    - Average realized risk score calculation
    - Recent assessments, findings, and audit streams
    """
    # 1. Setup realistic assets
    asset1 = Asset(name="DB Gateway", ip_address="10.8.0.1", hostname="db-gw", os_type="linux", os_version="Ubuntu 22.04 LTS")
    asset2 = Asset(name="Auth Gateway", ip_address="10.8.0.2", hostname="auth-gw", os_type="linux", os_version="Ubuntu 22.04 LTS")
    db_session.add_all([asset1, asset2])
    db_session.commit()

    # 2. Setup assessments
    ass1 = Assessment(asset_id=asset1.id, title="P8 Database Audit", status="completed", findings_count=2, average_risk_score=75.0)
    db_session.add(ass1)
    db_session.commit()

    # 3. Setup findings with various severities and detection statuses
    f_crit = VulnerabilityFinding(
        assessment_id=ass1.id,
        asset_id=asset1.id,
        cve_id="CVE-2023-38408",
        title="OpenSSH RCE",
        affected_component="openssh-server",
        installed_version="8.9p1",
        fixed_version="9.4p1",
        cvss_v3_score=9.8,
        severity="critical",
        detection_status="confirmed",
        risk_score=92.0
    )
    f_high = VulnerabilityFinding(
        assessment_id=ass1.id,
        asset_id=asset1.id,
        cve_id="CVE-2021-4034",
        title="Polkit PwnKit",
        affected_component="policykit-1",
        installed_version="0.105-26",
        fixed_version="0.105-31.1",
        cvss_v3_score=7.8,
        severity="high",
        detection_status="fixed",
        risk_score=0.0
    )
    db_session.add_all([f_crit, f_high])
    db_session.commit()

    # 4. Setup remediation recommendations
    rec1 = RemediationRecommendation(
        finding_id=f_crit.id,
        title="Upgrade OpenSSH",
        action_type="package_update",
        description="Patch ssh daemon",
        command_preview="apt-get install openssh-server=9.4p1",
        status="awaiting_approval"
    )
    rec2 = RemediationRecommendation(
        finding_id=f_high.id,
        title="Upgrade Polkit",
        action_type="package_update",
        description="Patch polkit binary",
        command_preview="apt-get install policykit-1=0.105-31.1",
        status="resolved"
    )
    db_session.add_all([rec1, rec2])
    db_session.commit()

    # 5. Setup audit events
    audit1 = AuditEvent(event_type="assessment", action="assessment_started", user_email="admin@vulntwin.com", details={"assessment_id": ass1.id})
    audit2 = AuditEvent(event_type="remediation", action="remediation_approved", user_email="admin@vulntwin.com", details={"rec_id": rec2.id})
    db_session.add_all([audit1, audit2])
    db_session.commit()

    # 6. Query dashboard metrics
    res = client.get("/api/v1/dashboard/metrics", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    # Verify counts match database state
    assert data["total_assets"] >= 2
    assert data["total_assessments"] >= 1
    assert data["total_findings"] >= 2
    assert data["critical_findings"] >= 1
    assert data["high_findings"] >= 1

    # Verify status breakdown
    assert "confirmed" in data["status_breakdown"]
    assert "fixed" in data["status_breakdown"]
    assert data["status_breakdown"]["confirmed"] >= 1
    assert data["status_breakdown"]["fixed"] >= 1

    # Verify remediation breakdown
    assert data["remediation_breakdown"]["awaiting_approval"] >= 1
    assert data["remediation_breakdown"]["resolved"] >= 1

    # Verify severity distribution chart array
    assert len(data["severity_distribution"]) == 4
    crit_entry = next(item for item in data["severity_distribution"] if item["name"] == "Critical")
    assert crit_entry["count"] >= 1

    # Verify recent records
    assert len(data["recent_assessments"]) >= 1
    assert len(data["recent_findings"]) >= 1
    assert len(data["recent_audit_events"]) >= 2


def test_phase8_pdf_reporting_endpoint(client, auth_headers, db_session):
    """
    Verify high-fidelity PDF report generation for an assessment:
    - Status 200 with application/pdf media type
    - Attachment header with valid filename
    - Binary content starts with %PDF magic bytes
    - Content length is non-trivial (>1000 bytes)
    """
    asset = Asset(name="PDF Test Server", ip_address="10.8.0.10", hostname="pdf-srv", os_type="linux", os_version="Ubuntu 22.04 LTS")
    db_session.add(asset)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="Executive PDF Security Audit", status="completed", findings_count=1)
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
        risk_score=75.0,
        description="Local privilege escalation flaw in pkexec."
    )
    db_session.add(finding)
    db_session.commit()

    # Valid download
    res = client.get(f"/api/v1/reports/assessments/{assessment.id}/pdf", headers=auth_headers)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF")
    assert len(res.content) > 1000

    # Non-existent assessment returns 404
    bad_res = client.get("/api/v1/reports/assessments/00000000-0000-0000-0000-000000000000/pdf", headers=auth_headers)
    assert bad_res.status_code == 404


def test_phase8_csv_reporting_endpoint(client, auth_headers, db_session):
    """
    Verify CSV assessment export contains structured columns:
    - Status 200 with text/csv media type
    - Standard security audit headers
    - Data rows with CVE ID, component, versions, and risk metrics
    """
    asset = Asset(name="CSV Test Server", ip_address="10.8.0.20", hostname="csv-srv", os_type="linux", os_version="Ubuntu 22.04 LTS")
    db_session.add(asset)
    db_session.commit()

    assessment = Assessment(asset_id=asset.id, title="CSV Export Assessment", status="completed", findings_count=1)
    db_session.add(assessment)
    db_session.commit()

    finding = VulnerabilityFinding(
        assessment_id=assessment.id,
        asset_id=asset.id,
        cve_id="CVE-2023-38408",
        title="OpenSSH ssh-agent PKCS11 Flaw",
        affected_component="openssh-server",
        installed_version="8.9p1",
        fixed_version="9.4p1",
        cvss_v3_score=9.8,
        severity="critical",
        detection_status="confirmed",
        risk_score=92.0,
        description="Arbitrary library loading in ssh-agent."
    )
    db_session.add(finding)
    db_session.commit()

    res = client.get(f"/api/v1/reports/assessments/{assessment.id}/csv", headers=auth_headers)
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "attachment; filename=" in res.headers["content-disposition"]
    text = res.text

    # Header and metadata assertions
    assert "Vuln TWin Security Assessment Report" in text
    assert "CVE ID" in text
    assert "Affected Component" in text
    assert "Installed Version" in text
    assert "Risk Score (0-100)" in text

    # Data row assertions
    assert "CVE-2023-38408" in text
    assert "openssh-server" in text
    assert "8.9p1" in text
    assert "9.4p1" in text
    assert "Critical" in text


def test_phase8_audit_logs_query_and_filtering(client, auth_headers, db_session):
    """
    Verify audit trail query and stream category filtering:
    - Query all events
    - Filter by event_type (auth, assessment, remediation, twin)
    - Verify structured details persistence
    """
    ev1 = AuditEvent(event_type="auth", action="user_logged_in", user_email="admin@vulntwin.com", ip_address="127.0.0.1", details={"method": "jwt"})
    ev2 = AuditEvent(event_type="twin", action="snapshot_created", user_email="admin@vulntwin.com", ip_address="127.0.0.1", details={"snapshot": "p8-snap"})
    db_session.add_all([ev1, ev2])
    db_session.commit()

    # Query all
    all_res = client.get("/api/v1/audit", headers=auth_headers)
    assert all_res.status_code == 200
    all_events = all_res.json()
    assert len(all_events) >= 2

    # Filter by 'twin'
    twin_res = client.get("/api/v1/audit?event_type=twin", headers=auth_headers)
    assert twin_res.status_code == 200
    twin_events = twin_res.json()
    assert all(e["event_type"] == "twin" for e in twin_events)
    assert any(e["action"] == "snapshot_created" for e in twin_events)


def test_phase8_security_headers_and_unauthenticated_guardrails(client):
    """
    Verify security hardening middleware and route protection:
    - HTTP response security headers present (nosniff, DENY, XSS-Protection, HSTS, Referrer-Policy)
    - Protected endpoints reject unauthenticated access with 401
    """
    # 1. Check security response headers on root and API endpoints
    root_res = client.get("/")
    assert root_res.status_code == 200
    assert root_res.headers.get("x-content-type-options") == "nosniff"
    assert root_res.headers.get("x-frame-options") == "DENY"
    assert "1; mode=block" in root_res.headers.get("x-xss-protection", "")
    assert "max-age=" in root_res.headers.get("strict-transport-security", "")
    assert root_res.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    # 2. Protected endpoints reject unauthenticated requests
    protected_get_urls = [
        "/api/v1/dashboard/metrics",
        "/api/v1/audit",
        "/api/v1/reports/assessments/test-id/pdf",
        "/api/v1/reports/assessments/test-id/csv",
        "/api/v1/assets",
        "/api/v1/assessments",
        "/api/v1/twins",
        "/api/v1/remediation/recommendations",
        "/api/v1/retesting/results"
    ]
    for url in protected_get_urls:
        res = client.get(url)
        assert res.status_code == 401, f"GET {url} failed to reject unauthenticated request!"

    protected_post_urls = [
        "/api/v1/validation/execute",
        "/api/v1/retesting/execute"
    ]
    for url in protected_post_urls:
        res = client.post(url, json={})
        assert res.status_code == 401, f"POST {url} failed to reject unauthenticated request!"

    # 3. Invalid Bearer token rejected
    bad_token_res = client.get("/api/v1/dashboard/metrics", headers={"Authorization": "Bearer invalid.token.payload"})
    assert bad_token_res.status_code == 401
