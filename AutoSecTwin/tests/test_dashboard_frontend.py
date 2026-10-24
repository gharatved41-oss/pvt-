"""Automated unit and integration tests for Milestone 6: Analysis Results and Evidence Dashboard."""

from fastapi.testclient import TestClient


def test_dashboard_html_page_served_successfully(client: TestClient) -> None:
    """Verify that GET /dashboard serves the responsive HTML5 dashboard with all required components."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

    html = response.text
    # Verify title and brand
    assert "VulnTwin AI" in html
    assert "Evidence &amp; Threat Intelligence Lab" in html or "Evidence & Threat Intelligence" in html

    # Verify Privacy & Third-Party Disclosure Banner
    assert "Privacy &amp; Third-Party Intelligence Disclosure" in html or "Privacy & Third-Party" in html
    assert "VirusTotal" in html
    assert "privacy guardrails" in html.lower()

    # Verify Submission Form Elements
    assert 'id="submission-form"' in html
    assert 'id="target-url-input"' in html
    assert 'id="submit-btn"' in html

    # Verify Metrics Grid Elements
    assert 'id="metric-total"' in html
    assert 'id="metric-completed"' in html
    assert 'id="metric-pending"' in html
    assert 'id="metric-failed"' in html

    # Verify Core Invariants Elements (Score, Confidence, Exploitability)
    assert 'id="detail-risk-score"' in html
    assert 'id="detail-confidence-badge"' in html
    assert "UNKNOWN" in html
    assert "Digital Twin" in html

    # Verify Evidence & Remediation Sections
    assert 'id="evidence-table"' in html
    assert 'id="remediation-cards-grid"' in html

    # Verify Analysis History Table
    assert 'id="analyses-table"' in html
    assert 'id="search-input"' in html
    assert 'id="status-filter"' in html


def test_dashboard_css_served_successfully(client: TestClient) -> None:
    """Verify that GET /dashboard/style.css returns the dark-mode cyber stylesheet."""
    response = client.get("/dashboard/style.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")
    css = response.text
    assert "--bg-base" in css
    assert "--primary" in css
    assert "status-badge" in css


def test_dashboard_javascript_served_successfully(client: TestClient) -> None:
    """Verify that GET /dashboard/app.js returns the dashboard SPA logic."""
    response = client.get("/dashboard/app.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers.get("content-type", "")
    js = response.text
    assert "handleTargetSubmission" in js
    assert "renderActiveDetail" in js
    assert "renderThreatOutcomeBanner" in js


def test_service_root_includes_dashboard_url(client: TestClient) -> None:
    """Verify GET / returns navigation link to the dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "dashboard_url" in data
    assert data["dashboard_url"] == "/dashboard"


def test_get_analysis_by_id_returns_detail_when_completed(client: TestClient) -> None:
    """Verify GET /api/v1/analyses/{id} provides full evidence and risk assessment when completed."""
    # 1. Create a target
    create_res = client.post("/api/v1/analyses", json={"url": "https://dashboard-test-target.io/auth/login"})
    assert create_res.status_code == 201
    analysis_id = create_res.json()["id"]

    # 2. Before analyze: status is pending, evidence is empty
    pending_res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert pending_res.status_code == 200
    pending_data = pending_res.json()
    assert pending_data["status"] == "pending"
    assert pending_data["evidence_items"] == []
    assert pending_data["risk_assessment"] is None

    # 3. Trigger analyze
    client.post(f"/api/v1/analyses/{analysis_id}/analyze")

    # 4. After analyze: status is completed, evidence and risk assessment are populated
    completed_res = client.get(f"/api/v1/analyses/{analysis_id}")
    assert completed_res.status_code == 200
    completed_data = completed_res.json()
    assert completed_data["status"] == "completed"
    assert len(completed_data["evidence_items"]) > 0
    assert completed_data["risk_assessment"] is not None
    assert "risk_score" in completed_data["risk_assessment"]
    assert "confidence_level" in completed_data["risk_assessment"]
    assert completed_data["risk_assessment"]["exploitability"] == "unknown"


def test_no_api_keys_leaked_in_frontend_assets(client: TestClient) -> None:
    """Verify that frontend assets do not contain any hardcoded API keys or secrets."""
    html_res = client.get("/dashboard")
    js_res = client.get("/dashboard/app.js")
    css_res = client.get("/dashboard/style.css")

    for content in (html_res.text, js_res.text, css_res.text):
        assert "VT_API_KEY" not in content
        assert "x-apikey" not in content
        assert "api_key" not in content.lower() or "api keys exclusively" in content.lower()


def test_dashboard_navigation_and_tab_views_served(client: TestClient) -> None:
    """Verify dashboard HTML includes the primary navigation bar and distinct view containers."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text

    # Verify primary navigation tabs
    assert 'id="tab-nav-dashboard"' in html
    assert 'id="tab-nav-os-assets"' in html
    assert 'id="tab-nav-os-assessments"' in html
    assert 'id="tab-nav-findings"' in html
    assert 'id="tab-nav-url-analysis"' in html
    assert 'id="tab-nav-settings"' in html

    # Verify view containers
    assert 'id="view-dashboard"' in html
    assert 'id="view-os-assets"' in html
    assert 'id="view-os-assessments"' in html
    assert 'id="view-findings"' in html
    assert 'id="view-url-analysis"' in html
    assert 'id="view-settings"' in html

    # Verify auth session pill
    assert 'id="auth-session-pill"' in html
    assert 'id="auth-current-username"' in html
    assert 'id="auth-current-role"' in html


def test_dashboard_overview_metrics_and_visuals_markup(client: TestClient) -> None:
    """Verify dashboard overview markup includes asset, assessment, finding metrics and distribution bars."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text

    assert 'id="dash-metric-assets"' in html
    assert 'id="dash-metric-assessments"' in html
    assert 'id="dash-metric-findings"' in html
    assert 'id="dash-metric-risk-level"' in html
    assert 'id="dash-severity-bar"' in html
    assert 'id="dash-recent-assessments-table"' in html


def test_os_asset_management_form_markup(client: TestClient) -> None:
    """Verify OS asset registration form has all required inputs and error/success containers."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text

    assert 'id="register-asset-form"' in html
    assert 'id="asset-hostname-input"' in html
    assert 'id="asset-family-select"' in html
    assert 'id="asset-name-input"' in html
    assert 'id="asset-version-input"' in html
    assert 'id="asset-arch-select"' in html
    assert 'id="btn-submit-asset"' in html
    assert 'id="os-assets-table"' in html


def test_os_assessment_workflow_and_safety_disclaimers(client: TestClient) -> None:
    """Verify assessment workflow includes read-only safety guarantees and unapplied proposal labels."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.text

    assert 'id="create-assessment-form"' in html
    assert 'id="select-assessment-asset"' in html
    assert 'id="os-assessment-detail-section"' in html
    assert 'id="os-evidence-table"' in html
    assert 'id="os-findings-table"' in html
    assert 'id="os-remediation-cards-grid"' in html

    # Strict invariant & safety disclaimers
    assert "Read-Only Safety Guarantee" in html
    assert "ALL RECOMMENDATIONS ARE PROPOSED ACTIONS ONLY" in html
    assert "tag-unapplied-proposal" in html


def test_dashboard_javascript_functions_and_api_integration(client: TestClient) -> None:
    """Verify app.js includes core functions for auth, tabs, OS assets, assessments, and findings."""
    response = client.get("/dashboard/app.js")
    assert response.status_code == 200
    js = response.text

    # Preserved URL analysis functions
    assert "handleTargetSubmission" in js
    assert "renderActiveDetail" in js
    assert "renderThreatOutcomeBanner" in js

    # New dashboard and OS assessment functions
    assert "switchTab" in js
    assert "getAuthHeaders" in js
    assert "loadDashboardOverview" in js
    assert "loadOSAssets" in js
    assert "handleRegisterAsset" in js
    assert "loadOSAssessments" in js
    assert "handleCreateAndStartAssessment" in js
    assert "loadAssessmentDetail" in js
    assert "renderOSFindings" in js
    assert "renderOSEvidence" in js
    assert "renderOSRemediation" in js
    assert "loadAggregatedFindings" in js


def test_dashboard_css_contains_new_components(client: TestClient) -> None:
    """Verify style.css contains styles for new navigation, auth pill, visuals, and proposal tags."""
    response = client.get("/dashboard/style.css")
    assert response.status_code == 200
    css = response.text

    assert ".main-nav-bar" in css
    assert ".nav-tab" in css
    assert ".auth-pill" in css
    assert ".tag-unapplied-proposal" in css
    assert ".breakdown-bar" in css
    assert ".status-running" in css
    assert ".safety-callout" in css


def test_os_asset_and_assessment_api_integration_flow(client: TestClient) -> None:
    """Verify backend API integration supporting the frontend asset and assessment lifecycle."""
    headers_a = {"Authorization": "Bearer token_user_a"}

    # 1. Register OS asset via API
    asset_payload = {
        "host_identifier": "a" * 64,
        "hostname": "localhost",
        "os_family": "linux",
        "os_name": "Debian GNU/Linux",
        "os_version": "12",
        "architecture": "x86_64",
    }
    create_asset_res = client.post("/api/v1/os/assets", json=asset_payload, headers=headers_a)
    assert create_asset_res.status_code == 201
    asset_id = create_asset_res.json()["id"]

    # 2. List assets for User A
    list_res = client.get("/api/v1/os/assets", headers=headers_a)
    assert list_res.status_code == 200
    assert any(item["id"] == asset_id for item in list_res.json()["items"])

    # 3. Create OS Assessment
    assess_create_res = client.post(
        "/api/v1/os/assessments",
        json={"asset_id": asset_id, "assessment_type": "local_read_only"},
        headers=headers_a,
    )
    assert assess_create_res.status_code == 201
    assessment_id = assess_create_res.json()["id"]
    assert assess_create_res.json()["status"] == "pending"

    # 4. Run local read-only assessment
    run_res = client.post(f"/api/v1/os/assessments/{assessment_id}/assess", headers=headers_a)
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["status"] == "completed"
    assert run_data["exploitability_state"] == "unknown"

    # 5. Verify evidence endpoint
    evid_res = client.get(f"/api/v1/os/assessments/{assessment_id}/evidence", headers=headers_a)
    assert evid_res.status_code == 200
    assert "items" in evid_res.json()

    # 6. Verify findings endpoint
    find_res = client.get(f"/api/v1/os/assessments/{assessment_id}/findings", headers=headers_a)
    assert find_res.status_code == 200
    assert "items" in find_res.json()

    # 7. Verify risk score endpoint
    risk_res = client.get(f"/api/v1/os/assessments/{assessment_id}/risk", headers=headers_a)
    assert risk_res.status_code == 200
    assert "risk_score" in risk_res.json()

    # 8. Verify remediation guidance endpoint
    rem_res = client.get(f"/api/v1/os/assessments/{assessment_id}/remediation", headers=headers_a)
    assert rem_res.status_code == 200
    assert "recommendations" in rem_res.json()


def test_auth_boundaries_and_ownership_in_api(client: TestClient) -> None:
    """Verify unauthorized role (guest) gets 403 Forbidden and User B cannot access User A's asset."""
    headers_a = {"Authorization": "Bearer token_user_a"}
    headers_b = {"Authorization": "Bearer token_user_b"}
    headers_guest = {"Authorization": "Bearer token_guest"}

    # Register asset as User A
    asset_res = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "b" * 64,
            "hostname": "tenant-iso-node",
            "os_family": "linux",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "architecture": "x86_64",
        },
        headers=headers_a,
    )
    assert asset_res.status_code == 201
    asset_id = asset_res.json()["id"]

    # Guest user is rejected with 403 Forbidden on asset registration
    guest_res = client.post(
        "/api/v1/os/assets",
        json={
            "host_identifier": "c" * 64,
            "hostname": "guest-node",
            "os_family": "linux",
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "architecture": "x86_64",
        },
        headers=headers_guest,
    )
    assert guest_res.status_code == 403

    # User B cannot access User A's asset
    b_res = client.get(f"/api/v1/os/assets/{asset_id}", headers=headers_b)
    assert b_res.status_code == 403

