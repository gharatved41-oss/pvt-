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
