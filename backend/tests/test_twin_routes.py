import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_create_and_remediate_digital_twin():
    # 1. Create Twin
    payload = {
        "target": "aws.production.vpc.ecommerce",
        "risk_score": 85,
        "verdict": "MALICIOUS",
        "indicators": {
            "cve": "CVE-2023-38606",
            "port": 5432
        }
    }
    create_res = client.post("/api/v1/twin/create", json=payload)
    assert create_res.status_code == 200
    twin_data = create_res.json()
    assert "twin_id" in twin_data
    twin_id = twin_data["twin_id"]
    assert twin_data["initial_posture"] < 50
    assert len(twin_data["components"]) >= 3
    assert len(twin_data["findings"]) >= 1

    # 2. Get Twin by ID
    get_res = client.get(f"/api/v1/twin/{twin_id}")
    assert get_res.status_code == 200
    assert get_res.json()["twin_id"] == twin_id

    # 3. Remediate Twin
    remediate_res = client.post("/api/v1/twin/remediate", json={"twin_id": twin_id})
    assert remediate_res.status_code == 200
    rem_data = remediate_res.json()
    assert "before_after_delta" in rem_data
    delta = rem_data["before_after_delta"]
    assert delta["after_posture"] > delta["before_posture"]
    assert delta["after_risk_score"] < delta["before_risk_score"]
    assert delta["posture_improvement_points"] > 0
    assert delta["open_findings_after"] == 0


def test_get_nonexistent_twin():
    res = client.get("/api/v1/twin/NON_EXISTENT_TWIN_9999")
    assert res.status_code == 404
