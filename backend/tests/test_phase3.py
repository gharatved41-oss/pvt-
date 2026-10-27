import pytest
from app.services.ml_risk_engine import MLRiskEngine, ml_risk_engine

def test_phase3_explainable_baseline_risk_calculation():
    """Verify deterministic mathematical baseline calculation and point derivation."""
    # Test high severity on critical production asset with functional exploit
    score, derivation = ml_risk_engine.compute_explainable_baseline_risk(
        cvss_score=9.8,
        crit_val=4,       # critical
        exploit_val=2,    # functional
        env_val=3,        # production
        unpatched=False,
        ev_val=2          # manifest
    )
    # Severity: (9.8 * 10) * 0.35 = 34.3 pts
    # Exploit: (2 / 3 * 100) * 0.30 = 20.0 pts
    # Criticality: (4 / 4 * 100) * 0.20 = 20.0 pts
    # Environment: (3 / 3 * 100) * 0.15 = 15.0 pts
    # Modifiers: 0.0 pts
    # Total: 34.3 + 20.0 + 20.0 + 15.0 = 89.3
    assert derivation["severity_component_points"] == 34.3
    assert derivation["exploitability_component_points"] == 20.0
    assert derivation["asset_criticality_points"] == 20.0
    assert derivation["environment_exposure_points"] == 15.0
    assert 88.0 <= score <= 90.0

    # Test unpatched modifier adds +8 pts
    score_unpatched, deriv_unpatched = ml_risk_engine.compute_explainable_baseline_risk(
        cvss_score=9.8,
        crit_val=4,
        exploit_val=2,
        env_val=3,
        unpatched=True,
        ev_val=2
    )
    assert deriv_unpatched["modifiers_points"] == 8.0
    assert round(score_unpatched - score, 1) == 8.0

    # Test confirmed in twin modifier adds +4 pts
    score_confirmed, deriv_confirmed = ml_risk_engine.compute_explainable_baseline_risk(
        cvss_score=9.8,
        crit_val=4,
        exploit_val=2,
        env_val=3,
        unpatched=False,
        ev_val=3
    )
    assert deriv_confirmed["modifiers_points"] == 4.0
    assert round(score_confirmed - score, 1) == 4.0

def test_phase3_separation_of_severity_exploitability_and_context():
    """Verify that intrinsic severity is decoupled from contextual host risk and exploit maturity."""
    # Scenario A: High CVSS (9.0) on low criticality dev host with no public exploit
    eval_a = ml_risk_engine.evaluate_risk(
        cvss_score=9.0,
        asset_criticality="low",
        asset_environment="development",
        exploit_maturity="unproven",
        patch_available=True,
        evidence_depth="heuristic",
        detection_status="detected"
    )

    # Scenario B: Moderate CVSS (7.5) on critical production host with weaponized exploit
    eval_b = ml_risk_engine.evaluate_risk(
        cvss_score=7.5,
        asset_criticality="critical",
        asset_environment="production",
        exploit_maturity="weaponized",
        patch_available=True,
        evidence_depth="manifest",
        detection_status="detected"
    )

    # In Scenario A, severity is higher (Critical vs High), but realized risk is much lower
    assert eval_a["severity"] == "Critical"
    assert eval_b["severity"] == "High"
    assert eval_a["severity_metrics"]["cvss_base_score"] > eval_b["severity_metrics"]["cvss_base_score"]

    # Realized risk reflects exploit maturity and asset context:
    assert eval_b["risk_score"] > eval_a["risk_score"]
    assert eval_b["contextual_metrics"]["asset_criticality"] == "Critical"
    assert eval_a["contextual_metrics"]["asset_criticality"] == "Low"
    assert eval_b["exploitability_metrics"]["weaponized"] is True
    assert eval_a["exploitability_metrics"]["weaponized"] is False

def test_phase3_scikit_learn_evaluation_gate():
    """Verify scikit-learn model evaluation benchmarks and fallback behavior on insufficient data."""
    # 1. Main model evaluation benchmarks
    eval_metrics = ml_risk_engine.model_evaluation
    assert eval_metrics["is_ml_active"] is True
    assert eval_metrics["evaluation_status"] == "evaluated_passed"
    assert eval_metrics["r2_score"] >= 0.80
    assert eval_metrics["cv_r2_mean"] >= 0.75
    assert eval_metrics["mean_absolute_error"] <= 6.0
    assert eval_metrics["sample_count"] >= 15
    assert len(eval_metrics["feature_importance"]) == 6

    # 2. Test fallback behavior when suitable labeled data is absent (< 10 samples)
    sparse_data = [
        [10.0, 4, 3, 3, 0, 3, 98.0],
        [5.0,  2, 1, 1, 0, 1, 35.0]
    ]
    sparse_engine = MLRiskEngine(training_data=sparse_data)
    assert sparse_engine.is_ml_active is False
    assert sparse_engine.model_evaluation["evaluation_status"] == "insufficient_labeled_data"

    # Evaluates safely using baseline engine
    res = sparse_engine.evaluate_risk(
        cvss_score=8.0,
        asset_criticality="high",
        asset_environment="production"
    )
    assert res["risk_score"] > 0.0
    assert res["scoring_engine"] == "Deterministic Explainable Baseline Engine"

def test_phase3_contributing_factors_and_uncertainty():
    """Verify factor decomposition, point weights, and quantitative uncertainty metrics."""
    # Manifest-based detection
    res_manifest = ml_risk_engine.evaluate_risk(
        cvss_score=8.5,
        asset_criticality="high",
        asset_environment="staging",
        exploit_maturity="functional",
        evidence_depth="manifest",
        detection_status="detected"
    )
    # Twin-confirmed detection
    res_confirmed = ml_risk_engine.evaluate_risk(
        cvss_score=8.5,
        asset_criticality="high",
        asset_environment="staging",
        exploit_maturity="functional",
        evidence_depth="manifest",
        detection_status="confirmed"
    )

    # Contributing factors
    factors = res_manifest["contributing_factors"]
    assert "cvss_base_impact" in factors
    assert "exploit_intelligence" in factors
    assert "asset_criticality" in factors
    assert "exposure_environment" in factors
    assert "evidence_verification" in factors

    # Uncertainty checks
    unc_manifest = res_manifest["uncertainty"]
    unc_confirmed = res_confirmed["uncertainty"]

    # Twin confirmation must significantly reduce uncertainty
    assert unc_confirmed["uncertainty_score"] < unc_manifest["uncertainty_score"]
    assert unc_confirmed["confidence_score"] > unc_manifest["confidence_score"]
    assert unc_confirmed["margin_of_error"] < unc_manifest["margin_of_error"]

    # Confidence interval format [min, max]
    ci = unc_confirmed["confidence_interval"]
    assert len(ci) == 2
    assert ci[0] <= res_confirmed["risk_score"] <= ci[1]
    assert len(unc_confirmed["sources_of_uncertainty"]) >= 1

def test_phase3_api_endpoints(client, auth_headers):
    """Test /api/v1/risk/evaluate and /api/v1/risk/model-status endpoints."""
    # 1. Test model-status endpoint
    status_res = client.get("/api/v1/risk/model-status", headers=auth_headers)
    assert status_res.status_code == 200
    st = status_res.json()
    assert st["is_ml_active"] is True
    assert "r2_score" in st
    assert "mean_absolute_error" in st

    # 2. Test ad-hoc evaluate endpoint
    eval_res = client.post("/api/v1/risk/evaluate", headers=auth_headers, json={
        "cvss_score": 7.8,
        "asset_criticality": "critical",
        "asset_environment": "production",
        "exploit_maturity": "high",
        "patch_available": True,
        "evidence_depth": "confirmed",
        "detection_status": "confirmed"
    })
    assert eval_res.status_code == 200
    r = eval_res.json()
    assert 80.0 <= r["risk_score"] <= 100.0
    assert r["severity"] == "High"
    assert "severity_metrics" in r
    assert "exploitability_metrics" in r
    assert "contextual_metrics" in r
    assert "uncertainty" in r
    assert "contributing_factors" in r
    assert "baseline_risk_score" in r
