"""Unit and API tests for analysis lifecycle states, risk engine, and evidence integration."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.analysis import AnalysisRecord, AnalysisStatus
from app.models.evidence import SecurityEvidenceRecord
from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate
from app.schemas.risk import ConfidenceLevel, ExploitabilityStatus, RiskLevel
from app.services import analysis_service
from app.services.analysis_service import InvalidStatusTransitionError
from app.services.risk_engine import DeterministicPassiveRiskEngine


# =====================================================================
# 1. State Machine Unit Tests
# =====================================================================

def test_analysis_status_valid_transitions() -> None:
    """Verify that allowed transitions return True."""
    rec = AnalysisRecord(url="https://example.com", status=AnalysisStatus.PENDING.value)
    assert rec.can_transition_to(AnalysisStatus.RUNNING.value) is True
    assert rec.can_transition_to(AnalysisStatus.FAILED.value) is True

    rec.status = AnalysisStatus.RUNNING.value
    assert rec.can_transition_to(AnalysisStatus.COMPLETED.value) is True
    assert rec.can_transition_to(AnalysisStatus.FAILED.value) is True


def test_analysis_status_invalid_transitions() -> None:
    """Verify that disallowed transitions return False."""
    rec = AnalysisRecord(url="https://example.com", status=AnalysisStatus.PENDING.value)
    assert rec.can_transition_to(AnalysisStatus.COMPLETED.value) is False

    rec.status = AnalysisStatus.COMPLETED.value
    assert rec.can_transition_to(AnalysisStatus.RUNNING.value) is False
    assert rec.can_transition_to(AnalysisStatus.PENDING.value) is False
    assert rec.can_transition_to(AnalysisStatus.FAILED.value) is False

    rec.status = AnalysisStatus.FAILED.value
    assert rec.can_transition_to(AnalysisStatus.RUNNING.value) is False


def test_transition_status_service_raises_on_invalid_transition(db_session: Session) -> None:
    """Verify that transition_status raises InvalidStatusTransitionError on invalid transition."""
    rec = analysis_service.create_analysis(db_session, "https://example.com")
    assert rec.status == "pending"

    # Attempt illegal jump from pending directly to completed
    with pytest.raises(InvalidStatusTransitionError):
        analysis_service.transition_status(db_session, rec, AnalysisStatus.COMPLETED.value)


# =====================================================================
# 2. Risk Engine Unit Tests
# =====================================================================

def test_deterministic_risk_engine_exploitability_and_confidence() -> None:
    """Verify that risk engine strictly maintains LOW confidence and UNKNOWN exploitability."""
    engine = DeterministicPassiveRiskEngine()
    items = [
        EvidenceItemCreate(
            signal_name="url_scheme",
            observed_value="https",
            collection_status=EvidenceCollectionStatus.OBSERVED,
            evidence_source="test",
        ),
        EvidenceItemCreate(
            signal_name="hostname_type",
            observed_value="domain_name",
            collection_status=EvidenceCollectionStatus.OBSERVED,
            evidence_source="test",
        ),
    ]

    result = engine.evaluate(items)

    assert result.confidence_level == ConfidenceLevel.LOW
    assert result.exploitability == ExploitabilityStatus.UNKNOWN
    assert result.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
    assert 0 <= result.risk_score <= 100
    assert len(result.contributing_factors) >= 1
    assert len(result.limitations) >= 1


# =====================================================================
# 3. Database Linkage & Cascade Deletion Tests
# =====================================================================

def test_evidence_persistence_and_cascade_delete(db_session: Session) -> None:
    """Verify evidence items are linked to analysis and cascade delete with parent."""
    rec = analysis_service.create_analysis(db_session, "https://target-cascade.org")

    evidence_data = [
        EvidenceItemCreate(
            signal_name="url_scheme",
            observed_value="https",
            collection_status=EvidenceCollectionStatus.OBSERVED,
            evidence_source="test_src",
        ),
        EvidenceItemCreate(
            signal_name="explicit_port",
            observed_value=None,
            collection_status=EvidenceCollectionStatus.ABSENT,
            evidence_source="test_src",
        ),
    ]

    persisted = analysis_service.add_evidence_items(db_session, rec.id, evidence_data)
    assert len(persisted) == 2
    assert persisted[0].analysis_id == rec.id

    # Retrieve via service
    retrieved = analysis_service.get_evidence_by_analysis_id(db_session, rec.id)
    assert len(retrieved) == 2

    # Delete parent analysis record
    db_session.delete(rec)
    db_session.commit()

    # Verify children evidence records are deleted
    remaining_evidence = analysis_service.get_evidence_by_analysis_id(db_session, rec.id)
    assert len(remaining_evidence) == 0


# =====================================================================
# 4. API End-to-End Trigger and Retrieval Tests
# =====================================================================

def test_api_trigger_passive_analysis_success(client: TestClient) -> None:
    """Verify triggering passive analysis via POST /api/v1/analyses/{id}/analyze."""
    # 1. Create a submission
    create_res = client.post("/api/v1/analyses", json={"url": "https://api.secops.internal/login"})
    assert create_res.status_code == 201
    analysis_id = create_res.json()["id"]

    # 2. Trigger passive analysis
    analyze_res = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert analyze_res.status_code == 200
    detail = analyze_res.json()

    assert detail["id"] == analysis_id
    assert detail["status"] == "completed"
    assert detail["error_message"] is None

    # Evidence items check
    assert len(detail["evidence_items"]) >= 5
    signals = {e["signal_name"] for e in detail["evidence_items"]}
    assert "url_scheme" in signals
    assert "hostname_type" in signals
    assert "url_length_metrics" in signals

    # Risk assessment check
    risk = detail["risk_assessment"]
    assert risk is not None
    assert "risk_score" in risk
    assert risk["confidence_level"] == "low"
    assert risk["exploitability"] == "unknown"


def test_api_trigger_analysis_conflict_on_already_completed(client: TestClient) -> None:
    """Verify that triggering analysis on an already completed record returns 409 Conflict."""
    create_res = client.post("/api/v1/analyses", json={"url": "https://conflict-target.org"})
    analysis_id = create_res.json()["id"]

    # First run succeeds
    first_run = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert first_run.status_code == 200

    # Second run should be rejected by lifecycle state machine
    second_run = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert second_run.status_code == 409
    data = second_run.json()
    assert "cannot transition" in data.get("message", "").lower()


def test_api_get_evidence_endpoint(client: TestClient) -> None:
    """Verify querying GET /api/v1/analyses/{id}/evidence."""
    create_res = client.post("/api/v1/analyses", json={"url": "http://10.0.0.1:9090/admin?auth=true"})
    analysis_id = create_res.json()["id"]

    # Trigger analysis first
    client.post(f"/api/v1/analyses/{analysis_id}/analyze")

    # Fetch evidence records
    res = client.get(f"/api/v1/analyses/{analysis_id}/evidence")
    assert res.status_code == 200
    data = res.json()

    assert data["analysis_id"] == analysis_id
    assert data["total"] > 0
    assert data["observed_count"] > 0
    assert data["total"] == data["observed_count"] + data["absent_count"] + data["error_count"]

    # Verify items contain required fields
    for item in data["items"]:
        assert "signal_name" in item
        assert "collection_status" in item
        assert "observation_timestamp" in item


def test_api_analyze_and_evidence_404_for_unknown_id(client: TestClient) -> None:
    """Verify 404 responses when querying non-existent analysis IDs."""
    unknown_id = "00000000-0000-0000-0000-000000000000"

    analyze_res = client.post(f"/api/v1/analyses/{unknown_id}/analyze")
    assert analyze_res.status_code == 404

    evidence_res = client.get(f"/api/v1/analyses/{unknown_id}/evidence")
    assert evidence_res.status_code == 404
