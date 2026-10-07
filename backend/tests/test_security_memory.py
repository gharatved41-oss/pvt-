"""Unit and integration tests for Security Memory and Historical Delta.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone

from backend.app.db.session import Base
from backend.app.models.database import Analysis
from backend.app.services.security_memory import SecurityMemoryService
from backend.app.schemas.analysis import EvidenceItem, RecommendationItem


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_security_memory_tracks_repeat_analyses(test_db):
    memory = SecurityMemoryService()
    url = "https://example-test.com/payload.exe"
    norm_url = "https://example-test.com/payload.exe"
    domain = "example-test.com"

    # 1. First Analysis: Score 50 (SUSPICIOUS)
    delta1 = memory.calculate_delta(50, "SUSPICIOUS", None, 0)
    assert delta1.has_history is False
    assert delta1.times_analyzed == 1

    memory.persist_analysis(
        db=test_db,
        analysis_id="AST-TEST-001",
        indicator_type="URL",
        submitted_url=url,
        normalized_url=norm_url,
        domain=domain,
        hostname=domain,
        scheme="https",
        path="/payload.exe",
        query_present=False,
        risk_score=50,
        risk_level="SUSPICIOUS",
        confidence=0.75,
        exploitability_level="MEDIUM",
        verdict="SUSPICIOUS",
        summary="First analysis run",
        duration_ms=100,
        evidence_items=[],
        provider_results=[],
        recommendations=[],
        safepath=None,
        historical=delta1
    )

    # 2. Second Analysis: Score 85 (MALICIOUS)
    previous = memory.find_previous_analyses(test_db, norm_url, domain)
    assert len(previous) == 1
    assert previous[0].analysis_id == "AST-TEST-001"

    delta2 = memory.calculate_delta(85, "MALICIOUS", previous[0], len(previous))
    assert delta2.has_history is True
    assert delta2.previous_analysis_id == "AST-TEST-001"
    assert delta2.previous_risk_score == 50
    assert delta2.score_delta == 35  # +35 points!
    assert delta2.verdict_changed is True
    assert delta2.times_analyzed == 2
    assert "Risk increased by +35 points" in delta2.status_summary

    memory.persist_analysis(
        db=test_db,
        analysis_id="AST-TEST-002",
        indicator_type="URL",
        submitted_url=url,
        normalized_url=norm_url,
        domain=domain,
        hostname=domain,
        scheme="https",
        path="/payload.exe",
        query_present=False,
        risk_score=85,
        risk_level="HIGH",
        confidence=0.92,
        exploitability_level="HIGH",
        verdict="MALICIOUS",
        summary="Second analysis run with higher detections",
        duration_ms=90,
        evidence_items=[],
        provider_results=[],
        recommendations=[],
        safepath=None,
        historical=delta2
    )

    # 3. Verify total history count in database
    all_records = memory.find_previous_analyses(test_db, norm_url, domain)
    assert len(all_records) == 2
    assert all_records[0].analysis_id == "AST-TEST-002"  # Newest first
    assert all_records[1].analysis_id == "AST-TEST-001"
