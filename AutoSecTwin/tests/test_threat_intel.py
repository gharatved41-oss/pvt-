"""Automated tests for threat intelligence provider interface, mock provider, error handling, and risk evaluation."""

import pytest
from fastapi.testclient import TestClient

from app.providers.base import (
    BaseThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelInvalidResponseError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    ThreatIntelUnavailableError,
)
from app.providers.mock_provider import MockThreatIntelProvider
from app.schemas.evidence import EvidenceCollectionStatus
from app.schemas.risk import ConfidenceLevel, ExploitabilityStatus, RiskLevel
from app.schemas.threat_intel import ThreatIntelLookupStatus
from app.services.collector import CollectorManager
from app.services.passive_analyzer import PassiveUrlAnalyzer
from app.services.risk_engine import DeterministicPassiveRiskEngine
from app.services.threat_intel_collector import ThreatIntelCollector


# =====================================================================
# 1. Mock Provider Direct Unit Tests
# =====================================================================

def test_mock_provider_confirmed_malicious_match() -> None:
    """Verify that the mock provider returns a structured MATCH for pre-seeded malicious indicator."""
    provider = MockThreatIntelProvider()
    result = provider.lookup("https://malicious-threat.org/auth/login")

    assert result.provider_name == "mock_threat_intel"
    assert result.lookup_status == ThreatIntelLookupStatus.MATCH
    assert result.threat_verdict == "malicious"
    assert result.threat_score == 92
    assert "phishing" in result.categories
    assert "credential_theft" in result.categories
    assert len(result.limitations) > 0


def test_mock_provider_confirmed_suspicious_match() -> None:
    """Verify that the mock provider returns a structured MATCH for pre-seeded suspicious indicator."""
    provider = MockThreatIntelProvider()
    result = provider.lookup("http://suspicious-cdn.org:8080/assets")

    assert result.lookup_status == ThreatIntelLookupStatus.MATCH
    assert result.threat_verdict == "suspicious"
    assert result.threat_score == 62
    assert "suspicious_infrastructure" in result.categories


def test_mock_provider_no_match() -> None:
    """Verify that the mock provider returns NO_MATCH for an unlisted target indicator."""
    provider = MockThreatIntelProvider()
    result = provider.lookup("https://standard-benign-service.org/home")

    assert result.lookup_status == ThreatIntelLookupStatus.NO_MATCH
    assert result.threat_verdict is None
    assert result.threat_score == 0
    assert len(result.categories) == 0
    # Check that limitations explicitly note no-match != safe
    assert any("does not prove" in lim.lower() for lim in result.limitations)


def test_mock_provider_timeout_simulation() -> None:
    """Verify that provider raises ThreatIntelTimeoutError on simulated timeout indicator."""
    provider = MockThreatIntelProvider()
    with pytest.raises(ThreatIntelTimeoutError) as exc_info:
        provider.lookup("https://simulate-timeout-service.com/query")
    assert "timeout" in str(exc_info.value).lower()


def test_mock_provider_rate_limit_simulation() -> None:
    """Verify that provider raises ThreatIntelRateLimitError on simulated rate limit indicator."""
    provider = MockThreatIntelProvider()
    with pytest.raises(ThreatIntelRateLimitError) as exc_info:
        provider.lookup("https://simulate-ratelimit-target.org")
    assert "rate limit" in str(exc_info.value).lower()


def test_mock_provider_invalid_response_simulation() -> None:
    """Verify that provider raises ThreatIntelInvalidResponseError on simulated malformed response."""
    provider = MockThreatIntelProvider()
    with pytest.raises(ThreatIntelInvalidResponseError) as exc_info:
        provider.lookup("https://simulate-invalid-response.io")
    assert "malformed" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()


def test_mock_provider_unavailable_simulation() -> None:
    """Verify that provider raises ThreatIntelUnavailableError on simulated service outage."""
    provider = MockThreatIntelProvider()
    with pytest.raises(ThreatIntelUnavailableError) as exc_info:
        provider.lookup("https://simulate-unavailable-host.net")
    assert "unreachable" in str(exc_info.value).lower() or "503" in str(exc_info.value)


def test_mock_provider_generic_error_simulation() -> None:
    """Verify that provider raises ThreatIntelError on generic failure."""
    provider = MockThreatIntelProvider()
    with pytest.raises(ThreatIntelError):
        provider.lookup("https://simulate-generic-error.org")


# =====================================================================
# 2. Collector Adapter Error Handling & Evidence Transformation Tests
# =====================================================================

def test_threat_intel_collector_match_transformation() -> None:
    """Verify collector transforms a MATCH into an OBSERVED evidence item."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://phishing-test.com/login")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.signal_name == "mock_threat_intel_reputation"
    assert item.collection_status == EvidenceCollectionStatus.OBSERVED
    assert item.observed_value == "malicious"
    assert item.structured_data["lookup_status"] == "match"
    assert item.structured_data["threat_score"] == 88
    assert "phishing" in item.explanatory_notes


def test_threat_intel_collector_no_match_transformation() -> None:
    """Verify collector transforms NO_MATCH into an ABSENT evidence item with safety disclaimer."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://clean-domain-test.io")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.signal_name == "mock_threat_intel_reputation"
    assert item.collection_status == EvidenceCollectionStatus.ABSENT
    assert item.observed_value == "no_match"
    assert item.structured_data["lookup_status"] == "no_match"
    # Verify the safety rule is clearly documented in explanatory notes
    assert "does not certify the target is safe" in item.explanatory_notes.lower()


def test_threat_intel_collector_handles_timeout_gracefully() -> None:
    """Verify collector transforms timeout error into ERROR evidence without crashing."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://simulate-timeout.test/api")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.collection_status == EvidenceCollectionStatus.ERROR
    assert "error_timeout" in item.observed_value
    assert item.structured_data["lookup_status"] == "timeout"
    assert "ThreatIntelTimeoutError" in item.structured_data["error_class"]


def test_threat_intel_collector_handles_ratelimit_gracefully() -> None:
    """Verify collector transforms rate limit error into ERROR evidence without crashing."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://simulate-ratelimit.test/auth")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.collection_status == EvidenceCollectionStatus.ERROR
    assert "error_rate_limited" in item.observed_value
    assert item.structured_data["lookup_status"] == "rate_limited"


def test_threat_intel_collector_handles_invalid_response_gracefully() -> None:
    """Verify collector transforms invalid response into ERROR evidence without crashing."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://simulate-invalid-response.test")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.collection_status == EvidenceCollectionStatus.ERROR
    assert "error_invalid_response" in item.observed_value


def test_threat_intel_collector_handles_unavailable_gracefully() -> None:
    """Verify collector transforms unavailable service error into ERROR evidence without crashing."""
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence_list = collector.collect("https://simulate-unavailable.test")

    assert len(evidence_list) == 1
    item = evidence_list[0]
    assert item.collection_status == EvidenceCollectionStatus.ERROR
    assert "error_unavailable" in item.observed_value


# =====================================================================
# 3. Risk Engine Rules for Threat Intelligence Tests
# =====================================================================

def test_risk_engine_malicious_match_elevates_score_and_confidence() -> None:
    """Verify that a confirmed malicious match increases risk and elevates confidence to MEDIUM."""
    engine = DeterministicPassiveRiskEngine()
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence = collector.collect("https://malicious-threat.org/login")

    assessment = engine.evaluate(evidence)

    # Base (10) + Malicious (40) = 50
    assert assessment.risk_score >= 50
    assert assessment.confidence_level == ConfidenceLevel.MEDIUM
    assert assessment.exploitability == ExploitabilityStatus.UNKNOWN
    # Verify factor is recorded
    factors = [f for f in assessment.contributing_factors if "reputation" in f.signal_name]
    assert len(factors) == 1
    assert factors[0].score_delta == 40


def test_risk_engine_no_match_does_not_reduce_score() -> None:
    """Verify that a no-match threat intel result contributes +0 and does NOT decrease risk score."""
    engine = DeterministicPassiveRiskEngine()
    collector = ThreatIntelCollector(MockThreatIntelProvider())
    evidence = collector.collect("https://clean-example-not-in-db.org")

    assessment = engine.evaluate(evidence)

    # Base is 10, no-match adds 0 delta
    assert assessment.risk_score == 10
    assert assessment.confidence_level == ConfidenceLevel.LOW
    assert assessment.exploitability == ExploitabilityStatus.UNKNOWN

    factors = [f for f in assessment.contributing_factors if "reputation" in f.signal_name]
    assert len(factors) == 1
    assert factors[0].score_delta == 0
    assert "not evidence that the target is safe" in factors[0].rationale.lower()


# =====================================================================
# 4. End-to-End API Integration Tests with Threat Intelligence
# =====================================================================

def test_api_trigger_analysis_with_malicious_target(client: TestClient) -> None:
    """Verify API pipeline processes malicious target, records threat evidence, and completes analysis."""
    # 1. Submit target URL
    create_res = client.post("/api/v1/analyses", json={"url": "https://malicious-threat.org/secure-login"})
    assert create_res.status_code == 201
    analysis_id = create_res.json()["id"]

    # 2. Trigger passive analysis
    analyze_res = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert analyze_res.status_code == 200
    data = analyze_res.json()

    assert data["status"] == "completed"

    # Evidence items should include both passive syntax and threat intel reputation
    signal_names = [item["signal_name"] for item in data["evidence_items"]]
    assert "url_scheme" in signal_names
    assert "mock_threat_intel_reputation" in signal_names

    # Check the reputation item details
    threat_item = next(item for item in data["evidence_items"] if item["signal_name"] == "mock_threat_intel_reputation")
    assert threat_item["collection_status"] == "observed"
    assert threat_item["observed_value"] == "malicious"

    # Check risk assessment
    risk = data["risk_assessment"]
    assert risk["risk_level"] in ["medium", "high", "critical"]
    assert risk["confidence_level"] == "medium"
    assert risk["exploitability"] == "unknown"


def test_api_trigger_analysis_with_provider_timeout_simulation(client: TestClient) -> None:
    """Verify API pipeline gracefully completes when threat intel times out without failing the run."""
    create_res = client.post("/api/v1/analyses", json={"url": "https://simulate-timeout.test/portal"})
    assert create_res.status_code == 201
    analysis_id = create_res.json()["id"]

    # Analysis must NOT fail or crash; it must record error evidence and mark run as completed
    analyze_res = client.post(f"/api/v1/analyses/{analysis_id}/analyze")
    assert analyze_res.status_code == 200
    data = analyze_res.json()

    assert data["status"] == "completed"

    # Find the error evidence record
    threat_item = next(item for item in data["evidence_items"] if item["signal_name"] == "mock_threat_intel_reputation")
    assert threat_item["collection_status"] == "error"
    assert "timeout" in threat_item["observed_value"]


def test_api_evidence_endpoint_reflects_threat_intel_counts(client: TestClient) -> None:
    """Verify GET /api/v1/analyses/{id}/evidence counts observed, absent, and error signals accurately."""
    # Clean target
    create_res = client.post("/api/v1/analyses", json={"url": "https://clean-regular-domain.com/index"})
    analysis_id = create_res.json()["id"]
    client.post(f"/api/v1/analyses/{analysis_id}/analyze")

    res = client.get(f"/api/v1/analyses/{analysis_id}/evidence")
    assert res.status_code == 200
    data = res.json()

    assert data["total"] > 0
    signals = {item["signal_name"]: item for item in data["items"]}
    assert "mock_threat_intel_reputation" in signals
    assert signals["mock_threat_intel_reputation"]["collection_status"] == "absent"
