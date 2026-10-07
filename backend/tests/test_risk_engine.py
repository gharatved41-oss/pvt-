"""Unit tests for deterministic risk engine.
"""
from backend.app.services.risk_engine import RiskEngine
from backend.app.utils.url_normalizer import normalize_url
from backend.app.providers.base import ProviderResultData
from datetime import datetime, timezone


def test_clean_indicator_scores_low_risk():
    engine = RiskEngine()
    indicators = normalize_url("https://example.com/about")
    provider_results = [
        ProviderResultData(
            provider_name="Test Clean Provider",
            status="AVAILABLE",
            classification="CLEAN",
            confidence=0.85,
            detections=0,
            total_engines=10,
            observed_at=datetime.now(timezone.utc)
        )
    ]
    score, risk_level, confidence, verdict, factors, evidence, exploitability = engine.calculate_risk(
        indicators, provider_results, []
    )
    assert score <= 24
    assert risk_level == "LOW"
    assert verdict == "SAFE"
    assert exploitability.level == "LOW"


def test_malicious_detection_escalates_score_and_verdict():
    engine = RiskEngine()
    indicators = normalize_url("http://spoofed-login.xyz/chase-bank/setup.exe")
    provider_results = [
        ProviderResultData(
            provider_name="Test Threat Feed",
            status="AVAILABLE",
            classification="MALICIOUS",
            confidence=0.92,
            detections=8,
            total_engines=10,
            observed_at=datetime.now(timezone.utc)
        )
    ]
    score, risk_level, confidence, verdict, factors, evidence, exploitability = engine.calculate_risk(
        indicators, provider_results, []
    )
    assert score >= 75
    assert risk_level == "HIGH"
    assert verdict == "MALICIOUS"
    assert exploitability.level == "HIGH"
    assert any(f.name == "Threat Intelligence Detection" for f in factors)


def test_unknown_when_providers_offline_and_zero_signals():
    engine = RiskEngine()
    # Indicator with no lexical red flags and no active providers
    indicators = normalize_url("https://internal-unknown-test-org.org/page")
    provider_results = [
        ProviderResultData(
            provider_name="Test Provider",
            status="UNAVAILABLE",
            classification="UNKNOWN",
            confidence=0.0,
            error_message="Provider down",
            observed_at=datetime.now(timezone.utc)
        )
    ]
    score, risk_level, confidence, verdict, factors, evidence, exploitability = engine.calculate_risk(
        indicators, provider_results, []
    )
    assert verdict == "UNKNOWN"
    assert exploitability.level == "UNKNOWN"
