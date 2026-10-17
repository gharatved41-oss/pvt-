"""Automated unit and integration tests for VirusTotal API v3 provider and factory.

All external HTTP queries are strictly mocked. Zero real external requests or quota consumed.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.config import Settings
from app.providers.base import (
    ThreatIntelError,
    ThreatIntelInvalidResponseError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    ThreatIntelUnavailableError,
)
from app.providers.factory import get_threat_intel_provider
from app.providers.mock_provider import MockThreatIntelProvider
from app.providers.virustotal_provider import (
    VirusTotalProvider,
    compute_virustotal_url_id,
    is_private_or_internal_indicator,
)
from app.schemas.evidence import EvidenceCollectionStatus
from app.schemas.threat_intel import ThreatIntelLookupStatus
from app.services.threat_intel_collector import ThreatIntelCollector


# =====================================================================
# 1. Privacy Guardrail Tests
# =====================================================================

def test_privacy_guardrail_private_ips() -> None:
    """Verify that RFC 1918 private IPs are detected and blocked."""
    is_priv, reason = is_private_or_internal_indicator("http://192.168.1.1/admin")
    assert is_priv is True
    assert "private" in reason.lower()

    is_priv, _ = is_private_or_internal_indicator("http://10.0.0.5:8080/test")
    assert is_priv is True

    is_priv, _ = is_private_or_internal_indicator("http://172.16.50.1/dashboard")
    assert is_priv is True


def test_privacy_guardrail_loopback_and_localhost() -> None:
    """Verify loopback addresses and localhost are detected and blocked."""
    is_priv, reason = is_private_or_internal_indicator("http://127.0.0.1:8000/api")
    assert is_priv is True
    assert "loopback" in reason.lower()

    is_priv, reason = is_private_or_internal_indicator("http://localhost:3000")
    assert is_priv is True
    assert "localhost" in reason.lower()


def test_privacy_guardrail_internal_tlds() -> None:
    """Verify reserved internal TLDs and single-label hostnames are blocked."""
    is_priv, reason = is_private_or_internal_indicator("https://auth.internal/login")
    assert is_priv is True
    assert "internal" in reason.lower()

    is_priv, _ = is_private_or_internal_indicator("http://server.local/share")
    assert is_priv is True

    is_priv, reason = is_private_or_internal_indicator("http://intranet/portal")
    assert is_priv is True
    assert "single-label" in reason.lower()


def test_privacy_guardrail_embedded_credentials() -> None:
    """Verify URLs with embedded credentials are blocked from external dispatch."""
    is_priv, reason = is_private_or_internal_indicator("https://admin:secret123@example.com/api")
    assert is_priv is True
    assert "credentials" in reason.lower()


def test_privacy_guardrail_allows_public_indicators() -> None:
    """Verify valid public indicators pass privacy guardrails."""
    is_priv, _ = is_private_or_internal_indicator("https://example.com/login")
    assert is_priv is False

    is_priv, _ = is_private_or_internal_indicator("http://public-target.io:8080/path")
    assert is_priv is False


# =====================================================================
# 2. VirusTotal URL ID Formatting Tests
# =====================================================================

def test_virustotal_url_id_computation() -> None:
    """Verify URL ID matches VirusTotal v3 base64url specification without padding."""
    url = "https://example.com/test"
    url_id = compute_virustotal_url_id(url)

    assert "=" not in url_id
    assert "/" not in url_id
    assert "+" not in url_id
    assert len(url_id) > 0


# =====================================================================
# 3. VirusTotal Provider Unit Tests with Mocked HTTP Responses
# =====================================================================

def test_virustotal_lookup_blocks_private_indicator_without_http_call() -> None:
    """Verify that private indicators return a safe NO_MATCH without transmitting HTTP requests."""
    provider = VirusTotalProvider(api_key="mock_test_key")

    with patch("httpx.Client.get") as mock_get:
        result = provider.lookup("http://192.168.1.10/login")

        # Zero network calls must be executed
        mock_get.assert_not_called()

        assert result.provider_name == "virustotal"
        assert result.lookup_status == ThreatIntelLookupStatus.NO_MATCH
        assert result.threat_score == 0
        assert any("blocked by privacy guardrails" in lim.lower() for lim in result.limitations)


def test_virustotal_lookup_missing_api_key_raises_unavailable() -> None:
    """Verify that missing API key raises ThreatIntelUnavailableError."""
    provider = VirusTotalProvider(api_key=None)
    with pytest.raises(ThreatIntelUnavailableError) as exc_info:
        provider.lookup("https://example.com/test")
    assert "api key is not configured" in str(exc_info.value).lower()


def test_virustotal_lookup_malicious_match() -> None:
    """Verify parsing of a 200 OK response with confirmed malicious engines."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "id": "mock_id",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10,
                },
                "categories": {
                    "VendorA": "phishing",
                    "VendorB": "malicious",
                },
                "reputation": -25,
            },
        }
    }

    with patch.object(httpx.Client, "get", return_value=mock_response):
        result = provider.lookup("https://malicious-test-site.org/auth")

        assert result.provider_name == "virustotal"
        assert result.lookup_status == ThreatIntelLookupStatus.MATCH
        assert result.threat_verdict == "malicious"
        assert result.threat_score >= 50
        assert "phishing" in result.categories
        assert "malicious" in result.categories


def test_virustotal_lookup_suspicious_match() -> None:
    """Verify parsing when only suspicious engines flag the URL."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "id": "mock_id",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 3,
                    "harmless": 65,
                    "undetected": 5,
                },
                "categories": {"VendorX": "suspicious"},
                "reputation": 0,
            },
        }
    }

    with patch.object(httpx.Client, "get", return_value=mock_response):
        result = provider.lookup("https://suspicious-test.io")

        assert result.lookup_status == ThreatIntelLookupStatus.MATCH
        assert result.threat_verdict == "suspicious"
        assert result.threat_score >= 30


def test_virustotal_lookup_clean_no_match() -> None:
    """Verify that 0 malicious and 0 suspicious engines returns NO_MATCH without safety claims."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "id": "mock_id",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 5,
                },
                "categories": {},
                "reputation": 10,
            },
        }
    }

    with patch.object(httpx.Client, "get", return_value=mock_response):
        result = provider.lookup("https://clean-example.com")

        assert result.lookup_status == ThreatIntelLookupStatus.NO_MATCH
        assert result.threat_verdict is None
        assert result.threat_score == 0


def test_virustotal_lookup_404_not_found() -> None:
    """Verify that HTTP 404 maps cleanly to NO_MATCH."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch.object(httpx.Client, "get", return_value=mock_response):
        result = provider.lookup("https://unscanned-domain-12345.org")

        assert result.lookup_status == ThreatIntelLookupStatus.NO_MATCH
        assert result.threat_score == 0


def test_virustotal_lookup_429_rate_limit() -> None:
    """Verify that HTTP 429 raises ThreatIntelRateLimitError."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch.object(httpx.Client, "get", return_value=mock_response):
        with pytest.raises(ThreatIntelRateLimitError) as exc_info:
            provider.lookup("https://example.com/ratelimit")
        assert "rate limit" in str(exc_info.value).lower()


def test_virustotal_lookup_401_authentication_failure() -> None:
    """Verify that HTTP 401 raises ThreatIntelUnavailableError."""
    provider = VirusTotalProvider(api_key="invalid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch.object(httpx.Client, "get", return_value=mock_response):
        with pytest.raises(ThreatIntelUnavailableError) as exc_info:
            provider.lookup("https://example.com")
        assert "authentication failed" in str(exc_info.value).lower()


def test_virustotal_lookup_timeout_exception() -> None:
    """Verify that httpx.TimeoutException maps to ThreatIntelTimeoutError."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    with patch.object(httpx.Client, "get", side_effect=httpx.TimeoutException("Read timed out")):
        with pytest.raises(ThreatIntelTimeoutError) as exc_info:
            provider.lookup("https://slow-endpoint.org")
        assert "timed out" in str(exc_info.value).lower()


def test_virustotal_lookup_malformed_json_response() -> None:
    """Verify that corrupt JSON response maps to ThreatIntelInvalidResponseError."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected_envelope": 123}

    with patch.object(httpx.Client, "get", return_value=mock_response):
        with pytest.raises(ThreatIntelInvalidResponseError) as exc_info:
            provider.lookup("https://example.com")
        assert "malformed" in str(exc_info.value).lower()


# =====================================================================
# 4. Collector Adapter & Factory Integration Tests
# =====================================================================

def test_threat_intel_collector_with_virustotal_malicious() -> None:
    """Verify ThreatIntelCollector wraps VirusTotalProvider findings into evidence records."""
    provider = VirusTotalProvider(api_key="valid_test_key")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "id": "url_id",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {"malicious": 12, "suspicious": 0, "harmless": 40},
                "categories": {"Vendor": "malware"},
            },
        }
    }

    with patch.object(httpx.Client, "get", return_value=mock_response):
        collector = ThreatIntelCollector(provider)
        evidence = collector.collect("https://malicious-distributor.com/payload")

        assert len(evidence) == 1
        item = evidence[0]
        assert item.signal_name == "virustotal_reputation"
        assert item.collection_status == EvidenceCollectionStatus.OBSERVED
        assert item.observed_value == "malicious"
        assert item.evidence_source == "virustotal"


def test_factory_returns_mock_by_default() -> None:
    """Verify provider factory returns MockThreatIntelProvider under default configuration."""
    with patch("app.providers.factory.settings.THREAT_INTEL_PROVIDER", "mock"):
        provider = get_threat_intel_provider()
        assert isinstance(provider, MockThreatIntelProvider)
        assert provider.name == "mock_threat_intel"


def test_factory_returns_virustotal_when_configured() -> None:
    """Verify provider factory returns VirusTotalProvider when THREAT_INTEL_PROVIDER=virustotal and key set."""
    with patch("app.providers.factory.settings.THREAT_INTEL_PROVIDER", "virustotal"):
        with patch("app.providers.factory.settings.VT_API_KEY", "dummy_key_123"):
            provider = get_threat_intel_provider()
            assert isinstance(provider, VirusTotalProvider)
            assert provider.name == "virustotal"


def test_factory_falls_back_to_mock_if_vt_key_missing() -> None:
    """Verify factory safely falls back to mock provider if VT is chosen but no key is configured."""
    with patch("app.providers.factory.settings.THREAT_INTEL_PROVIDER", "virustotal"):
        with patch("app.providers.factory.settings.VT_API_KEY", None):
            provider = get_threat_intel_provider()
            assert isinstance(provider, MockThreatIntelProvider)
