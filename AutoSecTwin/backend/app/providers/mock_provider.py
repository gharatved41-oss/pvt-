"""Mock threat intelligence provider for local testing and deterministic evaluation.

Operates entirely in-memory with zero outbound network calls and requires no API keys.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.providers.base import (
    BaseThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelInvalidResponseError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    ThreatIntelUnavailableError,
)
from app.schemas.threat_intel import ThreatIntelLookupStatus, ThreatIntelResult


class MockThreatIntelProvider(BaseThreatIntelProvider):
    """In-memory mock threat intelligence provider with simulated test datasets."""

    def __init__(self, name: str = "mock_threat_intel") -> None:
        self._name = name
        self._forced_exception: Optional[Exception] = None
        self._custom_records: Dict[str, Dict[str, Any]] = {}

        # Default pre-seeded test threats
        self._seed_default_records()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "In-memory deterministic mock threat intelligence provider"

    def _seed_default_records(self) -> None:
        """Seed known sample indicators for test automation."""
        self._custom_records["malicious-threat.org"] = {
            "verdict": "malicious",
            "score": 92,
            "categories": ["phishing", "credential_theft"],
            "raw": {"threat_actor": "APT-SIM", "confidence_score": 0.95},
        }
        self._custom_records["phishing-test.com"] = {
            "verdict": "malicious",
            "score": 88,
            "categories": ["phishing", "banking_fraud"],
            "raw": {"threat_actor": "SIMULATED_PHISH", "confidence_score": 0.90},
        }
        self._custom_records["suspicious-cdn.org"] = {
            "verdict": "suspicious",
            "score": 62,
            "categories": ["suspicious_infrastructure", "unverified_hosting"],
            "raw": {"risk_signals": ["bulletproof_range"], "confidence_score": 0.65},
        }

    def register_record(
        self,
        indicator: str,
        verdict: str,
        score: int,
        categories: Optional[List[str]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Programmatically register a simulated threat intelligence entry."""
        norm_key = self.extract_domain(indicator) or indicator.lower()
        self._custom_records[norm_key] = {
            "verdict": verdict,
            "score": score,
            "categories": categories or [],
            "raw": raw_data or {},
        }

    def set_forced_exception(self, exc: Optional[Exception]) -> None:
        """Force the provider to raise a specific exception on lookup."""
        self._forced_exception = exc

    def lookup(
        self,
        indicator: str,
        indicator_type: str = "url",
        context: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelResult:
        """Look up reputation in the mock dataset.

        Args:
            indicator: Target indicator (URL, hostname, or IP).
            indicator_type: Indicator type identifier.
            context: Optional context dictionary.

        Returns:
            ThreatIntelResult model.

        Raises:
            ThreatIntelTimeoutError, ThreatIntelRateLimitError,
            ThreatIntelInvalidResponseError, ThreatIntelUnavailableError, or ThreatIntelError.
        """
        # 1. Check for programmatic forced exception
        if self._forced_exception:
            raise self._forced_exception

        # 2. Check for token-based simulated errors embedded in indicator string
        lower_indicator = indicator.lower()
        if "simulate-timeout" in lower_indicator or "timeout.test" in lower_indicator:
            raise ThreatIntelTimeoutError("Mock provider request exceeded allowed timeout threshold (3000ms).")
        if "simulate-ratelimit" in lower_indicator or "ratelimit.test" in lower_indicator:
            raise ThreatIntelRateLimitError("Mock provider rate limit exceeded (HTTP 429 Too Many Requests).")
        if "simulate-invalid-response" in lower_indicator or "invalid.test" in lower_indicator:
            raise ThreatIntelInvalidResponseError("Mock provider returned malformed response envelope or invalid JSON.")
        if "simulate-unavailable" in lower_indicator or "unavailable.test" in lower_indicator:
            raise ThreatIntelUnavailableError("Mock provider service endpoint is unreachable or degraded (HTTP 503).")
        if "simulate-generic-error" in lower_indicator:
            raise ThreatIntelError("Mock provider encountered an unexpected internal error.")

        # 3. Check for matching indicator in simulated database
        domain_key = self.extract_domain(indicator)
        matched_data = self._custom_records.get(domain_key) or self._custom_records.get(lower_indicator)

        if matched_data:
            return ThreatIntelResult(
                provider_name=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                lookup_status=ThreatIntelLookupStatus.MATCH,
                threat_verdict=matched_data["verdict"],
                threat_score=matched_data["score"],
                categories=matched_data.get("categories", []),
                raw_data=matched_data.get("raw"),
                limitations=[
                    "Mock provider results are for local testing and validation only.",
                    "Reputation matches do not assert active exploitability in production.",
                ],
            )

        # 4. No match found
        return ThreatIntelResult(
            provider_name=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            lookup_status=ThreatIntelLookupStatus.NO_MATCH,
            threat_verdict=None,
            threat_score=0,
            categories=[],
            raw_data={"status": "clean_no_threat_records"},
            limitations=[
                "Absence of reported reputation telemetry in this provider does NOT prove the target is safe or benign.",
                "Threat intelligence lookup was negative for known IOCs in the simulated database.",
            ],
        )
