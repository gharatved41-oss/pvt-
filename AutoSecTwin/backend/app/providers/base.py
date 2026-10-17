"""Base interface and error hierarchy for modular threat intelligence providers."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.schemas.threat_intel import ThreatIntelLookupStatus, ThreatIntelResult

logger = logging.getLogger("vulntwin_ai.providers")


class ThreatIntelError(Exception):
    """Base exception for all threat intelligence provider errors."""

    pass


class ThreatIntelTimeoutError(ThreatIntelError):
    """Raised when a threat intelligence query times out."""

    pass


class ThreatIntelRateLimitError(ThreatIntelError):
    """Raised when provider rate limits or quotas are exceeded."""

    pass


class ThreatIntelInvalidResponseError(ThreatIntelError):
    """Raised when provider returns an unparseable or schema-violating response."""

    pass


class ThreatIntelUnavailableError(ThreatIntelError):
    """Raised when the provider endpoint or service is unreachable or degraded."""

    pass


class BaseThreatIntelProvider(ABC):
    """Abstract base class for all threat intelligence and reputation providers.

    SAFETY PRINCIPLES:
    1. Threat intelligence providers must NEVER send requests to or establish
       connections with arbitrary user-supplied target indicators or URLs.
    2. Queries are strictly restricted to metadata/reputation lookup against
       known, approved, fixed provider endpoints.
    3. Indicators must be canonicalized and sanitized before querying.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider identifier (e.g., 'mock_threat_intel')."""
        pass

    @property
    def description(self) -> str:
        """Human-readable provider description."""
        return "Threat intelligence reputation provider"

    @property
    def supported_indicator_types(self) -> List[str]:
        """Supported indicator formats: 'url', 'domain', 'ip'."""
        return ["url", "domain", "ip"]

    @abstractmethod
    def lookup(
        self,
        indicator: str,
        indicator_type: str = "url",
        context: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelResult:
        """Query reputation and threat telemetry for the specified indicator.

        Args:
            indicator: Target indicator (e.g., URL or hostname) to check.
            indicator_type: Classification ('url', 'domain', 'ip').
            context: Optional execution parameters.

        Returns:
            ThreatIntelResult containing structured reputation findings.

        Raises:
            ThreatIntelTimeoutError: On query timeout.
            ThreatIntelRateLimitError: On quota or rate limit exhaustion.
            ThreatIntelInvalidResponseError: On corrupt/unexpected provider payload.
            ThreatIntelUnavailableError: When provider infrastructure is down.
            ThreatIntelError: On general provider failure.
        """
        pass

    def extract_domain(self, url_or_domain: str) -> str:
        """Safely extract canonical domain/hostname without making network calls."""
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            return (parsed.hostname or "").lower()
        return url_or_domain.split("/")[0].split(":")[0].lower()
