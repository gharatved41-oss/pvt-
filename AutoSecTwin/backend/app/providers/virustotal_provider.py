"""VirusTotal API v3 threat intelligence reputation provider.

Provides structured reputation lookups using documented VirusTotal API v3 endpoints.
Enforces strict privacy controls: private IP literals, loopback addresses,
and internal hostnames are rejected locally before network transmission.
"""

import base64
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.providers.base import (
    BaseThreatIntelProvider,
    ThreatIntelError,
    ThreatIntelInvalidResponseError,
    ThreatIntelRateLimitError,
    ThreatIntelTimeoutError,
    ThreatIntelUnavailableError,
)
from app.schemas.threat_intel import ThreatIntelLookupStatus, ThreatIntelResult

logger = logging.getLogger("vulntwin_ai.providers.virustotal")

VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
INTERNAL_TLDS = {
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "test",
    "example",
    "invalid",
    "localhost",
    "onion",
}


def is_private_or_internal_indicator(indicator: str) -> Tuple[bool, str]:
    """Inspect indicator locally to determine if it is private, internal, or sensitive.

    Prevents leaking internal corporate addresses or credentials to third parties.

    Args:
        indicator: URL, hostname, or IP address string.

    Returns:
        Tuple of (is_private: bool, reason: str).
    """
    if "://" in indicator:
        parsed = urlparse(indicator)
        hostname = (parsed.hostname or "").lower()
        if parsed.username or parsed.password:
            return True, "Indicator contains embedded user credentials."
    else:
        hostname = indicator.split("/")[0].split(":")[0].lower()

    if not hostname:
        return True, "Missing or empty hostname."

    # Check loopback named host
    if hostname == "localhost":
        return True, "Hostname 'localhost' is a local loopback reference."

    # Check IP address literal
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return True, f"Hostname is a loopback IP address ({hostname})."
        if ip.is_private:
            return True, f"Hostname is an RFC 1918/4193 private IP address ({hostname})."
        if ip.is_link_local:
            return True, f"Hostname is a link-local IP address ({hostname})."
        if ip.is_reserved or ip.is_unspecified:
            return True, f"Hostname is a reserved/unspecified IP address ({hostname})."
    except ValueError:
        pass

    # Check internal or single-label domain
    parts = hostname.split(".")
    if len(parts) == 1:
        return True, f"Single-label hostname '{hostname}' is an internal non-routable name."

    tld = parts[-1]
    if tld in INTERNAL_TLDS:
        return True, f"Top-level domain '.{tld}' is reserved for private or internal networks."

    return False, ""


def compute_virustotal_url_id(url: str) -> str:
    """Generate the documented base64url URL identifier required by VirusTotal API v3.

    VirusTotal v3 requires the full URL string to be base64url encoded without '=' padding.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")


class VirusTotalProvider(BaseThreatIntelProvider):
    """Reputation provider querying the official VirusTotal API v3."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._api_key = api_key or settings.VT_API_KEY
        self._timeout = timeout or settings.THREAT_INTEL_TIMEOUT_SECONDS

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def description(self) -> str:
        return "VirusTotal API v3 reputation intelligence provider"

    def lookup(
        self,
        indicator: str,
        indicator_type: str = "url",
        context: Optional[Dict[str, Any]] = None,
    ) -> ThreatIntelResult:
        """Query VirusTotal API v3 for reputation telemetry on the target indicator.

        Safety controls:
          - Validates privacy boundaries first (rejects private IPs and internal domains).
          - Enforces strict request timeouts.
          - Never logs or exposes the API key.
        """
        # 1. Privacy Guardrail: Check for internal/private indicators
        is_private, reason = is_private_or_internal_indicator(indicator)
        if is_private:
            logger.info("Blocked external VirusTotal lookup for private indicator: %s (%s)", indicator, reason)
            return ThreatIntelResult(
                provider_name=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                lookup_status=ThreatIntelLookupStatus.NO_MATCH,
                threat_verdict=None,
                threat_score=0,
                categories=[],
                raw_data={"privacy_guardrail_applied": True, "reason": reason},
                limitations=[
                    f"External threat intelligence query was blocked by privacy guardrails: {reason}",
                    "No data was transmitted to external third-party services.",
                ],
            )

        # 2. Check API key configuration
        if not self._api_key or self._api_key.strip() == "":
            raise ThreatIntelUnavailableError(
                "VirusTotal API key is not configured. Set the VT_API_KEY environment variable "
                "or configure THREAT_INTEL_PROVIDER=mock for offline testing."
            )

        # 3. Construct URL identifier per VT v3 specification
        url_id = compute_virustotal_url_id(indicator)
        endpoint = f"{VIRUSTOTAL_URL_API}/{url_id}"

        headers = {
            "x-apikey": self._api_key,
            "accept": "application/json",
            "User-Agent": f"{settings.APP_NAME}-ThreatIntel/1.0",
        }

        # 4. Perform HTTP query with strict timeout
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(endpoint, headers=headers)

        except httpx.TimeoutException as exc:
            raise ThreatIntelTimeoutError(
                f"VirusTotal query timed out after {self._timeout} seconds."
            ) from exc
        except httpx.RequestError as exc:
            raise ThreatIntelUnavailableError(
                f"Network communication error connecting to VirusTotal endpoint: {exc}"
            ) from exc

        # 5. Handle HTTP status codes
        if response.status_code == 404:
            # Indicator has not been scanned or recorded in VirusTotal
            return ThreatIntelResult(
                provider_name=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                lookup_status=ThreatIntelLookupStatus.NO_MATCH,
                threat_verdict=None,
                threat_score=0,
                categories=[],
                raw_data={"http_status": 404, "message": "Indicator not found in VirusTotal database"},
                limitations=[
                    "Target has not been submitted to or recorded by VirusTotal.",
                    "Crucial safety rule: A negative (no-match) result is NOT proof that the target is safe or benign.",
                ],
            )

        if response.status_code == 429:
            raise ThreatIntelRateLimitError(
                "VirusTotal API rate limit or quota exceeded (HTTP 429 QuotaExceededError). "
                "Free public tier is limited to 4 requests/minute and 500 requests/day."
            )

        if response.status_code in (401, 403):
            raise ThreatIntelUnavailableError(
                f"VirusTotal authentication failed (HTTP {response.status_code}). Verify that VT_API_KEY is valid."
            )

        if response.status_code >= 500:
            raise ThreatIntelUnavailableError(
                f"VirusTotal server error (HTTP {response.status_code}): Service temporarily degraded."
            )

        if response.status_code != 200:
            raise ThreatIntelError(
                f"Unexpected response code from VirusTotal API: HTTP {response.status_code}"
            )

        # 6. Parse and validate JSON response schema
        try:
            payload = response.json()
            data = payload.get("data")
            if not isinstance(data, dict):
                raise ValueError("Response missing top-level 'data' object.")
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
        except Exception as exc:
            raise ThreatIntelInvalidResponseError(
                f"Malformed or unexpected response envelope from VirusTotal API: {exc}"
            ) from exc

        # 7. Evaluate analysis stats
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless_count = int(stats.get("harmless", 0))
        undetected_count = int(stats.get("undetected", 0))
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        categories_map = attributes.get("categories", {})
        unique_categories = sorted(list(set(categories_map.values())))

        # Extract reputation score
        reputation_val = attributes.get("reputation", 0)

        # Determine verdict and calculated score
        if malicious_count > 0:
            verdict = "malicious"
            status = ThreatIntelLookupStatus.MATCH
            threat_score = min(100, max(50, int((malicious_count / max(1, total_engines)) * 100) + 40))
        elif suspicious_count > 0:
            verdict = "suspicious"
            status = ThreatIntelLookupStatus.MATCH
            threat_score = min(75, max(30, suspicious_count * 15))
        else:
            verdict = None
            status = ThreatIntelLookupStatus.NO_MATCH
            threat_score = 0

        return ThreatIntelResult(
            provider_name=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            lookup_status=status,
            threat_verdict=verdict,
            threat_score=threat_score,
            categories=unique_categories,
            raw_data={
                "last_analysis_stats": stats,
                "reputation": reputation_val,
                "total_engines": total_engines,
            },
            limitations=[
                "VirusTotal data represents multi-vendor scanner consensus, not formal proof of exploitability.",
                "A no-match or zero-detection score does NOT certify that the target is safe.",
                "Exploitability remains UNKNOWN pending isolated verification in a Digital Twin sandbox.",
            ],
        )
