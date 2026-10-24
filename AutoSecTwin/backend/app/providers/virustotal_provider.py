"""VirusTotal API v3 threat intelligence reputation provider.

Provides structured reputation lookups using documented VirusTotal API v3 endpoints.
Enforces strict privacy controls: private IP literals, loopback addresses,
embedded credentials, and internal hostnames are rejected locally before network transmission.
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
    ThreatIntelAuthError,
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
    "intranet",
    "priv",
    "private",
    "box",
    "arpa",
}


def sanitize_indicator_for_logging(indicator: str) -> str:
    """Redact embedded credentials and sensitive parameters from indicator before logging.

    Prevents exposing sensitive credentials in application or audit logs.
    """
    if not indicator:
        return ""
    try:
        if "://" in indicator:
            parsed = urlparse(indicator)
            if parsed.username or parsed.password:
                netloc = parsed.hostname or ""
                if parsed.port:
                    netloc = f"{netloc}:{parsed.port}"
                sanitized_netloc = f"***:***@{netloc}"
                return parsed._replace(netloc=sanitized_netloc).geturl()
        elif "@" in indicator:
            parts = indicator.split("@", 1)
            return f"***:***@{parts[1]}"
    except Exception:
        pass
    return indicator


def is_private_or_internal_indicator(indicator: str) -> Tuple[bool, str]:
    """Inspect indicator locally to determine if it is private, internal, or sensitive.

    Prevents leaking internal corporate addresses or credentials to third parties.

    Args:
        indicator: URL, hostname, or IP address string.

    Returns:
        Tuple of (is_private: bool, reason: str).
    """
    if not indicator or not indicator.strip():
        return True, "Missing or empty indicator."

    stripped_indicator = indicator.strip()

    # 1. Embedded credentials check
    if "://" in stripped_indicator:
        parsed = urlparse(stripped_indicator)
        if parsed.username or parsed.password:
            return True, "Indicator contains embedded user credentials."
        hostname = (parsed.hostname or "").lower().rstrip(".")
    else:
        # Authority check for user:pass@host without scheme
        authority_part = stripped_indicator.split("/")[0]
        if "@" in authority_part:
            return True, "Indicator contains embedded user credentials."
        hostname = authority_part.split(":")[0].lower().rstrip(".")

    if not hostname:
        return True, "Missing or empty hostname."

    # Strip IPv6 brackets if present (e.g. [::1] -> ::1)
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    # 2. Check named loopback references
    if hostname in ("localhost", "ip6-localhost", "ip6-loopback"):
        return True, f"Hostname '{hostname}' is a local loopback reference."

    # 3. Check IP address literal
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return True, f"Hostname is a loopback IP address ({hostname})."
        if ip.is_link_local:
            return True, f"Hostname is a link-local IP address ({hostname})."
        if ip.is_private:
            return True, f"Hostname is an RFC 1918/4193 private IP address ({hostname})."
        if ip.is_reserved or ip.is_unspecified:
            return True, f"Hostname is a reserved/unspecified IP address ({hostname})."
        if ip.is_multicast:
            return True, f"Hostname is a multicast IP address ({hostname})."
    except ValueError:
        pass

    # 4. Check decimal numeric IPv4 integer representations (e.g. 2130706433 -> 127.0.0.1)
    if hostname.isdigit():
        try:
            int_val = int(hostname)
            if 0 <= int_val <= 0xFFFFFFFF:
                ip = ipaddress.IPv4Address(int_val)
                if ip.is_loopback:
                    return True, f"Hostname is a numeric loopback IP address ({ip})."
                if ip.is_private:
                    return True, f"Hostname is a numeric private IP address ({ip})."
                if ip.is_link_local:
                    return True, f"Hostname is a numeric link-local IP address ({ip})."
                if ip.is_reserved or ip.is_unspecified:
                    return True, f"Hostname is a numeric reserved/unspecified IP address ({ip})."
        except (ValueError, OverflowError):
            pass

    # 5. Check internal or single-label domain
    parts = hostname.split(".")
    if len(parts) == 1:
        return True, f"Single-label hostname '{hostname}' is an internal non-routable name."

    tld = parts[-1]
    if tld in INTERNAL_TLDS:
        return True, f"Top-level domain '.{tld}' is reserved for private or internal networks."

    if len(parts) >= 2 and f"{parts[-2]}.{parts[-1]}" == "home.arpa":
        return True, "Domain suffix '.home.arpa' is reserved for residential networks."

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
          - Validates privacy boundaries first (rejects private IPs, loopbacks, internal domains, and credentials).
          - Does not report privacy-blocked lookups as clean results.
          - Enforces strict request timeouts.
          - Disables redirect following (follow_redirects=False).
          - Never logs or exposes the API key.
          - Emits security warning before external network transmission.
        """
        # 1. Privacy Guardrail: Check for internal/private indicators
        is_private, reason = is_private_or_internal_indicator(indicator)
        if is_private:
            sanitized = sanitize_indicator_for_logging(indicator)
            logger.info("Blocked external VirusTotal lookup for private indicator: %s (%s)", sanitized, reason)
            return ThreatIntelResult(
                provider_name=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                lookup_status=ThreatIntelLookupStatus.PRIVACY_BLOCKED,
                threat_verdict=None,
                threat_score=0,
                categories=[],
                raw_data={"privacy_guardrail_applied": True, "reason": reason},
                limitations=[
                    f"External threat intelligence query was blocked by privacy guardrails: {reason}",
                    "No data was transmitted to external third-party services.",
                    "A privacy-blocked lookup is NOT a confirmed clean or safe result.",
                ],
            )

        # 2. Check API key configuration
        if not self._api_key or self._api_key.strip() == "":
            raise ThreatIntelAuthError(
                "VirusTotal API key is not configured. Set the VT_API_KEY environment variable "
                "or configure THREAT_INTEL_PROVIDER=mock for offline testing."
            )

        # 3. Privacy warning before external indicator transmission
        if settings.THREAT_INTEL_WARN_EXTERNAL:
            sanitized = sanitize_indicator_for_logging(indicator)
            logger.warning(
                "THREAT INTEL EXTERNAL LOOKUP: Indicator will be transmitted to external provider '%s' (indicator: %s). "
                "Note: Querying third-party providers discloses the submitted indicator to VirusTotal.",
                self.name,
                sanitized,
            )

        # 4. Construct URL identifier per VT v3 specification
        url_id = compute_virustotal_url_id(indicator)
        endpoint = f"{VIRUSTOTAL_URL_API}/{url_id}"

        headers = {
            "x-apikey": self._api_key,
            "accept": "application/json",
            "User-Agent": f"{settings.APP_NAME}-ThreatIntel/1.0",
        }

        # 5. Perform HTTP query with strict timeout and no automatic redirect following
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                response = client.get(endpoint, headers=headers)

        except httpx.TimeoutException as exc:
            raise ThreatIntelTimeoutError(
                f"VirusTotal query timed out after {self._timeout} seconds."
            ) from exc
        except httpx.RequestError as exc:
            raise ThreatIntelUnavailableError(
                f"Network communication error connecting to VirusTotal endpoint: {exc}"
            ) from exc

        # 6. Handle HTTP status codes according to VirusTotal v3 API semantics
        if response.status_code == 404:
            # Indicator has not been scanned or recorded in VirusTotal database (unknown indicator)
            return ThreatIntelResult(
                provider_name=self.name,
                indicator=indicator,
                indicator_type=indicator_type,
                lookup_status=ThreatIntelLookupStatus.UNKNOWN_INDICATOR,
                threat_verdict=None,
                threat_score=0,
                categories=[],
                raw_data={"http_status": 404, "message": "Indicator not found in VirusTotal database (unknown indicator)"},
                limitations=[
                    "Target indicator has not been submitted to or recorded in VirusTotal (unknown indicator).",
                    "Crucial safety rule: An unknown (not found) indicator is NOT proof that the target is safe or benign.",
                ],
            )

        if response.status_code == 429:
            raise ThreatIntelRateLimitError(
                "VirusTotal API rate limit or quota exceeded (HTTP 429 QuotaExceededError). "
                "Free public tier is limited to 4 requests/minute and 500 requests/day."
            )

        if response.status_code in (401, 403):
            raise ThreatIntelAuthError(
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

        # 7. Parse and validate JSON response schema
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

        # 8. Evaluate analysis stats
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless_count = int(stats.get("harmless", 0))
        undetected_count = int(stats.get("undetected", 0))
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        categories_map = attributes.get("categories", {})
        unique_categories = sorted(list(set(categories_map.values())))

        # Extract reputation score
        reputation_val = attributes.get("reputation", 0)

        # 9. Determine verdict and calculated score
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
                "Reputation results do not prove whether a vulnerability is exploitable without Digital Twin verification.",
                "Exploitability remains UNKNOWN pending isolated verification in a Digital Twin sandbox.",
            ],
        )
