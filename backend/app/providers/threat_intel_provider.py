"""External Threat Intelligence Adapter (VirusTotal / Reputation APIs).
Guarantees resilience: gracefully reports 'UNAVAILABLE' when unconfigured or offline,
and strictly enforces network timeouts.
"""
from typing import Dict, Any
import base64
from datetime import datetime, timezone
import httpx

from backend.app.config import settings
from backend.app.providers.base import ThreatIntelProvider, ProviderResultData
from backend.app.core.logging import logger


class ExternalThreatIntelProvider(ThreatIntelProvider):
    """
    Adapter for VirusTotal v3 Threat Intelligence API.
    Does NOT invent results if API key is not supplied or if rate-limited.
    """

    def __init__(self):
        super().__init__("VirusTotal Threat Intelligence")

    @property
    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())

    async def analyze_url(self, url: str, indicators: Dict[str, Any]) -> ProviderResultData:
        if not self.is_configured:
            return ProviderResultData(
                provider_name=self.name,
                status="UNAVAILABLE",
                classification="UNKNOWN",
                confidence=0.0,
                error_message="External threat intelligence source unconfigured (API key not provided in environment).",
                observed_at=datetime.now(timezone.utc)
            )

        try:
            # VirusTotal v3 URL ID is base64 of URL without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 404:
                    # Not yet analyzed on VirusTotal
                    return ProviderResultData(
                        provider_name=self.name,
                        status="AVAILABLE",
                        classification="UNKNOWN",
                        confidence=0.4,
                        raw_reference="Target not found in external provider index.",
                        observed_at=datetime.now(timezone.utc)
                    )
                elif response.status_code == 429:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="RATE_LIMITED",
                        classification="UNKNOWN",
                        confidence=0.0,
                        error_message="External provider query rate limit exceeded.",
                        observed_at=datetime.now(timezone.utc)
                    )
                elif response.status_code != 200:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="ERROR",
                        classification="UNKNOWN",
                        confidence=0.0,
                        error_message=f"External provider returned HTTP {response.status_code}.",
                        observed_at=datetime.now(timezone.utc)
                    )

                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                classification = "CLEAN"
                if malicious >= 3:
                    classification = "MALICIOUS"
                elif malicious >= 1 or suspicious >= 2:
                    classification = "SUSPICIOUS"
                elif harmless == 0 and malicious == 0 and suspicious == 0:
                    classification = "UNKNOWN"

                confidence = 0.90 if total > 10 else 0.50

                return ProviderResultData(
                    provider_name=self.name,
                    status="AVAILABLE",
                    classification=classification,
                    confidence=confidence,
                    detections=malicious + suspicious,
                    total_engines=total,
                    raw_reference=f"Detections: {malicious} malicious, {suspicious} suspicious out of {total} engines",
                    observed_at=datetime.now(timezone.utc),
                    details=stats
                )

        except httpx.TimeoutException:
            logger.warning("Timeout contacting external threat intelligence provider.")
            return ProviderResultData(
                provider_name=self.name,
                status="UNAVAILABLE",
                classification="UNKNOWN",
                confidence=0.0,
                error_message="External threat intelligence request timed out.",
                observed_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            logger.error(f"Error querying external threat intel: {str(e)}")
            return ProviderResultData(
                provider_name=self.name,
                status="ERROR",
                classification="UNKNOWN",
                confidence=0.0,
                error_message=str(e),
                observed_at=datetime.now(timezone.utc)
            )

    async def analyze_hash(self, file_hash: str) -> ProviderResultData:
        if not self.is_configured:
            return ProviderResultData(
                provider_name=self.name,
                status="UNAVAILABLE",
                classification="UNKNOWN",
                confidence=0.0,
                error_message="External threat intelligence source unconfigured.",
                observed_at=datetime.now(timezone.utc)
            )

        try:
            endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers)
                if response.status_code == 404:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="AVAILABLE",
                        classification="UNKNOWN",
                        confidence=0.3,
                        raw_reference="Hash not indexed by external provider.",
                        observed_at=datetime.now(timezone.utc)
                    )
                elif response.status_code != 200:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="ERROR",
                        classification="UNKNOWN",
                        confidence=0.0,
                        error_message=f"HTTP {response.status_code}",
                        observed_at=datetime.now(timezone.utc)
                    )

                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                classification = "MALICIOUS" if malicious >= 3 else ("SUSPICIOUS" if (malicious >= 1 or suspicious >= 2) else "CLEAN")
                return ProviderResultData(
                    provider_name=self.name,
                    status="AVAILABLE",
                    classification=classification,
                    confidence=0.92,
                    detections=malicious + suspicious,
                    total_engines=total,
                    raw_reference=f"{malicious} / {total} engines detected as malicious",
                    observed_at=datetime.now(timezone.utc),
                    details=stats
                )
        except Exception as e:
            return ProviderResultData(
                provider_name=self.name,
                status="ERROR",
                classification="UNKNOWN",
                confidence=0.0,
                error_message=str(e),
                observed_at=datetime.now(timezone.utc)
            )


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    Adapter for AbuseIPDB v2 Threat Intelligence API.
    Provides live reputation checking for host IP addresses and reported abusive infrastructure.
    """

    def __init__(self):
        super().__init__("AbuseIPDB Threat Intelligence")

    @property
    def is_configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY and settings.ABUSEIPDB_API_KEY.strip())

    async def analyze_url(self, url: str, indicators: Dict[str, Any]) -> ProviderResultData:
        if not self.is_configured:
            return ProviderResultData(
                provider_name=self.name,
                status="UNAVAILABLE",
                classification="UNKNOWN",
                confidence=0.0,
                error_message="AbuseIPDB API key not configured.",
                observed_at=datetime.now(timezone.utc)
            )

        hostname = indicators.get("hostname", "")
        is_ip = indicators.get("is_ip", False)
        ip_to_check = hostname if is_ip else None

        if not ip_to_check:
            try:
                import socket
                ip_to_check = socket.gethostbyname(hostname)
            except Exception:
                ip_to_check = None

        if not ip_to_check:
            return ProviderResultData(
                provider_name=self.name,
                status="AVAILABLE",
                classification="UNKNOWN",
                confidence=0.3,
                raw_reference="Hostname could not be resolved to public IP for AbuseIPDB telemetry.",
                observed_at=datetime.now(timezone.utc)
            )

        try:
            endpoint = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_to_check,
                "maxAgeInDays": 90
            }

            async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers, params=params)

                if response.status_code == 429:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="RATE_LIMITED",
                        classification="UNKNOWN",
                        confidence=0.0,
                        error_message="AbuseIPDB rate limit reached.",
                        observed_at=datetime.now(timezone.utc)
                    )
                elif response.status_code != 200:
                    return ProviderResultData(
                        provider_name=self.name,
                        status="ERROR",
                        classification="UNKNOWN",
                        confidence=0.0,
                        error_message=f"AbuseIPDB returned HTTP {response.status_code}",
                        observed_at=datetime.now(timezone.utc)
                    )

                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                is_whitelisted = data.get("isWhitelisted", False)
                country = data.get("countryCode", "Unknown")
                isp = data.get("isp", "Unknown")

                if is_whitelisted or abuse_score == 0:
                    classification = "CLEAN"
                    confidence = 0.85
                elif abuse_score >= 50:
                    classification = "MALICIOUS"
                    confidence = min(0.70 + (abuse_score / 200), 0.98)
                elif abuse_score >= 15 or total_reports >= 3:
                    classification = "SUSPICIOUS"
                    confidence = 0.75
                else:
                    classification = "CLEAN"
                    confidence = 0.80

                return ProviderResultData(
                    provider_name=self.name,
                    status="AVAILABLE",
                    classification=classification,
                    confidence=round(confidence, 2),
                    detections=total_reports,
                    total_engines=100,
                    raw_reference=f"Abuse Confidence: {abuse_score}% ({total_reports} reports, ISP: {isp}, Country: {country})",
                    observed_at=datetime.now(timezone.utc),
                    details=data
                )

        except httpx.TimeoutException:
            logger.warning("Timeout contacting AbuseIPDB provider.")
            return ProviderResultData(
                provider_name=self.name,
                status="UNAVAILABLE",
                classification="UNKNOWN",
                confidence=0.0,
                error_message="AbuseIPDB request timed out.",
                observed_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB: {str(e)}")
            return ProviderResultData(
                provider_name=self.name,
                status="ERROR",
                classification="UNKNOWN",
                confidence=0.0,
                error_message=str(e),
                observed_at=datetime.now(timezone.utc)
            )

    async def analyze_hash(self, file_hash: str) -> ProviderResultData:
        return ProviderResultData(
            provider_name=self.name,
            status="UNAVAILABLE",
            classification="UNKNOWN",
            confidence=0.0,
            error_message="AbuseIPDB does not support direct binary hash queries.",
            observed_at=datetime.now(timezone.utc)
        )

