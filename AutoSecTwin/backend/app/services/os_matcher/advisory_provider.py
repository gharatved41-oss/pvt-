"""Vulnerability advisory provider interface and implementations with explicit source attribution.

Provides authoritative advisory provider abstractions, metadata documentation,
safe network request allowlists, and deterministic mock providers.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.schemas.os_finding import OSSeverity


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


# ==============================================================================
# Trusted Advisory Source Network Constraints & Allowlist
# ==============================================================================

TRUSTED_ADVISORY_ALLOWLIST: Set[str] = {
    "security.ubuntu.com",
    "security-tracker.debian.org",
    "api.msrc.microsoft.com",
    "msrc.microsoft.com",
}

DEFAULT_ADVISORY_TIMEOUT_SECONDS: int = 10
MAX_ADVISORY_RESPONSE_BYTES: int = 5 * 1024 * 1024  # 5 MB safety ceiling


# ==============================================================================
# Advisory Provider Exceptions
# ==============================================================================

class AdvisoryProviderError(Exception):
    """Base exception for all advisory provider failures."""
    pass


class AdvisoryProviderTimeoutError(AdvisoryProviderError):
    """Raised when an advisory provider request exceeds the safety timeout."""
    pass


class AdvisoryProviderMalformedResponseError(AdvisoryProviderError):
    """Raised when an advisory provider returns malformed or invalid schema data."""
    pass


class AdvisoryProviderUnavailableError(AdvisoryProviderError):
    """Raised when an advisory provider service is unreachable or returns 5xx."""
    pass


# ==============================================================================
# Advisory Source Metadata
# ==============================================================================

class AdvisorySourceMetadata(BaseModel):
    """Documentation of coverage, update freshness, licensing, and limitations for an advisory source."""

    source_id: str = Field(..., description="Unique identifier of the advisory feed")
    name: str = Field(..., description="Full descriptive name of the security advisory authority")
    authoritative_url: str = Field(..., description="Official portal or API endpoint documentation")
    coverage_scope: str = Field(..., description="Operating systems, packages, and components covered")
    freshness_description: str = Field(..., description="Frequency and schedule of upstream vulnerability updates")
    license_or_terms: str = Field(..., description="Licensing, usage policies, and attribution terms")
    limitations: List[str] = Field(default_factory=list, description="Explicit boundaries and uncovered scenarios")


CANONICAL_USN_METADATA = AdvisorySourceMetadata(
    source_id="canonical_usn",
    name="Ubuntu Security Notices & Package Security Metadata",
    authoritative_url="https://security.ubuntu.com/notice/",
    coverage_scope="Canonical-supported packages in Ubuntu Main and Universe for active LTS and interim releases",
    freshness_description="Published continuously upon public disclosure and security package release",
    license_or_terms="Freely accessible public security metadata; subject to Canonical Intellectual Property Policy",
    limitations=[
        "Does not cover unmaintained Personal Package Archives (PPAs)",
        "Does not track self-compiled or unpacked binary installations",
        "Third-party snaps or flatpaks are not indexed in deb package notices",
        "Does not guarantee instantaneous coverage of 0-day disclosures prior to vendor publication",
    ],
)

DEBIAN_SECURITY_TRACKER_METADATA = AdvisorySourceMetadata(
    source_id="debian_security_tracker",
    name="Debian Security Bug Tracker & Debian Security Advisories",
    authoritative_url="https://security-tracker.debian.org/",
    coverage_scope="Debian Stable, Oldstable, and Testing releases across official Debian archives",
    freshness_description="Updated continuously by the Debian Security Team and volunteer security auditors",
    license_or_terms="Open security data conforming to the Debian Free Software Guidelines (DFSG)",
    limitations=[
        "Unofficial repositories and backports outside official tracking are not covered",
        "Does not cover non-Debian binaries or local builds",
        "Unfixed vulnerabilities may remain in 'undetermined' or 'postponed' state",
    ],
)

MICROSOFT_MSRC_METADATA = AdvisorySourceMetadata(
    source_id="microsoft_msrc",
    name="Microsoft Security Response Center (MSRC) Vulnerability API",
    authoritative_url="https://api.msrc.microsoft.com/",
    coverage_scope="Supported Windows 10/11 desktop and server operating system builds and Microsoft components",
    freshness_description="Updated on monthly Patch Tuesday cycles and for out-of-band security updates",
    license_or_terms="Microsoft Developer Portal / CVRF & CSAF Open Data Terms",
    limitations=[
        "Covers Microsoft OS binaries and official KB hotfixes only",
        "Does not index arbitrary third-party Windows software installed via installers or zip archives",
        "Matching requires accurate build revision and installed Cumulative Update (KB) evidence",
    ],
)


# ==============================================================================
# Advisory Models
# ==============================================================================

class AdvisoryEntry(BaseModel):
    """Standardized representation of a vulnerability advisory bulletin."""

    advisory_id: str = Field(..., description="Authoritative bulletin ID (e.g., 'USN-6409-1', 'DSA-5500-1')")
    cve_id: str = Field(..., description="Standard CVE identifier (e.g., 'CVE-2023-4911')")
    package_name: str = Field(..., description="Affected package or component name in lowercase (e.g., 'libc6')")
    affected_codename: str = Field(
        default="all",
        description="Distribution release codename (e.g., 'jammy', 'bookworm', or Windows build '22631')",
    )
    affected_architecture: str = Field(
        default="all",
        description="Target CPU architecture if restricted (e.g., 'amd64', 'arm64', or 'all')",
    )
    fixed_version: Optional[str] = Field(
        default=None,
        description="Minimum fixed version string, or None if no fix is published",
    )
    severity: OSSeverity = Field(
        default=OSSeverity.UNRATED,
        description="Authoritative vendor severity rating",
    )
    cvss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS v3 base score if available from authoritative source",
    )
    cvss_version: Optional[str] = Field(default="3.1", description="CVSS specification version")
    title: str = Field(..., description="Concise summary title of the vulnerability")
    description: str = Field(default="", description="Detailed technical description from the advisory")
    source: str = Field(..., description="Authoritative advisory source attribution")
    published_date: Optional[datetime] = Field(default=None, description="UTC timestamp of original publication")


class BaseAdvisoryProvider(ABC):
    """Abstract base class for all vulnerability advisory providers."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Identifier of the advisory authority (e.g., 'canonical_usn', 'microsoft_msrc')."""
        pass

    @property
    @abstractmethod
    def supported_os_family(self) -> str:
        """Target operating system family: 'linux' or 'windows'."""
        pass

    @property
    @abstractmethod
    def metadata(self) -> AdvisorySourceMetadata:
        """Formal metadata documenting source, coverage, and limitations."""
        pass

    @property
    def description(self) -> str:
        """Human-readable provider description."""
        return self.metadata.name

    @abstractmethod
    def get_advisories(
        self,
        component_name: str,
        codename_or_build: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Retrieve advisories affecting the specified component on the target release.

        Args:
            component_name: Package name or product identifier in lowercase.
            codename_or_build: OS release codename (e.g. 'jammy', 'bookworm') or Windows build.
            architecture: Optional CPU architecture filter (e.g. 'amd64').

        Returns:
            List of matching AdvisoryEntry objects.

        Raises:
            AdvisoryProviderTimeoutError: If the upstream source timed out.
            AdvisoryProviderMalformedResponseError: If the payload is unparseable.
            AdvisoryProviderUnavailableError: If the source service is down.
            AdvisoryProviderError: For other general provider failures.
        """
        pass


from urllib.parse import urlparse
import httpx


# ==============================================================================
# Hardened Safe Advisory HTTP Client
# ==============================================================================

class SafeAdvisoryHttpClient:
    """Safe, hardened HTTP client for querying authoritative security advisory endpoints.

    Enforces:
    - Domain allowlist restriction (security.ubuntu.com, security-tracker.debian.org, api.msrc.microsoft.com).
    - HTTPS protocol only.
    - Timeout enforcement (10s default).
    - Maximum response payload ceiling (5 MB).
    - Exception normalization into typed advisory exceptions.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_ADVISORY_TIMEOUT_SECONDS,
        max_bytes: int = MAX_ADVISORY_RESPONSE_BYTES,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._client = client

    def get_json(self, url: str) -> Any:
        """Fetch and validate JSON payload from an authoritative endpoint.

        Args:
            url: Target HTTPS URL.

        Returns:
            Parsed JSON object or dictionary.

        Raises:
            AdvisoryProviderError: On disallowed host, non-HTTPS scheme, or configuration violation.
            AdvisoryProviderTimeoutError: On socket or read timeout.
            AdvisoryProviderMalformedResponseError: On payload exceeding size limit or invalid JSON.
            AdvisoryProviderUnavailableError: On 5xx HTTP response or connection failure.
        """
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            raise AdvisoryProviderError(f"Insecure scheme '{parsed.scheme}'. Only HTTPS is permitted.")

        hostname = (parsed.hostname or "").lower()
        if hostname not in TRUSTED_ADVISORY_ALLOWLIST:
            raise AdvisoryProviderError(f"Target host '{hostname}' is not in TRUSTED_ADVISORY_ALLOWLIST.")

        try:
            if self._client:
                response = self._client.get(url, timeout=self.timeout)
            else:
                with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                    response = client.get(url)

            if response.status_code >= 500:
                raise AdvisoryProviderUnavailableError(f"Advisory service returned HTTP {response.status_code}")
            if response.status_code == 404:
                return {}
            if response.status_code >= 400:
                raise AdvisoryProviderUnavailableError(f"Advisory request failed with HTTP {response.status_code}")

            content_len = len(response.content)
            if content_len > self.max_bytes:
                raise AdvisoryProviderMalformedResponseError(
                    f"Payload size ({content_len} bytes) exceeded safety limit ({self.max_bytes} bytes)"
                )

            return response.json()

        except httpx.TimeoutException as exc:
            raise AdvisoryProviderTimeoutError(f"Timeout querying advisory URL '{url}': {exc}") from exc
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            raise AdvisoryProviderUnavailableError(f"Connection failure to '{url}': {exc}") from exc
        except (ValueError, TypeError) as exc:
            raise AdvisoryProviderMalformedResponseError(f"Failed to parse JSON response from '{url}': {exc}") from exc


# ==============================================================================
# Concrete Advisory Providers
# ==============================================================================

class CanonicalUSNProvider(BaseAdvisoryProvider):
    """Ubuntu Security Notices provider with live retrieval, parsing, schema validation, and normalization.

    Authoritative source: Canonical Ltd. / Ubuntu Security Notices.
    """

    def __init__(
        self,
        http_client: Optional[SafeAdvisoryHttpClient] = None,
        cached_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.http_client = http_client or SafeAdvisoryHttpClient()
        self.cached_data: Dict[str, Any] = cached_data or {}

    @property
    def source_name(self) -> str:
        return "canonical_usn"

    @property
    def supported_os_family(self) -> str:
        return "linux"

    @property
    def metadata(self) -> AdvisorySourceMetadata:
        return CANONICAL_USN_METADATA

    def parse_usn_package_notices(
        self,
        raw_json: Dict[str, Any],
        component_name: str,
        codename: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Parse Canonical USN notices and normalize into validated AdvisoryEntry objects.

        Handles Ubuntu CVE schema containing notices, packages, and distribution fixed versions.
        """
        entries: List[AdvisoryEntry] = []
        notices = raw_json.get("notices", [])
        if isinstance(raw_json, list):
            notices = raw_json

        target_pkg = component_name.lower().strip()
        target_code = (codename or "").lower().strip()

        for notice in notices:
            if not isinstance(notice, dict):
                continue

            advisory_id = str(notice.get("id") or notice.get("usn_id") or "USN-UNKNOWN")
            cves = notice.get("cves") or []
            if isinstance(cves, str):
                cves = [cves]
            cve_id = cves[0] if cves else "CVE-UNKNOWN"

            # Parse release package status
            packages = notice.get("packages", {})
            pkg_info = packages.get(target_pkg, {}) if isinstance(packages, dict) else {}

            fixed_version = pkg_info.get("fixed_version") if isinstance(pkg_info, dict) else None
            affected_release = pkg_info.get("release", "all") if isinstance(pkg_info, dict) else "all"

            # Check codename scoping if specified
            if target_code and affected_release not in ("all", "*") and affected_release.lower() != target_code:
                continue

            # Parse severity
            raw_sev = str(notice.get("severity", "unrated")).lower()
            severity_map = {
                "critical": OSSeverity.CRITICAL,
                "high": OSSeverity.HIGH,
                "medium": OSSeverity.MEDIUM,
                "low": OSSeverity.LOW,
            }
            severity = severity_map.get(raw_sev, OSSeverity.UNRATED)

            entry = AdvisoryEntry(
                advisory_id=advisory_id,
                cve_id=cve_id,
                package_name=target_pkg,
                affected_codename=affected_release,
                fixed_version=fixed_version,
                severity=severity,
                cvss_score=notice.get("cvss_score"),
                title=notice.get("title") or f"{advisory_id}: Security update for {target_pkg}",
                description=notice.get("description", ""),
                source=self.source_name,
            )
            entries.append(entry)

        return entries

    def get_advisories(
        self,
        component_name: str,
        codename_or_build: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Retrieve and normalize Ubuntu Security Notices for the specified package."""
        target_pkg = component_name.lower().strip()
        # If pre-seeded offline/cached data is present, parse it
        if target_pkg in self.cached_data:
            return self.parse_usn_package_notices(self.cached_data[target_pkg], target_pkg, codename_or_build)

        # Live retrieval from allowlisted Canonical endpoint
        endpoint = f"https://security.ubuntu.com/notice/api/v1/packages/{target_pkg}"
        try:
            payload = self.http_client.get_json(endpoint)
            return self.parse_usn_package_notices(payload, target_pkg, codename_or_build)
        except AdvisoryProviderError:
            raise
        except Exception as exc:
            raise AdvisoryProviderUnavailableError(f"Error querying Canonical USN: {exc}") from exc


class DebianSecurityTrackerProvider(BaseAdvisoryProvider):
    """Debian Security Tracker provider with live retrieval, parsing, and normalization.

    Authoritative source: Debian Security Bug Tracker (security-tracker.debian.org).
    """

    def __init__(
        self,
        http_client: Optional[SafeAdvisoryHttpClient] = None,
        cached_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.http_client = http_client or SafeAdvisoryHttpClient()
        self.cached_data: Dict[str, Any] = cached_data or {}

    @property
    def source_name(self) -> str:
        return "debian_security_tracker"

    @property
    def supported_os_family(self) -> str:
        return "linux"

    @property
    def metadata(self) -> AdvisorySourceMetadata:
        return DEBIAN_SECURITY_TRACKER_METADATA

    def parse_debian_security_tracker_json(
        self,
        raw_json: Dict[str, Any],
        component_name: str,
        codename: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Parse official Debian Security Tracker JSON schema and normalize into AdvisoryEntry items.

        Official schema:
        {
          "<package>": {
            "<CVE-ID>": {
              "description": "...",
              "releases": {
                "<codename>": {
                  "status": "resolved" | "open" | "undetermined",
                  "fixed_version": "...",
                  "urgency": "high" | "medium" | "low"
                }
              }
            }
          }
        }
        """
        entries: List[AdvisoryEntry] = []
        target_pkg = component_name.lower().strip()
        target_code = (codename or "").lower().strip()

        pkg_data = raw_json.get(target_pkg, raw_json)
        if not isinstance(pkg_data, dict):
            return []

        urgency_map = {
            "high": OSSeverity.HIGH,
            "medium": OSSeverity.MEDIUM,
            "low": OSSeverity.LOW,
            "unimportant": OSSeverity.LOW,
            "end-of-life": OSSeverity.HIGH,
        }

        for cve_id, cve_info in pkg_data.items():
            if not isinstance(cve_info, dict) or not cve_id.startswith("CVE-"):
                continue

            releases = cve_info.get("releases", {})
            desc = cve_info.get("description", "")

            # If a specific codename is requested, check its status
            if target_code and target_code in releases:
                rel_info = releases[target_code]
                fixed_ver = rel_info.get("fixed_version")
                urgency = str(rel_info.get("urgency", "medium")).lower()
                severity = urgency_map.get(urgency, OSSeverity.MEDIUM)

                entries.append(
                    AdvisoryEntry(
                        advisory_id=cve_id,
                        cve_id=cve_id,
                        package_name=target_pkg,
                        affected_codename=target_code,
                        fixed_version=fixed_ver if fixed_ver != "0" else None,
                        severity=severity,
                        title=f"{cve_id} in {target_pkg} ({target_code})",
                        description=desc,
                        source=self.source_name,
                    )
                )
            elif not target_code:
                # Add all tracked releases
                for rel_name, rel_info in releases.items():
                    fixed_ver = rel_info.get("fixed_version")
                    urgency = str(rel_info.get("urgency", "medium")).lower()
                    severity = urgency_map.get(urgency, OSSeverity.MEDIUM)
                    entries.append(
                        AdvisoryEntry(
                            advisory_id=cve_id,
                            cve_id=cve_id,
                            package_name=target_pkg,
                            affected_codename=rel_name,
                            fixed_version=fixed_ver if fixed_ver != "0" else None,
                            severity=severity,
                            title=f"{cve_id} in {target_pkg} ({rel_name})",
                            description=desc,
                            source=self.source_name,
                        )
                    )

        return entries

    def get_advisories(
        self,
        component_name: str,
        codename_or_build: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Retrieve and normalize Debian Security Tracker bulletins."""
        target_pkg = component_name.lower().strip()
        if target_pkg in self.cached_data:
            return self.parse_debian_security_tracker_json(self.cached_data[target_pkg], target_pkg, codename_or_build)

        endpoint = f"https://security-tracker.debian.org/tracker/data/json"
        try:
            payload = self.http_client.get_json(endpoint)
            return self.parse_debian_security_tracker_json(payload, target_pkg, codename_or_build)
        except AdvisoryProviderError:
            raise
        except Exception as exc:
            raise AdvisoryProviderUnavailableError(f"Error querying Debian Security Tracker: {exc}") from exc


class MicrosoftMSRCProvider(BaseAdvisoryProvider):
    """Microsoft Security Response Center (MSRC) provider with CVRF parsing and normalization.

    Authoritative source: api.msrc.microsoft.com.
    """

    def __init__(
        self,
        http_client: Optional[SafeAdvisoryHttpClient] = None,
        cached_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.http_client = http_client or SafeAdvisoryHttpClient()
        self.cached_data: Dict[str, Any] = cached_data or {}

    @property
    def source_name(self) -> str:
        return "microsoft_msrc"

    @property
    def supported_os_family(self) -> str:
        return "windows"

    @property
    def metadata(self) -> AdvisorySourceMetadata:
        return MICROSOFT_MSRC_METADATA

    def parse_msrc_cvrf_json(
        self,
        raw_json: Dict[str, Any],
        component_name: str,
        build: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Parse Microsoft MSRC CVRF JSON schema and normalize into AdvisoryEntry items.

        Extracts vulnerability Title, CVE, CVSS base score, and fixed KB/build remediation.
        """
        entries: List[AdvisoryEntry] = []
        vulns = raw_json.get("Vulnerability", [])
        target_comp = component_name.lower().strip()

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            cve_id = vuln.get("CVE", "CVE-UNKNOWN")
            title = vuln.get("Title", {}).get("Value", f"Microsoft Security Update for {cve_id}")

            # CVSS Score extraction
            cvss_score = None
            cvss_sets = vuln.get("CVSSScoreSets", [])
            if cvss_sets and isinstance(cvss_sets, list):
                cvss_score = cvss_sets[0].get("BaseScore")

            # Extract fixed build from Remediations
            fixed_build = None
            remediations = vuln.get("Remediations", [])
            for rem in remediations:
                desc = rem.get("Description", {}).get("Value", "")
                if "KB" in desc or "Build" in desc:
                    fixed_build = desc
                    break

            entries.append(
                AdvisoryEntry(
                    advisory_id=cve_id,
                    cve_id=cve_id,
                    package_name=target_comp,
                    affected_codename=build or "all",
                    fixed_version=fixed_build,
                    severity=OSSeverity.HIGH if (cvss_score and cvss_score >= 7.0) else OSSeverity.MEDIUM,
                    cvss_score=cvss_score,
                    title=title,
                    description=vuln.get("Notes", [{}])[0].get("Value", "") if vuln.get("Notes") else "",
                    source=self.source_name,
                )
            )

        return entries

    def get_advisories(
        self,
        component_name: str,
        codename_or_build: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Retrieve and normalize Microsoft MSRC security updates."""
        target_comp = component_name.lower().strip()
        if target_comp in self.cached_data:
            return self.parse_msrc_cvrf_json(self.cached_data[target_comp], target_comp, codename_or_build)

        endpoint = f"https://api.msrc.microsoft.com/cvrf/v2.0/document/{codename_or_build or 'current'}"
        try:
            payload = self.http_client.get_json(endpoint)
            return self.parse_msrc_cvrf_json(payload, target_comp, codename_or_build)
        except AdvisoryProviderError:
            raise
        except Exception as exc:
            raise AdvisoryProviderUnavailableError(f"Error querying Microsoft MSRC: {exc}") from exc



class MockAdvisoryProvider(BaseAdvisoryProvider):
    """In-memory advisory provider pre-seeded with deterministic test fixtures.

    Supports simulating errors: timeouts, malformed responses, and unavailable states.
    """

    def __init__(
        self,
        source_name: str = "canonical_usn_mock",
        os_family: str = "linux",
        advisories: Optional[List[AdvisoryEntry]] = None,
        simulate_timeout: bool = False,
        simulate_malformed: bool = False,
        simulate_unavailable: bool = False,
    ) -> None:
        self._source_name = source_name
        self._os_family = os_family
        self._advisories: List[AdvisoryEntry] = advisories or []
        self.simulate_timeout = simulate_timeout
        self.simulate_malformed = simulate_malformed
        self.simulate_unavailable = simulate_unavailable

    @property
    def source_name(self) -> str:
        return self._source_name

    @property
    def supported_os_family(self) -> str:
        return self._os_family

    @property
    def metadata(self) -> AdvisorySourceMetadata:
        return AdvisorySourceMetadata(
            source_id=self._source_name,
            name=f"Mock Advisory Provider ({self._source_name})",
            authoritative_url="mock://localhost/advisories",
            coverage_scope="Deterministic test fixtures for validation",
            freshness_description="Deterministic in-memory test data",
            license_or_terms="Test harness only",
            limitations=["Contains only preconfigured mock records"],
        )

    def add_advisory(self, entry: AdvisoryEntry) -> None:
        """Dynamically add an advisory entry for testing."""
        self._advisories.append(entry)

    def get_advisories(
        self,
        component_name: str,
        codename_or_build: Optional[str] = None,
        architecture: Optional[str] = None,
    ) -> List[AdvisoryEntry]:
        """Find matching advisories for the given component and release."""
        if self.simulate_timeout:
            raise AdvisoryProviderTimeoutError(f"Provider '{self._source_name}' timed out after 10s")
        if self.simulate_malformed:
            raise AdvisoryProviderMalformedResponseError(f"Provider '{self._source_name}' returned malformed JSON payload")
        if self.simulate_unavailable:
            raise AdvisoryProviderUnavailableError(f"Provider '{self._source_name}' is currently unreachable (503)")

        matches: List[AdvisoryEntry] = []
        target_name = component_name.lower().strip()

        for adv in self._advisories:
            if adv.package_name.lower() == target_name:
                matches.append(adv)

        return matches


