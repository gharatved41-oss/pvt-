"""Vulnerability matching and Debian version comparison package."""

from app.services.os_matcher.advisory_provider import (
    CANONICAL_USN_METADATA,
    DEBIAN_SECURITY_TRACKER_METADATA,
    MICROSOFT_MSRC_METADATA,
    TRUSTED_ADVISORY_ALLOWLIST,
    AdvisoryEntry,
    AdvisoryProviderError,
    AdvisoryProviderMalformedResponseError,
    AdvisoryProviderTimeoutError,
    AdvisoryProviderUnavailableError,
    AdvisorySourceMetadata,
    BaseAdvisoryProvider,
    CanonicalUSNProvider,
    DebianSecurityTrackerProvider,
    MicrosoftMSRCProvider,
    MockAdvisoryProvider,
    SafeAdvisoryHttpClient,
)

from app.services.os_matcher.debian_version import (
    compare_debian_part,
    compare_debian_versions,
    is_debian_version_less,
    parse_debian_version,
)
from app.services.os_matcher.vulnerability_matcher import (
    MatchEvaluationRecord,
    MatchingEvaluationReport,
    MatchOutcome,
    OSVulnerabilityMatcher,
)

__all__ = [
    "compare_debian_part",
    "compare_debian_versions",
    "is_debian_version_less",
    "parse_debian_version",
    "AdvisoryEntry",
    "AdvisorySourceMetadata",
    "BaseAdvisoryProvider",
    "CanonicalUSNProvider",
    "DebianSecurityTrackerProvider",
    "MicrosoftMSRCProvider",
    "MockAdvisoryProvider",
    "SafeAdvisoryHttpClient",
    "AdvisoryProviderError",

    "AdvisoryProviderTimeoutError",
    "AdvisoryProviderMalformedResponseError",
    "AdvisoryProviderUnavailableError",
    "TRUSTED_ADVISORY_ALLOWLIST",
    "CANONICAL_USN_METADATA",
    "DEBIAN_SECURITY_TRACKER_METADATA",
    "MICROSOFT_MSRC_METADATA",
    "MatchOutcome",
    "MatchEvaluationRecord",
    "MatchingEvaluationReport",
    "OSVulnerabilityMatcher",
]

