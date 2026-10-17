"""Factory for instantiating the configured threat intelligence provider."""

import logging
from typing import Optional

from app.core.config import settings
from app.providers.base import BaseThreatIntelProvider
from app.providers.mock_provider import MockThreatIntelProvider
from app.providers.virustotal_provider import VirusTotalProvider

logger = logging.getLogger("vulntwin_ai.providers.factory")


def get_threat_intel_provider(provider_name: Optional[str] = None) -> BaseThreatIntelProvider:
    """Instantiate threat intelligence provider based on environment configuration.

    Args:
        provider_name: Optional provider identifier override ('mock' or 'virustotal').
                       If None, defaults to settings.THREAT_INTEL_PROVIDER.

    Returns:
        BaseThreatIntelProvider instance.
    """
    selected = (provider_name or settings.THREAT_INTEL_PROVIDER).strip().lower()

    if selected == "virustotal":
        if not settings.VT_API_KEY:
            logger.warning(
                "THREAT_INTEL_PROVIDER is set to 'virustotal', but VT_API_KEY is not configured. "
                "Falling back to MockThreatIntelProvider for safe offline execution."
            )
            return MockThreatIntelProvider()
        return VirusTotalProvider(api_key=settings.VT_API_KEY, timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS)

    if selected != "mock":
        logger.warning(
            "Unknown THREAT_INTEL_PROVIDER '%s'. Falling back to 'mock'.", selected
        )

    return MockThreatIntelProvider()
