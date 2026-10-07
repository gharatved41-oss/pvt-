"""Abstract base interface for threat intelligence providers.
Provides resilience against timeouts, rate limits, and network errors.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone


class ProviderResultData(BaseModel):
    provider_name: str
    status: str  # AVAILABLE, UNAVAILABLE, RATE_LIMITED, ERROR
    classification: str  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    confidence: float = 0.5
    raw_reference: Optional[str] = None
    detections: int = 0
    total_engines: int = 0
    observed_at: datetime = datetime.now(timezone.utc)
    error_message: Optional[str] = None
    details: Dict[str, Any] = {}


class ThreatIntelProvider(ABC):
    """Base class for all security intelligence provider adapters."""

    def __init__(self, name: str):
        self.name = name

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if required credentials and network configurations are present."""
        pass

    @abstractmethod
    async def analyze_url(self, url: str, indicators: Dict[str, Any]) -> ProviderResultData:
        """Asynchronously queries reputation or threat intelligence for a given URL."""
        pass

    @abstractmethod
    async def analyze_hash(self, file_hash: str) -> ProviderResultData:
        """Asynchronously queries reputation or threat intelligence for a given cryptographic hash."""
        pass
