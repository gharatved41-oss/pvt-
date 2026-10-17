"""Pydantic schemas for structured threat intelligence and reputation results."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class ThreatIntelLookupStatus(str, Enum):
    """Status outcomes for a threat intelligence reputation lookup."""

    MATCH = "match"
    NO_MATCH = "no_match"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    INVALID_RESPONSE = "invalid_response"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class ThreatIntelResult(BaseModel):
    """Standardized representation of threat intelligence reputation findings."""

    provider_name: str = Field(
        ...,
        description="Identifier of the threat intelligence service or provider",
        examples=["mock_threat_intel"],
    )
    indicator: str = Field(
        ...,
        description="The indicator (URL, domain, or IP) queried",
    )
    indicator_type: str = Field(
        default="url",
        description="Classification of indicator: 'url', 'domain', 'ip', or 'hash'",
    )
    lookup_status: ThreatIntelLookupStatus = Field(
        ...,
        description="Outcome of the reputation query (match, no_match, timeout, etc.)",
    )
    threat_verdict: Optional[str] = Field(
        default=None,
        description="Categorical threat verdict if match found: 'malicious', 'suspicious', 'benign'",
    )
    threat_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description="Provider-reported threat score between 0 and 100",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Threat classification tags (e.g., ['phishing', 'credential_theft'])",
    )
    raw_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Raw structured metadata returned by the provider",
    )
    observation_timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the provider lookup was executed",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit limitations and disclaimers regarding the provider's result",
    )
