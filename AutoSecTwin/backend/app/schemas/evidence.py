"""Pydantic schemas for security evidence records."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceCollectionStatus(str, Enum):
    """Observation outcome for a security evidence signal."""

    OBSERVED = "observed"
    ABSENT = "absent"
    SKIPPED = "skipped"
    ERROR = "error"


class EvidenceItemBase(BaseModel):
    """Base attributes for security evidence observations."""

    signal_name: str = Field(
        ...,
        description="Standardized signal identifier (e.g., 'url_scheme', 'hostname_type')",
        examples=["url_scheme"],
    )
    observed_value: Optional[str] = Field(
        default=None,
        description="Observed textual representation or summary of the signal",
        examples=["https"],
    )
    structured_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Structured dictionary containing detailed telemetry or raw observations",
    )
    evidence_source: str = Field(
        default="passive_syntax_analyzer",
        description="Module or provider that gathered this evidence item",
    )
    collection_status: EvidenceCollectionStatus = Field(
        default=EvidenceCollectionStatus.OBSERVED,
        description="Collection status: 'observed', 'absent', or 'error'",
    )
    explanatory_notes: Optional[str] = Field(
        default=None,
        description="Contextual remarks clarifying the observation without asserting unverified security conclusions",
    )


class EvidenceItemCreate(EvidenceItemBase):
    """Schema for internal creation of evidence records."""

    pass


class EvidenceItemResponse(EvidenceItemBase):
    """Response schema representing an individual persisted evidence record."""

    id: str = Field(..., description="Unique UUID identifier for the evidence record")
    analysis_id: str = Field(..., description="Foreign key referencing the parent analysis")
    observation_timestamp: datetime = Field(..., description="UTC timestamp when the observation occurred")

    model_config = ConfigDict(from_attributes=True)


class EvidenceListResponse(BaseModel):
    """Response schema containing a collection of evidence records."""

    analysis_id: str = Field(..., description="ID of the analysis to which the evidence belongs")
    items: List[EvidenceItemResponse] = Field(default_factory=list, description="List of evidence items")
    total: int = Field(..., description="Total count of evidence items for this analysis")
    observed_count: int = Field(..., description="Count of signals successfully observed")
    absent_count: int = Field(..., description="Count of signals checked but not present")
    error_count: int = Field(..., description="Count of signals that encountered collection errors")
