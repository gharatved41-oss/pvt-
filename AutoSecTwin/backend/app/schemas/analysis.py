"""Pydantic schemas for target analysis requests and responses."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.evidence import EvidenceItemResponse
from app.schemas.risk import RiskAssessmentResponse
from app.utils.url_validator import validate_and_normalize_url


class AnalysisCreateRequest(BaseModel):
    """Payload for submitting a new target URL for analysis."""

    url: str = Field(
        ...,
        description="Target URL to submit for analysis. Only HTTP and HTTPS schemes are supported.",
        examples=["https://example.com/login"],
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, value: str) -> str:
        """Validate and canonicalize target URL syntax."""
        return validate_and_normalize_url(value)


class AnalysisResponse(BaseModel):
    """Response model representing an individual analysis record."""

    id: str = Field(..., description="Unique UUID identifier for the analysis record")
    url: str = Field(..., description="Validated and canonicalized target URL")
    status: str = Field(..., description="Current status of the analysis (e.g., 'pending')")
    created_at: datetime = Field(..., description="UTC creation timestamp")
    error_message: Optional[str] = Field(default=None, description="Error message if analysis failed")

    model_config = ConfigDict(from_attributes=True)


class AnalysisDetailResponse(AnalysisResponse):
    """Detailed response model including associated evidence records and risk evaluation."""

    evidence_items: List[EvidenceItemResponse] = Field(
        default_factory=list,
        description="List of security evidence items gathered for this analysis",
    )
    risk_assessment: Optional[RiskAssessmentResponse] = Field(
        default=None,
        description="Deterministic risk assessment calculated from gathered evidence",
    )


class AnalysisListResponse(BaseModel):
    """Paginated response containing multiple analysis records."""

    items: List[AnalysisResponse] = Field(..., description="List of analysis records")
    total: int = Field(..., description="Total count of recorded analyses")
    limit: int = Field(..., description="Maximum items per page")
    offset: int = Field(..., description="Offset index from start of records")
