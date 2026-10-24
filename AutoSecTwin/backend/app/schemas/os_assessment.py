"""Pydantic schemas for operating system security assessment sessions and assets."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.os_evidence import OSEvidenceItemResponse
from app.schemas.os_finding import OSConfidence, OSExploitability, OSFindingResponse


class OSAssessmentStatus(str, Enum):
    """Lifecycle states for operating system assessment execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class OSRiskLevel(str, Enum):
    """Categorical risk classification based on transparent policy evaluation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Asset Schemas
# ---------------------------------------------------------------------------

class OSAssetCreateRequest(BaseModel):
    """Payload for registering or updating an assessed asset profile."""

    host_identifier: str = Field(..., description="Anonymized SHA-256 identifier of the host")
    hostname: str = Field(..., description="Observed host machine name")
    os_family: str = Field(..., description="Operating system family ('windows', 'linux')")
    os_name: str = Field(..., description="Full OS release name (e.g. 'Ubuntu 22.04 LTS')")
    os_version: Optional[str] = Field(default=None, description="Distribution version or Windows display version")
    os_build: Optional[str] = Field(default=None, description="Kernel release or Windows build revision")
    architecture: str = Field(default="x86_64", description="Hardware architecture (x86_64, aarch64)")

    @field_validator("os_family")
    @classmethod
    def validate_os_family(cls, v: str) -> str:
        cleaned = v.lower().strip()
        if cleaned not in ("windows", "linux"):
            raise ValueError(
                f"Unsupported operating system family '{v}'. Only 'windows' and 'linux' are supported."
            )
        return cleaned


class OSAssetResponse(OSAssetCreateRequest):
    """Response model representing a persisted OS asset."""

    id: str = Field(..., description="Unique UUID primary key of the asset record")
    collected_at: datetime = Field(..., description="UTC timestamp when the profile was collected")
    owner_id: Optional[str] = Field(default=None, description="Subject identifier who owns this asset profile")

    model_config = ConfigDict(from_attributes=True)


class OSAssetListResponse(BaseModel):
    """Paginated response containing multiple OS asset profiles."""

    items: List[OSAssetResponse] = Field(..., description="List of asset summary records")
    total: int = Field(..., description="Total count of recorded assets")
    limit: int = Field(..., description="Page item limit")
    offset: int = Field(..., description="Page offset index")


# ---------------------------------------------------------------------------
# Assessment Schemas
# ---------------------------------------------------------------------------

class OSAssessmentCreateRequest(BaseModel):
    """Payload for submitting a new operating system assessment run."""

    asset_id: Optional[str] = Field(
        default=None,
        description="Optional foreign key of an existing asset record",
    )
    assessment_type: str = Field(
        default="local_read_only",
        description="Assessment execution mode (strictly 'local_read_only')",
    )

    @field_validator("assessment_type")
    @classmethod
    def validate_assessment_type(cls, v: str) -> str:
        cleaned = v.lower().strip()
        if cleaned != "local_read_only":
            raise ValueError(
                f"Unauthorized assessment type '{v}'. Only 'local_read_only' assessments are authorized."
            )
        return cleaned


class OSAssessmentResponse(BaseModel):
    """Response model representing an individual OS assessment record."""

    id: str = Field(..., description="Unique UUID identifier for the assessment session")
    asset_id: Optional[str] = Field(default=None, description="Foreign key referencing the target asset")
    assessment_type: str = Field(..., description="Assessment execution mode")
    status: OSAssessmentStatus = Field(..., description="Current lifecycle state (e.g. 'pending')")
    risk_policy_version: str = Field(..., description="Policy version used for risk evaluation")
    risk_score: Optional[int] = Field(default=None, description="Composite risk score (0-100) if evaluated")
    risk_level: Optional[OSRiskLevel] = Field(default=None, description="Categorical risk classification")
    confidence_level: Optional[OSConfidence] = Field(default=None, description="Evidence confidence rating")
    exploitability_state: OSExploitability = Field(
        default=OSExploitability.UNKNOWN,
        description="Exploitability verification status (strictly 'unknown' by default)",
    )
    error_message: Optional[str] = Field(default=None, description="Diagnostic error if assessment failed")
    created_at: datetime = Field(..., description="UTC creation timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="UTC completion timestamp")
    owner_id: Optional[str] = Field(default=None, description="Subject identifier who owns this assessment session")

    model_config = ConfigDict(from_attributes=True)


class OSAssessmentDetailResponse(OSAssessmentResponse):
    """Detailed response model including supporting evidence and identified findings."""

    asset: Optional[OSAssetResponse] = Field(default=None, description="Assessed asset metadata")
    evidence_items: List[OSEvidenceItemResponse] = Field(
        default_factory=list,
        description="List of security evidence items collected during assessment",
    )
    findings: List[OSFindingResponse] = Field(
        default_factory=list,
        description="List of security findings and vulnerabilities identified",
    )


class OSAssessmentListResponse(BaseModel):
    """Paginated response containing multiple OS assessment records."""

    items: List[OSAssessmentResponse] = Field(..., description="List of assessment summary records")
    total: int = Field(..., description="Total count of recorded assessments")
    limit: int = Field(..., description="Page item limit")
    offset: int = Field(..., description="Page offset index")
