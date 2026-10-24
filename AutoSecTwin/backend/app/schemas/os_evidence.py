"""Pydantic schemas for operating system security evidence items."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class OSEvidenceStatus(str, Enum):
    """Observation outcome for an operating system evidence signal."""

    OBSERVED = "observed"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    NOT_CHECKED = "not_checked"


class OSPermissionState(str, Enum):
    """Privilege and access state during evidence collection."""

    GRANTED = "granted"
    LIMITED = "limited"
    DENIED = "denied"


class OSEvidenceItemBase(BaseModel):
    """Base schema for an individual OS evidence observation."""

    collector_name: str = Field(
        ...,
        description="Module or probe that gathered this evidence item",
        examples=["linux_dpkg_collector"],
    )
    check_id: str = Field(
        ...,
        description="Identifier of the specific check performed",
        examples=["dpkg_installed_packages"],
    )
    signal_name: str = Field(
        ...,
        description="Standardized classification of the observed signal",
        examples=["installed_package"],
    )
    observed_value: Optional[str] = Field(
        default=None,
        description="Human-readable summary or primary observed metric",
        examples=["openssl 3.0.2-0ubuntu1.10"],
    )
    structured_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Detailed structured observation telemetry dictionary",
    )
    collection_status: OSEvidenceStatus = Field(
        default=OSEvidenceStatus.OBSERVED,
        description="Outcome of evidence gathering: observed, absent, unavailable, error, not_checked",
    )
    permission_state: OSPermissionState = Field(
        default=OSPermissionState.GRANTED,
        description="Privilege level state during collection: granted, limited, denied",
    )
    explanatory_notes: Optional[str] = Field(
        default=None,
        description="Factual context clarifying the observation or explaining why permissions were denied",
    )


class OSEvidenceItemCreate(OSEvidenceItemBase):
    """Schema for internal creation and ingestion of OS evidence items."""

    pass


class OSEvidenceItemResponse(OSEvidenceItemBase):
    """Response model representing a persisted OS evidence record."""

    id: str = Field(..., description="Unique UUID primary key of the evidence record")
    assessment_id: str = Field(..., description="Foreign key referencing the parent assessment")
    observation_timestamp: datetime = Field(..., description="UTC timestamp when the observation occurred")

    model_config = ConfigDict(from_attributes=True)


class OSEvidenceListResponse(BaseModel):
    """Paginated or aggregated response containing OS evidence records."""

    assessment_id: str = Field(..., description="Parent assessment ID")
    items: List[OSEvidenceItemResponse] = Field(default_factory=list, description="List of evidence items")
    total: int = Field(..., description="Total count of evidence items")
    observed_count: int = Field(..., description="Count of successfully observed signals")
    absent_count: int = Field(..., description="Count of signals confirmed absent")
    unavailable_count: int = Field(..., description="Count of signals unavailable due to permissions or environment")
    error_count: int = Field(..., description="Count of signals that encountered runtime errors")
