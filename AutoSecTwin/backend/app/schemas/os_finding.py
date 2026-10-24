"""Pydantic schemas for operating system security findings and vulnerabilities."""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class OSSeverity(str, Enum):
    """Authoritative severity rating from vendor advisory or CVSS mapping."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNRATED = "unrated"


class OSConfidence(str, Enum):
    """Degree of certainty in the finding based on evidence breadth."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OSExploitability(str, Enum):
    """Empirical verification state of exploitability. Strictly UNKNOWN by default."""

    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    VERIFIED = "verified"


class OSFindingType(str, Enum):
    """Classification of the security finding."""

    CVE_VULNERABILITY = "cve_vulnerability"
    MISCONFIGURATION = "misconfiguration"
    MISSING_PATCH = "missing_patch"


class OSFindingBase(BaseModel):
    """Base schema for an individual OS security finding."""

    finding_type: OSFindingType = Field(
        default=OSFindingType.CVE_VULNERABILITY,
        description="Type of finding: cve_vulnerability, misconfiguration, missing_patch",
    )
    advisory_id: str = Field(
        ...,
        description="Authoritative vendor advisory or public CVE identifier",
        examples=["CVE-2023-4911"],
    )
    title: str = Field(
        ...,
        description="Concise descriptive title of the finding",
        examples=["Buffer overflow in dynamic linker (ld.so)"],
    )
    component_name: str = Field(
        ...,
        description="Affected software component or package",
        examples=["libc6"],
    )
    installed_version: Optional[str] = Field(
        default=None,
        description="Version currently observed on the system",
        examples=["2.35-0ubuntu3.1"],
    )
    fixed_version: Optional[str] = Field(
        default=None,
        description="Minimum fixed version designated in the vendor advisory",
        examples=["2.35-0ubuntu3.4"],
    )
    cvss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Authoritative CVSS base score (0.0 to 10.0), or None if unrated",
        examples=[9.8],
    )
    cvss_version: Optional[str] = Field(
        default="3.1",
        description="CVSS specification version",
        examples=["3.1"],
    )
    severity: OSSeverity = Field(
        default=OSSeverity.UNRATED,
        description="Authoritative severity: critical, high, medium, low, unrated",
    )
    confidence: OSConfidence = Field(
        default=OSConfidence.LOW,
        description="Confidence level reflecting evidence breadth: high, medium, low",
    )
    exploitability: OSExploitability = Field(
        default=OSExploitability.UNKNOWN,
        description="Exploitability verification state (strictly 'unknown' by default)",
    )
    advisory_source: Optional[str] = Field(
        default=None,
        description="Originating advisory feed (e.g. 'canonical_usn', 'debian_tracker', 'microsoft_msrc')",
    )
    match_basis: Optional[str] = Field(
        default=None,
        description="Criteria used to establish the finding match (e.g. 'exact_package_version')",
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed description of the vulnerability and security implications",
    )


class OSFindingCreate(OSFindingBase):
    """Schema for internal creation of findings."""

    evidence_id: Optional[str] = Field(
        default=None,
        description="Foreign key of the supporting evidence item",
    )


class OSFindingResponse(OSFindingBase):
    """Response model representing a persisted OS security finding."""

    id: str = Field(..., description="Unique UUID primary key of the finding")
    assessment_id: str = Field(..., description="Parent assessment ID")
    evidence_id: Optional[str] = Field(default=None, description="Primary supporting evidence ID")
    created_at: datetime = Field(..., description="UTC creation timestamp")

    model_config = ConfigDict(from_attributes=True)


class OSFindingListResponse(BaseModel):
    """Response containing multiple OS security findings."""

    assessment_id: str = Field(..., description="Parent assessment ID")
    items: List[OSFindingResponse] = Field(default_factory=list, description="List of findings")
    total: int = Field(..., description="Total count of findings")
    critical_count: int = Field(default=0, description="Count of critical severity findings")
    high_count: int = Field(default=0, description="Count of high severity findings")
    medium_count: int = Field(default=0, description="Count of medium severity findings")
    low_count: int = Field(default=0, description="Count of low severity findings")
    unrated_count: int = Field(default=0, description="Count of unrated findings")
