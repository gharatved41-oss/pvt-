"""Pydantic schemas for deterministic risk assessment, confidence, and exploitability."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Categorical risk severity rating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    """Confidence level in the assessment based on breadth of available evidence."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExploitabilityStatus(str, Enum):
    """Verification state of exploitability."""

    UNKNOWN = "unknown"
    THEORETICAL = "theoretical"
    VERIFIED = "verified"


class RiskFactor(BaseModel):
    """Contributing evidentiary factor in the deterministic risk evaluation."""

    signal_name: str = Field(..., description="Signal identifier associated with this factor")
    score_delta: int = Field(..., description="Deterministic integer points contributed (positive or negative)")
    rationale: str = Field(..., description="Transparent factual explanation of why this factor contributed to the score")


class RiskAssessmentResponse(BaseModel):
    """Explainable risk evaluation result based strictly on observed passive evidence."""

    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic composite score between 0 (lowest risk indicators) and 100 (highest risk indicators)",
    )
    risk_level: RiskLevel = Field(..., description="Categorical risk classification")
    confidence_level: ConfidenceLevel = Field(
        default=ConfidenceLevel.LOW,
        description="Confidence level reflecting the extent of evidence collected (Low for passive syntax only)",
    )
    exploitability: ExploitabilityStatus = Field(
        default=ExploitabilityStatus.UNKNOWN,
        description="Exploitability verification status (defaults to 'unknown' in absence of authorized verification)",
    )
    contributing_factors: List[RiskFactor] = Field(
        default_factory=list,
        description="Deterministic list of individual factors contributing to the risk score",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit disclaimers regarding assessment scope and boundaries",
    )
