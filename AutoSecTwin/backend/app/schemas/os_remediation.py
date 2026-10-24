"""Pydantic schemas for explainable OS vulnerability and misconfiguration remediation."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.os_finding import OSConfidence


class ActionCategory(str, Enum):
    """Categorization of the suggested remediation action."""

    PACKAGE_UPGRADE = "package_upgrade"
    SECURITY_CONFIGURATION = "security_configuration"
    PATCH_INSTALLATION = "patch_installation"
    FEATURE_DISABLE = "feature_disable"
    MANUAL_INVESTIGATION = "manual_investigation"


class OSRemediationRecommendation(BaseModel):
    """Structured, explainable remediation guidance for an identified OS security finding."""

    recommendation_id: str = Field(..., description="Unique deterministic recommendation identifier")
    finding_ref: str = Field(..., description="Reference to the finding or rule identifier")
    advisory_id: Optional[str] = Field(default=None, description="Vendor advisory ID (e.g. USN-6409-1)")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if applicable")
    component_name: str = Field(..., description="Target package, service, or OS setting")
    title: str = Field(..., description="Short descriptive title of the recommendation")
    rationale: str = Field(..., description="Why this recommendation is necessary based on observed evidence")
    supporting_evidence: str = Field(..., description="Summary of the empirical evidence triggering this recommendation")
    action_category: ActionCategory = Field(
        default=ActionCategory.PACKAGE_UPGRADE,
        description="Type of remediation activity required",
    )
    suggested_action: str = Field(..., description="High-level, vendor-aligned corrective action")
    security_benefit: str = Field(..., description="Expected threat mitigation and defensive advantage")
    operational_impact: str = Field(..., description="Potential compatibility risks, downtime, or service restarts")
    prerequisites: List[str] = Field(default_factory=list, description="Requirements prior to applying the action")
    verification_steps: List[str] = Field(default_factory=list, description="Safe post-remediation audit steps")
    confidence: OSConfidence = Field(
        default=OSConfidence.MEDIUM,
        description="Confidence in the recommendation based on evidence certainty",
    )
    is_verified_fix: bool = Field(
        default=True,
        description="True if an authoritative vendor patch/version is confirmed in vendor advisory; False if unpatched or heuristic. Indicates vendor fix availability, NOT that the fix has been applied to the host.",
    )
    is_applied: bool = Field(
        default=False,
        description="Always False for newly planned recommendations. Recommendations are proposed actions, not applied or verified host modifications.",
    )
    uncertainty_notes: Optional[str] = Field(
        default=None,
        description="Explicit caveats regarding missing evidence, unpatched status, or unknowns",
    )
    documentation_urls: List[str] = Field(
        default_factory=list,
        description="Authoritative vendor documentation and security notice links",
    )

    model_config = ConfigDict(from_attributes=True)


class OSRemediationPlan(BaseModel):
    """Comprehensive remediation plan for an entire OS assessment."""

    assessment_id: Optional[str] = Field(default=None, description="Parent assessment identifier")
    recommendations: List[OSRemediationRecommendation] = Field(
        default_factory=list,
        description="Ordered list of actionable security recommendations",
    )
    total_recommendations: int = Field(..., description="Total count of recommendations")
    verified_fix_count: int = Field(default=0, description="Count of recommendations with confirmed vendor fixes")
    investigation_required_count: int = Field(
        default=0,
        description="Count of recommendations requiring investigation due to missing fix or ambiguous state",
    )
    remediation_summary: str = Field(..., description="High-level executive summary of recommended hardening")
    limitations: List[str] = Field(
        default_factory=list,
        description="Documented boundaries, missing sources, or unassessed components",
    )

    model_config = ConfigDict(from_attributes=True)
