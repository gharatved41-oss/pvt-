from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any

from ...services.ml_risk_engine import ml_risk_engine
from ...models.models import User
from ..deps import get_current_user

router = APIRouter(prefix="/risk", tags=["AI/ML Risk Analysis"])

class RiskEvaluationRequest(BaseModel):
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    asset_criticality: str = "high"  # critical, high, medium, low
    asset_environment: str = "production"  # production, staging, development
    exploit_maturity: str = "poc"  # high, critical, functional, poc, unproven
    patch_available: bool = True
    evidence_depth: str = "manifest"  # confirmed, manifest, heuristic
    detection_status: str = "detected"

@router.post("/evaluate")
def evaluate_risk(
    req: RiskEvaluationRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Run ad-hoc ML risk prioritization model evaluation with feature weight breakdown.
    Demonstrates model explainability and separation of severity vs risk.
    """
    return ml_risk_engine.evaluate_risk(
        cvss_score=req.cvss_score,
        asset_criticality=req.asset_criticality,
        asset_environment=req.asset_environment,
        exploit_maturity=req.exploit_maturity,
        patch_available=req.patch_available,
        evidence_depth=req.evidence_depth,
        detection_status=req.detection_status
    )
