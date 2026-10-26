from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import (
    RemediationRecommendation, RemediationApproval, DigitalTwin, VulnerabilityFinding, User
)
from ...schemas.schemas import (
    RemediationRecommendationResponse, RemediationApprovalCreate, RemediationApplyRequest
)
from ...services.remediation_engine import remediation_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/remediation", tags=["AI-Assisted Remediation"])

@router.get("/recommendations", response_model=List[RemediationRecommendationResponse])
def list_recommendations(
    finding_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(RemediationRecommendation)
    if finding_id:
        query = query.filter(RemediationRecommendation.finding_id == finding_id)
    if status:
        query = query.filter(RemediationRecommendation.status == status)
    return query.order_by(RemediationRecommendation.created_at.desc()).all()

@router.post("/recommendations/{rec_id}/approval")
def review_recommendation(
    rec_id: str,
    approval_in: RemediationApprovalCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Remediation recommendation not found")

    approval = RemediationApproval(
        recommendation_id=rec.id,
        user_id=current_user.id,
        status=approval_in.status,
        justification=approval_in.justification,
        target_environment="twin_lab",
        approved_at=datetime.now(timezone.utc)
    )
    db.add(approval)

    rec.status = "approved" if approval_in.status == "approved" else "rejected"
    rec.updated_at = datetime.now(timezone.utc)
    db.commit()

    audit_service.log_event(
        db=db,
        event_type="remediation",
        action=f"remediation_{approval_in.status}",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "recommendation_id": rec.id,
            "finding_id": rec.finding_id,
            "status": rec.status,
            "justification": approval_in.justification
        }
    )

    return {"message": f"Remediation recommendation {rec.status} successfully", "status": rec.status}

@router.post("/recommendations/{rec_id}/apply-in-twin")
def apply_remediation_in_twin(
    rec_id: str,
    req: RemediationApplyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    if rec.status != "approved":
        raise HTTPException(
            status_code=400,
            detail=f"Safety restriction: Remediation must be explicitly approved before application. Current status: '{rec.status}'"
        )

    twin = db.query(DigitalTwin).filter(DigitalTwin.id == req.twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Designated digital twin replica not found")

    # Enforce safe application strictly inside twin
    result = remediation_engine.apply_remediation_in_twin(rec, twin)
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error"))

    rec.status = "applied_in_twin"
    rec.updated_at = datetime.now(timezone.utc)
    
    # Mark finding as retest pending
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == rec.finding_id).first()
    if finding:
        finding.detection_status = "suspected"  # awaiting retest confirmation
    
    db.commit()

    audit_service.log_event(
        db=db,
        event_type="remediation",
        action="remediation_applied_in_twin",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "recommendation_id": rec.id,
            "twin_id": twin.id,
            "target_component": finding.affected_component if finding else "unknown"
        }
    )

    return {
        "status": "applied_in_twin",
        "result": result,
        "message": "Remediation applied safely in Digital Twin sandbox. Retest verification ready."
    }
