from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import (
    RetestResult, VulnerabilityFinding, DigitalTwin, RemediationRecommendation, User
)
from ...schemas.schemas import RetestRequest, RetestResultResponse, BeforeAfterComparison
from ...services.retest_engine import retest_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/retesting", tags=["Retesting and Verification"])

@router.get("/results", response_model=List[RetestResultResponse])
def list_retest_results(
    finding_id: Optional[str] = None,
    twin_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(RetestResult)
    if finding_id:
        query = query.filter(RetestResult.finding_id == finding_id)
    if twin_id:
        query = query.filter(RetestResult.twin_id == twin_id)
    return query.order_by(RetestResult.executed_at.desc()).all()

@router.post("/execute", response_model=RetestResultResponse, status_code=status.HTTP_201_CREATED)
def execute_retest(
    retest_in: RetestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == retest_in.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    twin = db.query(DigitalTwin).filter(DigitalTwin.id == retest_in.twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Digital Twin replica not found")

    original_status = finding.detection_status

    # Execute retest logic
    retest_out = retest_engine.perform_retest(finding=finding, twin=twin)

    # Persist RetestResult record
    retest_record = RetestResult(
        finding_id=finding.id,
        twin_id=twin.id,
        original_finding_status=original_status,
        post_fix_status=retest_out["post_fix_status"],
        package_version_before=retest_out["package_version_before"],
        package_version_after=retest_out["package_version_after"],
        retest_detection_output=retest_out["retest_detection_output"],
        retest_validation_output=retest_out["retest_validation_output"],
        remaining_risk_score=retest_out["remaining_risk_score"],
        conclusion=retest_out["conclusion"],
        executed_at=retest_out["executed_at"]
    )
    db.add(retest_record)

    # Update finding and recommendation states based on retest outcome
    if retest_out["post_fix_status"] == "resolved":
        finding.detection_status = "fixed"
        finding.risk_score = 0.0
        finding.risk_category = "Remediated"
        finding.risk_explanation = f"Vulnerability resolved and verified in Digital Twin '{twin.name}'. Both scanner clearance and non-destructive validation test succeeded."
        
        # Mark recommendation resolved
        rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.finding_id == finding.id).first()
        if rec:
            rec.status = "resolved"
            rec.updated_at = datetime.now(timezone.utc)

    elif retest_out["post_fix_status"] == "remains_present":
        finding.detection_status = "unresolved"
        rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.finding_id == finding.id).first()
        if rec:
            rec.status = "failed"
            rec.updated_at = datetime.now(timezone.utc)
    else:
        finding.detection_status = "inconclusive"

    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(retest_record)

    audit_service.log_event(
        db=db,
        event_type="remediation",
        action="retest_executed",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "finding_id": finding.id,
            "twin_id": twin.id,
            "post_fix_status": retest_out["post_fix_status"],
            "remaining_risk": retest_out["remaining_risk_score"]
        }
    )

    return retest_record

@router.get("/comparison/{finding_id}", response_model=BeforeAfterComparison)
def get_comparison(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    retest = db.query(RetestResult).filter(
        RetestResult.finding_id == finding_id
    ).order_by(RetestResult.executed_at.desc()).first()

    rec = db.query(RemediationRecommendation).filter(
        RemediationRecommendation.finding_id == finding_id
    ).first()

    return {
        "finding_id": finding.id,
        "cve_id": finding.cve_id,
        "component": finding.affected_component,
        "original_version": retest.package_version_before if retest else finding.installed_version,
        "new_version": retest.package_version_after if retest else (finding.fixed_version or "N/A"),
        "original_status": retest.original_finding_status if retest else "detected",
        "final_status": retest.post_fix_status if retest else finding.detection_status,
        "original_risk": finding.cvss_v3_score * 10,
        "remaining_risk": retest.remaining_risk_score if retest else finding.risk_score,
        "remediation_applied": rec.title if rec else "Security patch update",
        "retest_outcome": retest.post_fix_status if retest else "Pending retest",
        "retest_evidence": retest.retest_validation_output if retest else "Retest has not yet been executed in twin."
    }
