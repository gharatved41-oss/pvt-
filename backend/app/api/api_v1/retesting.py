from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import (
    RetestResult, VulnerabilityFinding, DigitalTwin, RemediationRecommendation, User, EvidenceRecord
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

    # Execute rigorous retest logic
    retest_out = retest_engine.perform_retest(
        finding=finding,
        twin=twin,
        procedure_code=retest_in.procedure_code
    )

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

    # Persist Forensic Retest EvidenceRecord
    evidence = EvidenceRecord(
        finding_id=finding.id,
        evidence_type="retest_evidence",
        title=f"Retest Verification: {finding.affected_component} [{retest_out['post_fix_status'].upper()}]",
        raw_evidence=(
            f"=== LAB RETEST & VERIFICATION EVIDENCE ===\n"
            f"Timestamp: {retest_out['executed_at'].isoformat()}\n"
            f"Digital Twin: {twin.name} (IP: {twin.ip_address})\n"
            f"Target Finding: {finding.cve_id} ({finding.affected_component})\n\n"
            f"--- BEFORE REMEDIATION (BASELINE) ---\n"
            f"Installed Version: {retest_out['package_version_before']}\n"
            f"Initial Detection Status: {original_status}\n\n"
            f"--- AFTER REMEDIATION (RETESTED) ---\n"
            f"Retested Version: {retest_out['package_version_after']}\n"
            f"Outcome: {retest_out['post_fix_status']}\n"
            f"Residual Risk Score: {retest_out['remaining_risk_score']}\n\n"
            f"--- SCANNER RE-CHECK ---\n"
            f"{retest_out['retest_detection_output']}\n\n"
            f"--- VALIDATION PROCEDURE PROBE ---\n"
            f"{retest_out['retest_validation_output']}\n\n"
            f"--- VERIFICATION CONCLUSION ---\n"
            f"{retest_out['conclusion']}"
        ),
        metadata_info={
            "retest_id": retest_record.id,
            "twin_id": twin.id,
            "cve_id": finding.cve_id,
            "component": finding.affected_component,
            "version_before": retest_out["package_version_before"],
            "version_after": retest_out["package_version_after"],
            "original_status": original_status,
            "post_fix_status": retest_out["post_fix_status"],
            "remaining_risk": retest_out["remaining_risk_score"]
        }
    )
    db.add(evidence)

    # Update finding and recommendation states based on retest outcome
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.finding_id == finding.id).first()

    if retest_out["post_fix_status"] == "resolved":
        finding.detection_status = "fixed"
        finding.risk_score = 0.0
        finding.risk_category = "Remediated"
        finding.risk_explanation = (
            f"Vulnerability resolved and verified in Digital Twin '{twin.name}'. "
            f"Both scanner clearance and non-destructive validation test succeeded."
        )
        if rec:
            rec.status = "resolved"
            rec.updated_at = datetime.now(timezone.utc)

    elif retest_out["post_fix_status"] == "remains_present":
        finding.detection_status = "unresolved"
        finding.risk_explanation = (
            f"Lab retest verification failed in Digital Twin '{twin.name}'. "
            f"Vulnerability continues to be reproduced."
        )
        if rec:
            rec.status = "failed"
            rec.updated_at = datetime.now(timezone.utc)
    else:
        finding.detection_status = "inconclusive"
        finding.risk_score = retest_out["remaining_risk_score"]
        finding.risk_explanation = (
            f"Lab retest verification inconclusive in Digital Twin '{twin.name}'. "
            f"Discrepancy or indeterminate telemetry observed."
        )
        if rec:
            rec.status = "retest_pending"
            rec.updated_at = datetime.now(timezone.utc)

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
            "remaining_risk": retest_out["remaining_risk_score"],
            "evidence_id": evidence.id
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

    evidence_text = "Retest has not yet been executed in twin."
    if retest:
        evidence_text = (
            f"{retest.retest_detection_output}\n\n"
            f"{retest.retest_validation_output}\n\n"
            f"Verdict: {retest.conclusion}"
        )

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
        "retest_evidence": evidence_text
    }
