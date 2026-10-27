from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from ...core.database import get_db
from ...models.models import (
    RemediationRecommendation, RemediationApproval, DigitalTwin, VulnerabilityFinding, Asset, EvidenceRecord, User
)
from ...schemas.schemas import (
    RemediationRecommendationResponse, RemediationApprovalCreate, RemediationApprovalResponse, RemediationApplyRequest
)
from ...services.remediation_engine import remediation_engine
from ...services.twin_engine import twin_engine
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

@router.get("/recommendations/{rec_id}", response_model=RemediationRecommendationResponse)
def get_recommendation(
    rec_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Remediation recommendation not found")
    return rec

@router.post("/findings/{finding_id}/generate", response_model=RemediationRecommendationResponse, status_code=status.HTTP_201_CREATED)
def generate_remediation_for_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate an evidence-backed remediation recommendation for a vulnerability finding.
    Synthesizes finding details, asset environment, and collected evidence records.
    Never generates arbitrary unverified shell scripts.
    """
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Vulnerability finding not found")

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
    evidence_records = db.query(EvidenceRecord).filter(EvidenceRecord.finding_id == finding.id).all()

    rec_data = remediation_engine.generate_recommendation_data(
        finding=finding,
        asset=asset,
        evidence_records=evidence_records
    )

    rec = RemediationRecommendation(
        finding_id=finding.id,
        action_type=rec_data["action_type"],
        title=rec_data["title"],
        description=rec_data["description"],
        vendor_advisory_url=rec_data["vendor_advisory_url"],
        prerequisites=rec_data["prerequisites"],
        compatibility_concerns=rec_data["compatibility_concerns"],
        command_preview=rec_data["command_preview"],
        rollback_instructions=rec_data["rollback_instructions"],
        expected_outcome=rec_data["expected_outcome"],
        status="recommended"
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)

    audit_service.log_event(
        db=db,
        event_type="remediation",
        action="remediation_generated",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "recommendation_id": rec.id,
            "finding_id": finding.id,
            "title": rec.title
        }
    )

    return rec

@router.post("/recommendations/{rec_id}/approval")
def review_recommendation(
    rec_id: str,
    approval_in: RemediationApprovalCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approve or reject a remediation recommendation with mandatory justification.
    Approvals are strictly scoped to isolated digital twins ('twin_lab'); production changes are forbidden.
    """
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Remediation recommendation not found")

    if not approval_in.justification or len(approval_in.justification.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Justification is required for governance audit compliance."
        )

    approval = RemediationApproval(
        recommendation_id=rec.id,
        user_id=current_user.id,
        status=approval_in.status,
        justification=approval_in.justification.strip(),
        target_environment="twin_lab", # Strict policy: approvals apply only to twin lab
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

    return {
        "message": f"Remediation recommendation {rec.status} successfully",
        "status": rec.status,
        "recommendation_id": rec.id,
        "reviewer": current_user.email
    }

@router.get("/recommendations/{rec_id}/approvals", response_model=List[RemediationApprovalResponse])
def get_recommendation_approvals(
    rec_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List historical approvals and rejections for a remediation recommendation."""
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Remediation recommendation not found")

    approvals = db.query(RemediationApproval).filter(RemediationApproval.recommendation_id == rec_id).order_by(RemediationApproval.approved_at.desc()).all()
    
    result = []
    for a in approvals:
        item = RemediationApprovalResponse.model_validate(a)
        if a.user:
            item.user_email = a.user.email
        result.append(item)
    return result

@router.post("/recommendations/{rec_id}/apply-in-twin")
def apply_remediation_in_twin(
    rec_id: str,
    req: RemediationApplyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Apply approved remediation changes strictly inside designated digital twin sandbox.
    Direct modification of live production assets is strictly prohibited.
    """
    rec = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == rec_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    # Safety Enforcement 1: Explicit Human-in-the-Loop Approval Required
    if rec.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Remediation must be explicitly approved before application. Current status: '{rec.status}'"
        )

    twin = db.query(DigitalTwin).filter(DigitalTwin.id == req.twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Designated digital twin replica not found")

    # Safety Enforcement 2: Twin State & Airgap Isolation Check
    if twin.status not in ["ready", "remediating", "testing"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Digital Twin '{twin.name}' is in '{twin.status}' state. Must be 'ready' before remediation."
        )

    if not twin.network_isolated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Safety restriction: Digital Twin '{twin.name}' is not network-isolated. Airgap required before applying changes."
        )

    # Execute safe lab remediation via predefined adapter
    result = remediation_engine.apply_remediation_in_twin(rec, twin)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    # Recompute twin configuration parity score after remediation
    parity_report = twin_engine.compare_config(twin.target_config or {}, twin.current_config or {})
    twin.config_parity_score = parity_report["config_parity_score"]

    rec.status = "applied_in_twin"
    rec.updated_at = datetime.now(timezone.utc)

    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == rec.finding_id).first()
    if finding:
        # Finding is set to suspected awaiting retest verification
        finding.detection_status = "suspected"

    # Persist Forensic Evidence Record of Lab Remediation Execution
    evidence = EvidenceRecord(
        finding_id=rec.finding_id,
        evidence_type="remediation_log",
        title=f"Lab Remediation Applied: {rec.title} in {twin.name}",
        raw_evidence=result["execution_log"],
        metadata_info={
            "recommendation_id": rec.id,
            "action_type": rec.action_type,
            "twin_id": twin.id,
            "twin_name": twin.name,
            "twin_ip": twin.ip_address,
            "applied_at": result["applied_at"],
            "version_before": result.get("version_before"),
            "version_after": result.get("version_after"),
            "isolation_verified": True
        }
    )
    db.add(evidence)

    db.commit()
    db.refresh(rec)

    audit_service.log_event(
        db=db,
        event_type="remediation",
        action="remediation_applied_in_twin",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "recommendation_id": rec.id,
            "twin_id": twin.id,
            "target_component": finding.affected_component if finding else "unknown",
            "action_type": rec.action_type,
            "version_after": result.get("version_after")
        }
    )

    return {
        "status": "applied_in_twin",
        "result": result,
        "message": "Remediation applied safely in Digital Twin sandbox. Retest verification ready."
    }
