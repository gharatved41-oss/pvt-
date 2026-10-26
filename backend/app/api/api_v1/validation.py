from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ...models.models import (
    ValidationProcedure, ValidationRun, VulnerabilityFinding, DigitalTwin, User
)
from ...schemas.schemas import (
    ValidationProcedureResponse, ValidationRunCreate, ValidationRunResponse
)
from ...services.validation_engine import validation_engine
from ...services.ml_risk_engine import ml_risk_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/validation", tags=["Controlled Vulnerability Validation"])

@router.get("/procedures")
def list_procedures(current_user: User = Depends(get_current_user)):
    return list(validation_engine.approved_procedures.values())

@router.get("/runs", response_model=List[ValidationRunResponse])
def list_validation_runs(
    finding_id: Optional[str] = None,
    twin_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(ValidationRun)
    if finding_id:
        query = query.filter(ValidationRun.finding_id == finding_id)
    if twin_id:
        query = query.filter(ValidationRun.twin_id == twin_id)
    return query.order_by(ValidationRun.created_at.desc()).all()

@router.post("/execute", response_model=ValidationRunResponse, status_code=status.HTTP_201_CREATED)
def execute_validation_test(
    run_in: ValidationRunCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == run_in.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    twin = db.query(DigitalTwin).filter(DigitalTwin.id == run_in.twin_id).first()
    if not twin:
        raise HTTPException(status_code=404, detail="Designated digital twin not found")

    # Execute controlled validation through validation engine
    result = validation_engine.execute_validation(
        finding=finding,
        twin=twin,
        procedure_code=run_in.procedure_code
    )

    proc_code = run_in.procedure_code or "AUTO-DISCOVERED"
    if not run_in.procedure_code:
        proc_meta = validation_engine.get_procedure_for_cve(finding.cve_id)
        if proc_meta:
            proc_code = proc_meta["procedure_code"]

    run = ValidationRun(
        finding_id=finding.id,
        twin_id=twin.id,
        procedure_code=proc_code,
        status=result["status"],
        outcome=result["outcome"],
        start_time=result["start_time"],
        completion_time=result["completion_time"],
        preconditions_met=result["preconditions_met"],
        test_output=result["test_output"],
        error_details=result.get("error_details", ""),
        limitations=result.get("limitations", "Isolated digital twin lab test.")
    )
    db.add(run)

    # If outcome is confirmed, update finding detection_status to 'confirmed' and update ML risk
    if result["outcome"] == "confirmed":
        finding.detection_status = "confirmed"
        # Recalculate ML risk with confirmed status
        updated_risk = ml_risk_engine.evaluate_risk(
            cvss_score=finding.cvss_v3_score,
            asset_criticality=finding.asset.criticality if finding.asset else "high",
            asset_environment=finding.asset.environment if finding.asset else "production",
            exploit_maturity="functional",
            patch_available=True,
            evidence_depth="confirmed",
            detection_status="confirmed"
        )
        finding.risk_score = updated_risk["risk_score"]
        finding.risk_category = updated_risk["risk_category"]
        finding.confidence_score = updated_risk["confidence_score"]
        finding.contributing_factors = updated_risk["contributing_factors"]
        finding.risk_explanation = updated_risk["risk_explanation"]

    elif result["outcome"] == "not_reproduced":
        finding.detection_status = "inconclusive"

    db.commit()
    db.refresh(run)

    audit_service.log_event(
        db=db,
        event_type="validation",
        action="validation_executed",
        user_id=current_user.id,
        user_email=current_user.email,
        details={
            "finding_id": finding.id,
            "twin_id": twin.id,
            "procedure": proc_code,
            "outcome": result["outcome"]
        }
    )

    return run
