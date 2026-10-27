from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ...models.models import (
    ValidationProcedure, ValidationRun, VulnerabilityFinding, DigitalTwin, User, EvidenceRecord
)
from ...schemas.schemas import (
    ValidationProcedureResponse, ValidationRunCreate, ValidationRunResponse
)
from ...services.validation_engine import validation_engine
from ...services.twin_engine import twin_engine
from ...services.ml_risk_engine import ml_risk_engine
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/validation", tags=["Controlled Vulnerability Validation"])

@router.get("/procedures")
def list_procedures(current_user: User = Depends(get_current_user)):
    """List all certified non-destructive test procedures in the registry."""
    return list(validation_engine.approved_procedures.values())

@router.get("/procedures/{procedure_code}")
def get_procedure_details(procedure_code: str, current_user: User = Depends(get_current_user)):
    """Retrieve detailed specification for a certified test procedure."""
    proc = validation_engine.get_procedure(procedure_code)
    if not proc:
        raise HTTPException(status_code=404, detail=f"Procedure '{procedure_code}' not found in certified registry.")
    return proc

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

    # Safety Check 1: Enforce Twin Lifecycle State
    if twin.status not in ["ready", "testing"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation blocked: Digital Twin '{twin.name}' is currently in '{twin.status}' state. Twin must be in 'ready' state to execute validation probes."
        )

    # Safety Check 2: Enforce Twin Airgap & Network Isolation
    if not twin.network_isolated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation blocked: Digital Twin '{twin.name}' is not marked as network isolated. Validation against non-isolated environments is prohibited."
        )

    isolation_check = twin_engine.verify_isolation(twin.id)
    if not isolation_check.get("isolated"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation blocked: Airgap isolation check failed for twin '{twin.name}'. Status: {isolation_check.get('status')}."
        )

    # Safety Check 3: Enforce Procedure Approval & Dangerous Operation Filter
    if run_in.procedure_code:
        # Check against destructive injection strings
        if not validation_engine.validate_command_safety(run_in.procedure_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Validation blocked: Forbidden or destructive operation pattern detected in procedure input."
            )

        # Check procedure registry whitelist
        if run_in.procedure_code not in validation_engine.approved_procedures:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Validation blocked: Procedure '{run_in.procedure_code}' is unapproved. Only certified non-destructive procedures from the registry are permitted."
            )

    # Transition twin state to testing during run
    twin.status = "testing"
    db.commit()

    try:
        # Execute controlled validation through validation engine
        result = validation_engine.execute_validation(
            finding=finding,
            twin=twin,
            procedure_code=run_in.procedure_code
        )
    finally:
        # Reset twin back to ready after run
        twin.status = "ready"
        db.commit()

    # Safety Check 4: Check if engine blocked execution
    if result.get("outcome") == "blocked":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("test_output", "Validation blocked by safety engine.")
        )

    proc_code = run_in.procedure_code or "AUTO-DISCOVERED"
    if not run_in.procedure_code:
        proc_meta = validation_engine.get_procedure_for_cve(finding.cve_id)
        if proc_meta:
            proc_code = proc_meta["procedure_code"]

    # Persist ValidationRun record
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
        limitations=result.get("limitations", "Controlled non-destructive lab validation. Zero production impact. Exploit payloads prohibited.")
    )
    db.add(run)
    db.flush()

    # Persist Forensic Evidence Record
    duration_ms = int((result["completion_time"] - result["start_time"]).total_seconds() * 1000)
    evidence = EvidenceRecord(
        finding_id=finding.id,
        evidence_type="validation_log",
        title=f"Lab Validation Diagnostic: {proc_code} [{result['outcome'].upper()}]",
        raw_evidence=result["test_output"],
        metadata_info={
            "validation_run_id": run.id,
            "procedure_code": proc_code,
            "twin_id": twin.id,
            "twin_name": twin.name,
            "twin_ip": twin.ip_address,
            "outcome": result["outcome"],
            "preconditions_met": result["preconditions_met"],
            "safety_level": "safe_non_destructive",
            "isolation_verified": True,
            "start_time": result["start_time"].isoformat(),
            "completion_time": result["completion_time"].isoformat(),
            "duration_ms": duration_ms
        }
    )
    db.add(evidence)

    # State Transition: Update finding detection status and risk score based on outcome
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

    elif result["outcome"] in ["inconclusive", "not_reproduced"]:
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
            "outcome": result["outcome"],
            "preconditions_met": result["preconditions_met"]
        }
    )

    return run
