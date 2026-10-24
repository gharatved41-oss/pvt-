"""Versioned REST API endpoints for OS security assessment, asset inventory, evidence, findings, risk scores, and remediation."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.security import AuthenticatedUser, require_os_assessor
from app.db.session import get_db
from app.models.os_assessment import OSAssessmentRecord, OSAssessmentStatus
from app.models.os_asset import OSAssetRecord
from app.models.os_evidence import OSEvidenceStatus
from app.models.os_finding import OSSeverity
from app.schemas.os_assessment import (
    OSAssetCreateRequest,
    OSAssetListResponse,
    OSAssetResponse,
    OSAssessmentCreateRequest,
    OSAssessmentDetailResponse,
    OSAssessmentListResponse,
    OSAssessmentResponse,
)
from app.schemas.os_evidence import (
    OSEvidenceItemResponse,
    OSEvidenceListResponse,
)
from app.schemas.os_finding import (
    OSFindingListResponse,
    OSFindingResponse,
)
from app.schemas.os_remediation import OSRemediationPlan
from app.services import os_assessment_service
from app.services.os_assessment_service import (
    AssessmentNotFoundError,
    AssetNotFoundError,
    InvalidStatusTransitionError,
    MateriallyIncompleteAssessmentError,
    UnauthorizedAssessmentError,
    UnsupportedOperatingSystemError,
)
from app.services.os_risk_engine.engine import OSRiskEvaluationResult

logger = logging.getLogger("vulntwin_ai.api.os_assessments")

router = APIRouter()


# ---------------------------------------------------------------------------
# Authorization & Ownership Helpers
# ---------------------------------------------------------------------------

def check_asset_access(asset: OSAssetRecord, user: AuthenticatedUser) -> None:
    """Verify current user has permission to read, inspect, or assess the asset."""
    if user.is_admin:
        return
    if asset.owner_id is not None and asset.owner_id != user.user_id:
        logger.warning(
            "Access denied: user '%s' attempted to access asset '%s' owned by '%s'",
            user.username,
            asset.id,
            asset.owner_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: user '{user.username}' is not authorized to access asset '{asset.id}'.",
        )


def check_assessment_access(assessment: OSAssessmentRecord, user: AuthenticatedUser) -> None:
    """Verify current user has permission to inspect, execute, or view assessment data."""
    if user.is_admin:
        return
    if assessment.owner_id is not None and assessment.owner_id != user.user_id:
        logger.warning(
            "Access denied: user '%s' attempted to access assessment '%s' owned by '%s'",
            user.username,
            assessment.id,
            assessment.owner_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: user '{user.username}' is not authorized to access assessment '{assessment.id}'.",
        )


# ---------------------------------------------------------------------------
# OS Asset Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/assets",
    response_model=OSAssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register OS Asset Profile",
    description="Registers an assessed operating system host profile using validated hardware and platform metadata.",
)
def create_asset(
    payload: OSAssetCreateRequest,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssetResponse:
    """Register or record an assessed OS host asset profile associated with the current user."""
    try:
        record = os_assessment_service.create_os_asset(
            db=db, asset_data=payload, owner_id=user.user_id
        )
        return OSAssetResponse.model_validate(record)
    except UnsupportedOperatingSystemError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/assets",
    response_model=OSAssetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Registered OS Assets",
    description="Retrieves a paginated list of registered operating system asset records owned by the caller.",
)
def list_assets(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of initial records to skip"),
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssetListResponse:
    """Retrieve paginated OS asset records scoped to the authenticated user."""
    owner_filter = None if user.is_admin else user.user_id
    records, total = os_assessment_service.list_os_assets(
        db=db, limit=limit, offset=offset, owner_id=owner_filter
    )
    return OSAssetListResponse(
        items=[OSAssetResponse.model_validate(item) for item in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/assets/{asset_id}",
    response_model=OSAssetResponse,
    status_code=status.HTTP_200_OK,
    summary="Get OS Asset by ID",
    description="Retrieves metadata of an individual operating system asset profile by unique UUID.",
)
def get_asset_by_id(
    asset_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssetResponse:
    """Retrieve an OS asset record by unique identifier with ownership verification."""
    record = os_assessment_service.get_os_asset_by_id(db=db, asset_id=asset_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Asset with ID '{asset_id}' was not found.",
        )
    check_asset_access(record, user)
    return OSAssetResponse.model_validate(record)


# ---------------------------------------------------------------------------
# OS Assessment Lifecycle Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/assessments",
    response_model=OSAssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create OS Assessment Session",
    description="Initializes a new operating system security assessment session in 'pending' status.",
)
def create_assessment(
    payload: OSAssessmentCreateRequest,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssessmentResponse:
    """Initialize a new OS assessment session with validated parameters and ownership scoping."""
    if payload.asset_id:
        target_asset = os_assessment_service.get_os_asset_by_id(db=db, asset_id=payload.asset_id)
        if not target_asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"OS Asset with ID '{payload.asset_id}' was not found.",
            )
        check_asset_access(target_asset, user)

    try:
        record = os_assessment_service.create_os_assessment(
            db=db, payload=payload, owner_id=user.user_id
        )
        return OSAssessmentResponse.model_validate(record)
    except AssetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except UnauthorizedAssessmentError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except UnsupportedOperatingSystemError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "/assessments",
    response_model=OSAssessmentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List OS Assessment Sessions",
    description="Retrieves a paginated list of operating system assessment records ordered by creation timestamp.",
)
def list_assessments(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of initial records to skip"),
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssessmentListResponse:
    """Retrieve paginated assessment sessions scoped to the authenticated caller."""
    owner_filter = None if user.is_admin else user.user_id
    records, total = os_assessment_service.list_os_assessments(
        db=db, limit=limit, offset=offset, owner_id=owner_filter
    )
    return OSAssessmentListResponse(
        items=[OSAssessmentResponse.model_validate(item) for item in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=OSAssessmentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get OS Assessment by ID",
    description="Retrieves full details of an assessment session including target asset, evidence observations, and findings.",
)
def get_assessment_by_id(
    assessment_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssessmentDetailResponse:
    """Retrieve detailed assessment record including supporting evidence and findings."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    evidence_records = os_assessment_service.get_os_evidence_by_assessment_id(db=db, assessment_id=assessment_id)
    finding_records = os_assessment_service.get_os_findings_by_assessment_id(db=db, assessment_id=assessment_id)

    asset_schema = OSAssetResponse.model_validate(record.asset) if record.asset else None

    return OSAssessmentDetailResponse(
        id=record.id,
        asset_id=record.asset_id,
        assessment_type=record.assessment_type,
        status=record.status,
        risk_policy_version=record.risk_policy_version,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        confidence_level=record.confidence_level,
        exploitability_state=record.exploitability_state,
        error_message=record.error_message,
        created_at=record.created_at,
        completed_at=record.completed_at,
        owner_id=record.owner_id,
        asset=asset_schema,
        evidence_items=[OSEvidenceItemResponse.model_validate(e) for e in evidence_records],
        findings=[OSFindingResponse.model_validate(f) for f in finding_records],
    )


@router.post(
    "/assessments/{assessment_id}/assess",
    response_model=OSAssessmentDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Start Authorized Local OS Assessment",
    description=(
        "Executes safe, authorized, local read-only evidence gathering, authoritative advisory matching, "
        "and transparent risk evaluation. Transitions status from 'pending' to 'running' to 'completed'."
    ),
)
def start_assessment(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSAssessmentDetailResponse:
    """Start local read-only assessment execution with authorization and ownership checks."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    if record.status in (OSAssessmentStatus.COMPLETED.value, OSAssessmentStatus.FAILED.value, OSAssessmentStatus.RUNNING.value):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Assessment '{assessment_id}' is already in state '{record.status}' and cannot be started again.",
        )

    # Note: X-Asset-Authorized client header is explicitly ignored to prevent unauthorized remote assessment bypass.
    ctx: dict = {}
    if request.headers.get("x-missing-inventory", "").lower() in ("true", "1", "yes"):
        ctx["missing_inventory"] = True
    if request.headers.get("x-materially-incomplete", "").lower() in ("true", "1", "yes"):
        ctx["materially_incomplete"] = True
    if request.headers.get("x-fail-on-provider-error", "").lower() in ("true", "1", "yes"):
        ctx["fail_on_provider_error"] = True

    try:
        updated_rec, evidence_items, findings, risk_result = os_assessment_service.run_local_os_assessment(
            db=db,
            record=record,
            context=ctx,
        )
    except InvalidStatusTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except UnauthorizedAssessmentError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except UnsupportedOperatingSystemError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except MateriallyIncompleteAssessmentError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment failed due to material incompleteness: {exc}",
        )
    except Exception as exc:
        logger.error("Unexpected error executing assessment '%s': %s", assessment_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Assessment failed during execution pipeline.",
        )

    asset_schema = OSAssetResponse.model_validate(updated_rec.asset) if updated_rec.asset else None

    return OSAssessmentDetailResponse(
        id=updated_rec.id,
        asset_id=updated_rec.asset_id,
        assessment_type=updated_rec.assessment_type,
        status=updated_rec.status,
        risk_policy_version=updated_rec.risk_policy_version,
        risk_score=updated_rec.risk_score,
        risk_level=updated_rec.risk_level,
        confidence_level=updated_rec.confidence_level,
        exploitability_state=updated_rec.exploitability_state,
        error_message=updated_rec.error_message,
        created_at=updated_rec.created_at,
        completed_at=updated_rec.completed_at,
        owner_id=updated_rec.owner_id,
        asset=asset_schema,
        evidence_items=[OSEvidenceItemResponse.model_validate(e) for e in evidence_items],
        findings=[OSFindingResponse.model_validate(f) for f in findings],
    )


# ---------------------------------------------------------------------------
# Findings & Evidence Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/assessments/{assessment_id}/evidence",
    response_model=OSEvidenceListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get OS Assessment Evidence Records",
    description="Retrieves all security evidence observations collected during an operating system assessment.",
)
def get_assessment_evidence(
    assessment_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSEvidenceListResponse:
    """Retrieve collected security evidence observations for an assessment session with access control."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    evidence_records = os_assessment_service.get_os_evidence_by_assessment_id(db=db, assessment_id=assessment_id)
    items = [OSEvidenceItemResponse.model_validate(e) for e in evidence_records]

    observed_count = sum(1 for e in items if e.collection_status == OSEvidenceStatus.OBSERVED)
    absent_count = sum(1 for e in items if e.collection_status == OSEvidenceStatus.ABSENT)
    unavailable_count = sum(1 for e in items if e.collection_status == OSEvidenceStatus.UNAVAILABLE)
    error_count = sum(1 for e in items if e.collection_status == OSEvidenceStatus.ERROR)

    return OSEvidenceListResponse(
        assessment_id=assessment_id,
        items=items,
        total=len(items),
        observed_count=observed_count,
        absent_count=absent_count,
        unavailable_count=unavailable_count,
        error_count=error_count,
    )


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=OSFindingListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get OS Assessment Security Findings",
    description="Retrieves all CVE vulnerabilities and security misconfigurations identified in an assessment session.",
)
def get_assessment_findings(
    assessment_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSFindingListResponse:
    """Retrieve security findings identified during an assessment session with access control."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    finding_records = os_assessment_service.get_os_findings_by_assessment_id(db=db, assessment_id=assessment_id)
    items = [OSFindingResponse.model_validate(f) for f in finding_records]

    critical_count = sum(1 for f in items if f.severity == OSSeverity.CRITICAL)
    high_count = sum(1 for f in items if f.severity == OSSeverity.HIGH)
    medium_count = sum(1 for f in items if f.severity == OSSeverity.MEDIUM)
    low_count = sum(1 for f in items if f.severity == OSSeverity.LOW)
    unrated_count = sum(1 for f in items if f.severity == OSSeverity.UNRATED)

    return OSFindingListResponse(
        assessment_id=assessment_id,
        items=items,
        total=len(items),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        unrated_count=unrated_count,
    )


# ---------------------------------------------------------------------------
# Risk & Remediation Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/assessments/{assessment_id}/risk",
    response_model=OSRiskEvaluationResult,
    status_code=status.HTTP_200_OK,
    summary="Get OS Assessment Risk Score and Explanation",
    description="Calculates and returns explainable risk scores, scoring rationale, subscores, and documented assessment limitations.",
)
def get_assessment_risk(
    assessment_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSRiskEvaluationResult:
    """Retrieve transparent risk evaluation result for an assessment session with access control."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    return os_assessment_service.get_os_risk_evaluation(db=db, assessment_id=assessment_id)


@router.get(
    "/assessments/{assessment_id}/remediation",
    response_model=OSRemediationPlan,
    status_code=status.HTTP_200_OK,
    summary="Get Recommendation-Only Remediation Plan",
    description=(
        "Returns explainable, vendor-aligned hardening guidance for all identified findings. "
        "Recommendations are proposed actions only and have NOT been executed on the host."
    ),
)
def get_assessment_remediation(
    assessment_id: str,
    db: Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_os_assessor),
) -> OSRemediationPlan:
    """Retrieve structured remediation guidance for an assessment session with access control."""
    record = os_assessment_service.get_os_assessment_by_id(db=db, assessment_id=assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OS Assessment with ID '{assessment_id}' was not found.",
        )
    check_assessment_access(record, user)

    return os_assessment_service.get_os_remediation_plan(db=db, assessment_id=assessment_id)
