"""API endpoints for target URL submission, analysis history, passive evidence collection, and risk evaluation."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.analysis import (
    AnalysisCreateRequest,
    AnalysisDetailResponse,
    AnalysisListResponse,
    AnalysisResponse,
)
from app.schemas.evidence import (
    EvidenceCollectionStatus,
    EvidenceItemResponse,
    EvidenceListResponse,
)
from app.services import analysis_service
from app.services.analysis_service import InvalidStatusTransitionError

from app.services.risk_engine import DeterministicPassiveRiskEngine

router = APIRouter()


@router.post(
    "",
    response_model=AnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit Target URL for Analysis",
    description=(
        "Accepts a target URL with an HTTP or HTTPS scheme, validates syntax according "
        "to defensive cybersecurity rules, and records an analysis entry in 'pending' status."
    ),
    tags=["Analyses"],
)
def create_analysis(
    payload: AnalysisCreateRequest,
    db: Session = Depends(get_db),
) -> AnalysisResponse:
    """Submit a validated target URL and persist a new analysis record."""
    record = analysis_service.create_analysis(db=db, url=payload.url)
    return AnalysisResponse.model_validate(record)


@router.get(
    "",
    response_model=AnalysisListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Analysis Records",
    description="Retrieves a paginated list of recorded target analyses, ordered by creation time descending.",
    tags=["Analyses"],
)
def list_analyses(
    limit: int = Query(default=20, ge=1, le=100, description="Maximum number of records to return (1-100)"),
    offset: int = Query(default=0, ge=0, description="Number of initial records to skip"),
    db: Session = Depends(get_db),
) -> AnalysisListResponse:
    """Retrieve paginated analysis history records."""
    records, total = analysis_service.list_analyses(db=db, limit=limit, offset=offset)
    return AnalysisListResponse(
        items=[AnalysisResponse.model_validate(item) for item in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Analysis Record by ID",
    description="Retrieves the details and current status of an individual analysis record by its UUID, including evidence and risk assessment when available.",
    tags=["Analyses"],
)
def get_analysis_by_id(
    analysis_id: str,
    db: Session = Depends(get_db),
) -> AnalysisDetailResponse:
    """Retrieve a single analysis record by unique UUID."""
    record = analysis_service.get_analysis_by_id(db=db, analysis_id=analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' was not found.",
        )

    evidence_models = []
    risk_assessment = None
    if record.status == "completed":
        items = analysis_service.get_evidence_by_analysis_id(db=db, analysis_id=analysis_id)
        evidence_models = [EvidenceItemResponse.model_validate(e) for e in items]
        risk_assessment = DeterministicPassiveRiskEngine().evaluate(items)

    return AnalysisDetailResponse(
        id=record.id,
        url=record.url,
        status=record.status,
        created_at=record.created_at,
        error_message=record.error_message,
        evidence_items=evidence_models,
        risk_assessment=risk_assessment,
    )


@router.post(
    "/{analysis_id}/analyze",
    response_model=AnalysisDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger Passive Analysis",
    description=(
        "Executes safe, local passive evidence collection and deterministic risk evaluation "
        "on an existing analysis record. Transitions lifecycle from 'pending' to 'running' to 'completed'."
    ),
    tags=["Analyses", "Evidence"],
)
def trigger_analysis(
    analysis_id: str,
    db: Session = Depends(get_db),
) -> AnalysisDetailResponse:
    """Trigger passive evidence collection and deterministic risk scoring."""
    record = analysis_service.get_analysis_by_id(db=db, analysis_id=analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' was not found.",
        )

    try:
        updated_record, evidence_items, risk_assessment = analysis_service.run_passive_analysis(
            db=db, record=record
        )
    except InvalidStatusTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )

    return AnalysisDetailResponse(
        id=updated_record.id,
        url=updated_record.url,
        status=updated_record.status,
        created_at=updated_record.created_at,
        error_message=updated_record.error_message,
        evidence_items=[EvidenceItemResponse.model_validate(e) for e in evidence_items],
        risk_assessment=risk_assessment,
    )


@router.get(
    "/{analysis_id}/evidence",
    response_model=EvidenceListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Analysis Evidence Records",
    description="Retrieves all security evidence observations collected for a specific analysis record.",
    tags=["Evidence"],
)
def get_analysis_evidence(
    analysis_id: str,
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    """Retrieve all evidence observations collected for an analysis."""
    record = analysis_service.get_analysis_by_id(db=db, analysis_id=analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record with ID '{analysis_id}' was not found.",
        )

    items = analysis_service.get_evidence_by_analysis_id(db=db, analysis_id=analysis_id)
    evidence_models = [EvidenceItemResponse.model_validate(item) for item in items]

    observed_count = sum(1 for e in evidence_models if e.collection_status == EvidenceCollectionStatus.OBSERVED)
    absent_count = sum(1 for e in evidence_models if e.collection_status == EvidenceCollectionStatus.ABSENT)
    error_count = sum(1 for e in evidence_models if e.collection_status == EvidenceCollectionStatus.ERROR)

    return EvidenceListResponse(
        analysis_id=analysis_id,
        items=evidence_models,
        total=len(evidence_models),
        observed_count=observed_count,
        absent_count=absent_count,
        error_count=error_count,
    )
