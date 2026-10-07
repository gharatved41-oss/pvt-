"""History API Endpoint for AutoSecTwin.
Provides searchable, filterable, and paginated records of stored security memory.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_
from typing import Optional, List

from backend.app.db.session import get_db
from backend.app.models.database import Analysis, AnalysisComparison
from backend.app.schemas.history import HistoryListResponse, HistoryItemSummary
from backend.app.services.security_memory import compute_freshness

router = APIRouter()


@router.get("/history", response_model=HistoryListResponse)
def get_analysis_history(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(15, ge=1, le=100, description="Items per page"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level: LOW, GUARDED, SUSPICIOUS, HIGH"),
    search: Optional[str] = Query(None, description="Search term in URL, domain, or analysis_id"),
    sort: Optional[str] = Query("newest", description="Sort order: newest, oldest, highest_risk, lowest_risk"),
    db: Session = Depends(get_db)
):
    """
    Returns stored security analyses matching filters and search queries.
    """
    query = db.query(Analysis)

    # Filter by verdict
    if verdict and verdict.upper() != "ALL":
        query = query.filter(Analysis.verdict == verdict.upper())

    # Filter by risk level
    if risk_level and risk_level.upper() != "ALL":
        query = query.filter(Analysis.risk_level == risk_level.upper())

    # Text search across URL, domain, or analysis ID
    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(
            or_(
                Analysis.submitted_url.ilike(term),
                Analysis.normalized_url.ilike(term),
                Analysis.domain.ilike(term),
                Analysis.analysis_id.ilike(term)
            )
        )

    # Sort ordering
    if sort == "oldest":
        query = query.order_by(asc(Analysis.created_at))
    elif sort == "highest_risk":
        query = query.order_by(desc(Analysis.risk_score), desc(Analysis.created_at))
    elif sort == "lowest_risk":
        query = query.order_by(asc(Analysis.risk_score), desc(Analysis.created_at))
    else:  # newest
        query = query.order_by(desc(Analysis.created_at))

    total = query.count()
    offset = (page - 1) * limit
    results = query.offset(offset).limit(limit).all()

    items = []
    for a in results:
        # Check comparison delta
        comp = db.query(AnalysisComparison).filter(AnalysisComparison.current_analysis_id == a.analysis_id).first()
        score_delta = comp.risk_delta if comp else None

        # Count total times this indicator has been analyzed
        times_count = db.query(Analysis).filter(
            or_(
                Analysis.normalized_url == a.normalized_url,
                (Analysis.domain == a.domain) if a.domain else False
            )
        ).count()

        items.append(HistoryItemSummary(
            analysis_id=a.analysis_id,
            indicator_type=a.indicator_type,
            submitted_url=a.submitted_url,
            normalized_url=a.normalized_url,
            domain=a.domain,
            verdict=a.verdict,
            risk_score=a.risk_score,
            risk_level=a.risk_level,
            confidence=a.confidence,
            freshness=compute_freshness(a.created_at),
            score_delta=score_delta,
            times_analyzed=times_count,
            is_demo=a.is_demo,
            created_at=a.created_at
        ))

    return HistoryListResponse(
        total=total,
        page=page,
        limit=limit,
        items=items
    )
