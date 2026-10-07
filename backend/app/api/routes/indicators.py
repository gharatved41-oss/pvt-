"""Indicator Security Memory Detail API.
Returns full timeline and evolution history for a specific domain or indicator.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_

from backend.app.db.session import get_db
from backend.app.models.database import Analysis
from backend.app.schemas.history import IndicatorDetailResponse, IndicatorTimelinePoint

router = APIRouter()


@router.get("/indicators/{indicator:path}", response_model=IndicatorDetailResponse)
def get_indicator_memory(
    indicator: str,
    db: Session = Depends(get_db)
):
    """
    Returns security memory evolution and risk timeline for an indicator/domain.
    """
    clean_target = indicator.strip().lower()
    analyses = db.query(Analysis).filter(
        or_(
            Analysis.domain == clean_target,
            Analysis.hostname == clean_target,
            Analysis.normalized_url.ilike(f"%{clean_target}%"),
            Analysis.submitted_url.ilike(f"%{clean_target}%")
        )
    ).order_by(asc(Analysis.created_at)).all()

    if not analyses:
        raise HTTPException(
            status_code=404,
            detail=f"No security memory found for indicator '{indicator}'."
        )

    first_analysis = analyses[0]
    latest_analysis = analyses[-1]

    # Calculate trend
    if len(analyses) == 1:
        trend = "FIRST_SEEN"
    else:
        first_score = first_analysis.risk_score
        last_score = latest_analysis.risk_score
        if last_score > first_score + 5:
            trend = "INCREASING"
        elif last_score < first_score - 5:
            trend = "DECREASING"
        else:
            trend = "STABLE"

    timeline_points = [
        IndicatorTimelinePoint(
            analysis_id=a.analysis_id,
            score=a.risk_score,
            verdict=a.verdict,
            risk_level=a.risk_level,
            evidence_count=len(a.evidence_items),
            created_at=a.created_at
        )
        for a in analyses
    ]

    return IndicatorDetailResponse(
        indicator=indicator,
        indicator_type=latest_analysis.indicator_type,
        first_seen=first_analysis.created_at,
        last_checked=latest_analysis.created_at,
        times_analyzed=len(analyses),
        current_verdict=latest_analysis.verdict,
        current_risk_score=latest_analysis.risk_score,
        current_risk_level=latest_analysis.risk_level,
        trend=trend,
        timeline=timeline_points
    )
