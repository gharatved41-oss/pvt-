"""Pydantic schemas for History and Indicator Security Memory views.
"""
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel


class HistoryItemSummary(BaseModel):
    analysis_id: str
    indicator_type: str
    submitted_url: str
    normalized_url: str
    domain: Optional[str] = None
    verdict: str
    risk_score: int
    risk_level: str
    confidence: float
    freshness: str
    score_delta: Optional[int] = None
    times_analyzed: int
    is_demo: bool
    created_at: datetime


class HistoryListResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[HistoryItemSummary]


class IndicatorTimelinePoint(BaseModel):
    analysis_id: str
    score: int
    verdict: str
    risk_level: str
    evidence_count: int
    created_at: datetime


class IndicatorDetailResponse(BaseModel):
    indicator: str
    indicator_type: str
    first_seen: datetime
    last_checked: datetime
    times_analyzed: int
    current_verdict: str
    current_risk_score: int
    current_risk_level: str
    trend: str  # INCREASING, DECREASING, STABLE, FIRST_SEEN
    timeline: List[IndicatorTimelinePoint]
