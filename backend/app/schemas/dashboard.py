"""Pydantic schemas for the AutoSecTwin Security Operations Dashboard.
Guarantees all statistics originate from real stored analyses.
"""
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel


class DomainCount(BaseModel):
    domain: str
    count: int
    highest_risk: int


class VerdictDistribution(BaseModel):
    verdict: str
    count: int
    percentage: float


class RiskTimelineBucket(BaseModel):
    date: str
    count: int
    average_risk: float


class DashboardMetrics(BaseModel):
    total_analyses: int
    high_risk_count: int
    suspicious_count: int
    low_risk_count: int
    unknown_count: int
    average_risk_score: float = 0.0
    changed_since_previous: int
    risk_trend: str  # INCREASING, DECREASING, STABLE, INSUFFICIENT_DATA
    top_domains: List[DomainCount]
    verdict_distribution: List[VerdictDistribution]
    timeline_activity: List[RiskTimelineBucket]
    demo_mode_active: bool
    latest_analyses: List[Dict] = []
