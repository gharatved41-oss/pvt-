"""Dashboard API for AutoSecTwin.
Computes real-time telemetry from persistent database analyses.
Strictly adheres to Section 6: No fabricated stats; empty state returned when no analyses exist.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timezone, timedelta
from typing import List, Dict

from backend.app.db.session import get_db
from backend.app.models.database import Analysis, AnalysisComparison
from backend.app.schemas.dashboard import (
    DashboardMetrics, DomainCount, VerdictDistribution, RiskTimelineBucket
)
from backend.app.db.seed_data import seed_demo_data
from backend.app.core.logging import logger

router = APIRouter()


@router.get("/dashboard", response_model=DashboardMetrics)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """
    Computes all dashboard metrics directly from the database.
    """
    total_analyses = db.query(Analysis).count()

    if total_analyses == 0:
        return DashboardMetrics(
            total_analyses=0,
            high_risk_count=0,
            suspicious_count=0,
            low_risk_count=0,
            unknown_count=0,
            changed_since_previous=0,
            risk_trend="INSUFFICIENT_DATA",
            top_domains=[],
            verdict_distribution=[],
            timeline_activity=[],
            demo_mode_active=False,
            latest_analyses=[]
        )

    # Risk counts
    high_risk_count = db.query(Analysis).filter(Analysis.risk_score >= 75).count()
    suspicious_count = db.query(Analysis).filter(Analysis.risk_score >= 25, Analysis.risk_score < 75).count()
    low_risk_count = db.query(Analysis).filter(Analysis.verdict == "SAFE").count()
    unknown_count = db.query(Analysis).filter(Analysis.verdict == "UNKNOWN").count()

    # Average risk score across all stored analyses
    avg_score_raw = db.query(func.avg(Analysis.risk_score)).scalar()
    average_risk_score = round(float(avg_score_raw), 1) if avg_score_raw is not None else 0.0

    # Changed since previous analysis
    changed_since_previous = db.query(AnalysisComparison).filter(
        (AnalysisComparison.risk_delta != 0) | (AnalysisComparison.verdict_changed == True)
    ).count()

    # Check if demo mode records exist
    demo_count = db.query(Analysis).filter(Analysis.is_demo == True).count()
    demo_mode_active = demo_count > 0

    # Top analyzed domains
    top_domain_rows = (
        db.query(
            Analysis.domain,
            func.count(Analysis.id).label("total_count"),
            func.max(Analysis.risk_score).label("max_risk")
        )
        .filter(Analysis.domain != None)
        .group_by(Analysis.domain)
        .order_by(desc("total_count"))
        .limit(6)
        .all()
    )
    top_domains = [
        DomainCount(domain=row[0], count=row[1], highest_risk=row[2])
        for row in top_domain_rows
    ]

    # Verdict distribution
    verdict_rows = (
        db.query(Analysis.verdict, func.count(Analysis.id))
        .group_by(Analysis.verdict)
        .all()
    )
    verdict_distribution = [
        VerdictDistribution(
            verdict=v[0],
            count=v[1],
            percentage=round((v[1] / total_analyses) * 100, 1)
        )
        for v in verdict_rows
    ]

    # Timeline activity (last 7 days)
    now = datetime.now(timezone.utc)
    timeline_activity: List[RiskTimelineBucket] = []
    for day_offset in range(6, -1, -1):
        day_date = (now - timedelta(days=day_offset)).strftime("%Y-%m-%d")
        day_analyses = db.query(Analysis).filter(
            func.strftime("%Y-%m-%d", Analysis.created_at) == day_date
        ).all()
        count = len(day_analyses)
        avg_risk = round(sum(a.risk_score for a in day_analyses) / count, 1) if count > 0 else 0.0
        timeline_activity.append(RiskTimelineBucket(
            date=day_date,
            count=count,
            average_risk=avg_risk
        ))

    # Overall risk trend based on latest 5 analyses vs previous 5
    recent_5 = db.query(Analysis).order_by(desc(Analysis.created_at)).limit(5).all()
    if len(recent_5) >= 2:
        latest_avg = sum(a.risk_score for a in recent_5[:2]) / 2
        older_avg = sum(a.risk_score for a in recent_5[-2:]) / 2
        if latest_avg > older_avg + 5:
            risk_trend = "INCREASING"
        elif latest_avg < older_avg - 5:
            risk_trend = "DECREASING"
        else:
            risk_trend = "STABLE"
    else:
        risk_trend = "STABLE"

    # Latest 5 analyses for the dashboard table
    latest_analyses = [
        {
            "analysis_id": a.analysis_id,
            "submitted_url": a.submitted_url,
            "domain": a.domain,
            "verdict": a.verdict,
            "risk_score": a.risk_score,
            "risk_level": a.risk_level,
            "is_demo": a.is_demo,
            "created_at": a.created_at.isoformat()
        }
        for a in recent_5
    ]

    return DashboardMetrics(
        total_analyses=total_analyses,
        high_risk_count=high_risk_count,
        suspicious_count=suspicious_count,
        low_risk_count=low_risk_count,
        unknown_count=unknown_count,
        average_risk_score=average_risk_score,
        changed_since_previous=changed_since_previous,
        risk_trend=risk_trend,
        top_domains=top_domains,
        verdict_distribution=verdict_distribution,
        timeline_activity=timeline_activity,
        demo_mode_active=demo_mode_active,
        latest_analyses=latest_analyses
    )


@router.post("/dashboard/seed-demo")
def trigger_seed_demo_data(db: Session = Depends(get_db)):
    """Seeds controlled presentation demonstration scenarios."""
    seed_demo_data()
    return {"status": "success", "message": "Development demo data seeded successfully."}


@router.post("/dashboard/clear-demo")
def clear_demo_data(db: Session = Depends(get_db)):
    """Purges demo records so user has a clean database for production scans."""
    db.query(Analysis).filter(Analysis.is_demo == True).delete()
    db.commit()
    return {"status": "success", "message": "Demo records removed. Database contains only organic analyses."}
