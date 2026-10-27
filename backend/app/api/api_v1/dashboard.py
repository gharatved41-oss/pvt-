from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any

from ...core.database import get_db
from ...models.models import (
    Asset, Assessment, VulnerabilityFinding, RemediationRecommendation, AuditEvent, User
)
from ..deps import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Main Dashboard"])

@router.get("/metrics")
def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    total_assets = db.query(Asset).count()
    total_assessments = db.query(Assessment).count()
    total_findings = db.query(VulnerabilityFinding).count()

    critical_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "critical").count()
    high_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "high").count()
    medium_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "medium").count()
    low_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "low").count()

    # Detection status breakdown: detected, suspected, confirmed, fixed, unresolved, inconclusive
    status_counts = {}
    for st in ["detected", "suspected", "confirmed", "fixed", "unresolved", "inconclusive"]:
        status_counts[st] = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.detection_status == st).count()

    # Remediation status breakdown
    rem_counts = {}
    for rst in ["recommended", "awaiting_approval", "approved", "applied_in_twin", "resolved", "failed"]:
        rem_counts[rst] = db.query(RemediationRecommendation).filter(RemediationRecommendation.status == rst).count()

    # Average asset risk score
    avg_risk = db.query(func.avg(VulnerabilityFinding.risk_score)).scalar() or 0.0

    # Severity distribution chart data
    severity_distribution = [
        {"name": "Critical", "count": critical_findings, "color": "#ef4444"},
        {"name": "High", "count": high_findings, "color": "#f97316"},
        {"name": "Medium", "count": medium_findings, "color": "#eab308"},
        {"name": "Low", "count": low_findings, "color": "#3b82f6"},
    ]

    # Status distribution chart data
    status_distribution = [
        {"name": "Confirmed", "count": status_counts["confirmed"], "color": "#10b981"},
        {"name": "Detected", "count": status_counts["detected"], "color": "#06b6d4"},
        {"name": "Fixed", "count": status_counts["fixed"], "color": "#22c55e"},
        {"name": "Suspected", "count": status_counts["suspected"], "color": "#f59e0b"},
        {"name": "Inconclusive", "count": status_counts["inconclusive"], "color": "#6b7280"},
    ]

    # Recent assessments
    recent_assessments_raw = db.query(Assessment).order_by(Assessment.started_at.desc()).limit(5).all()
    recent_assessments = [
        {
            "id": a.id,
            "title": a.title,
            "asset_id": a.asset_id,
            "asset_name": a.asset.name if a.asset else "Unknown",
            "findings_count": a.findings_count,
            "average_risk_score": a.average_risk_score,
            "status": a.status,
            "started_at": a.started_at.isoformat() if a.started_at else None
        }
        for a in recent_assessments_raw
    ]

    # Recent findings
    recent_findings_raw = db.query(VulnerabilityFinding).order_by(VulnerabilityFinding.created_at.desc()).limit(5).all()
    recent_findings = [
        {
            "id": f.id,
            "cve_id": f.cve_id,
            "title": f.title,
            "component": f.affected_component,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "detection_status": f.detection_status,
            "priority": f.recommended_priority
        }
        for f in recent_findings_raw
    ]

    # Recent audit events
    recent_audits_raw = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(6).all()
    recent_audits = [
        {
            "id": ev.id,
            "event_type": ev.event_type,
            "action": ev.action,
            "user_email": ev.user_email,
            "created_at": ev.created_at.isoformat()
        }
        for ev in recent_audits_raw
    ]

    return {
        "total_assets": total_assets,
        "total_assessments": total_assessments,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "status_breakdown": status_counts,
        "remediation_breakdown": rem_counts,
        "average_risk_score": round(avg_risk, 1),
        "severity_distribution": severity_distribution,
        "status_distribution": status_distribution,
        "recent_assessments": recent_assessments,
        "recent_findings": recent_findings,
        "recent_audit_events": recent_audits,
        "recent_audits": recent_audits
    }
