"""AutoSecTwin Security Memory & Historical Delta Engine.
Maintains persistent, immutable records of all security analyses.
Calculates historical deltas (risk score change, verdict change, timeline trends)
across repeat queries of URLs, domains, and cryptographic hashes.
"""
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, or_

from backend.app.models.database import (
    Analysis, Indicator, Evidence, ProviderResult,
    Recommendation, AnalysisComparison, SafePathRecommendation, SystemEvent
)
from backend.app.schemas.analysis import (
    HistoricalComparison, SafePathAlternative, EvidenceItem,
    RecommendationItem, RiskFactor
)
from backend.app.core.logging import logger
from backend.app.config import settings


def compute_freshness(analyzed_at: datetime) -> str:
    """Computes freshness state based on elapsed time."""
    if not analyzed_at:
        return "UNKNOWN"
    if analyzed_at.tzinfo is None:
        analyzed_at = analyzed_at.replace(tzinfo=timezone.utc)
    delta_seconds = (datetime.now(timezone.utc) - analyzed_at).total_seconds()
    if delta_seconds < settings.FRESHNESS_FRESH_SECONDS:
        return "FRESH"
    elif delta_seconds < settings.FRESHNESS_RECENT_SECONDS:
        return "RECENT"
    return "STALE"


class SecurityMemoryService:
    """
    Manages immutable security memory persistence, delta calculation,
    and historical timeline querying.
    """

    def find_previous_analyses(
        self,
        db: Session,
        normalized_url: str,
        domain: Optional[str] = None
    ) -> List[Analysis]:
        """Finds prior historical analyses for this exact normalized URL or domain."""
        query = db.query(Analysis).filter(
            or_(
                Analysis.normalized_url == normalized_url,
                (Analysis.domain == domain) if domain else False
            )
        ).order_by(desc(Analysis.created_at))
        return query.all()

    def calculate_delta(
        self,
        current_score: int,
        current_verdict: str,
        previous: Optional[Analysis],
        total_prior_count: int
    ) -> HistoricalComparison:
        """Calculates delta between current result and previous analysis."""
        if not previous:
            return HistoricalComparison(
                has_history=False,
                current_risk_score=current_score,
                score_delta=0,
                verdict_changed=False,
                status_summary="First time this indicator has been analyzed.",
                times_analyzed=1
            )

        score_delta = current_score - previous.risk_score
        verdict_changed = current_verdict != previous.verdict

        if score_delta > 0:
            status_summary = f"Risk increased by +{score_delta} points since previous analysis."
        elif score_delta < 0:
            status_summary = f"Risk decreased by {abs(score_delta)} points since previous analysis."
        else:
            status_summary = "Risk score unchanged since previous analysis."

        if verdict_changed:
            status_summary += f" Verdict shifted from {previous.verdict} to {current_verdict}."

        return HistoricalComparison(
            has_history=True,
            previous_analysis_id=previous.analysis_id,
            previous_analyzed_at=previous.created_at,
            previous_verdict=previous.verdict,
            previous_risk_score=previous.risk_score,
            current_risk_score=current_score,
            score_delta=score_delta,
            verdict_changed=verdict_changed,
            status_summary=status_summary,
            times_analyzed=total_prior_count + 1
        )

    def persist_analysis(
        self,
        db: Session,
        analysis_id: str,
        indicator_type: str,
        submitted_url: str,
        normalized_url: str,
        domain: Optional[str],
        hostname: Optional[str],
        scheme: Optional[str],
        path: Optional[str],
        query_present: bool,
        risk_score: int,
        risk_level: str,
        confidence: float,
        exploitability_level: str,
        verdict: str,
        summary: str,
        duration_ms: int,
        evidence_items: List[EvidenceItem],
        provider_results: List[Any],
        recommendations: List[RecommendationItem],
        safepath: Optional[SafePathAlternative],
        historical: HistoricalComparison,
        is_demo: bool = False
    ) -> Analysis:
        """Persists the full analysis record into the database along with relationships."""
        # 1. Create main Analysis record
        db_analysis = Analysis(
            analysis_id=analysis_id,
            indicator_type=indicator_type,
            submitted_url=submitted_url,
            normalized_url=normalized_url,
            domain=domain,
            hostname=hostname,
            scheme=scheme,
            path=path,
            query_present=query_present,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            exploitability_level=exploitability_level,
            verdict=verdict,
            status="COMPLETED",
            summary=summary,
            duration_ms=duration_ms,
            is_demo=is_demo
        )
        db.add(db_analysis)

        # 2. Add Indicator records
        if domain:
            db.add(Indicator(
                analysis_id=analysis_id,
                indicator_type="DOMAIN",
                indicator_value=domain,
                normalized_value=domain.lower()
            ))
        db.add(Indicator(
            analysis_id=analysis_id,
            indicator_type=indicator_type,
            indicator_value=submitted_url,
            normalized_value=normalized_url
        ))

        # 3. Add Evidence
        for ev in evidence_items:
            db.add(Evidence(
                analysis_id=analysis_id,
                category=ev.category,
                title=ev.title,
                description=ev.description,
                source=ev.source,
                severity=ev.severity,
                impact_score=ev.impact_score,
                observed_at=ev.observed_at
            ))

        # 4. Add Provider Results
        for p in provider_results:
            db.add(ProviderResult(
                analysis_id=analysis_id,
                provider_name=getattr(p, "provider_name", "Unknown"),
                status=getattr(p, "status", "AVAILABLE"),
                classification=getattr(p, "classification", "UNKNOWN"),
                confidence=getattr(p, "confidence", 0.5),
                raw_reference=getattr(p, "raw_reference", None),
                observed_at=getattr(p, "observed_at", datetime.now(timezone.utc))
            ))

        # 5. Add Recommendations
        for rec in recommendations:
            db.add(Recommendation(
                analysis_id=analysis_id,
                priority=rec.priority,
                title=rec.title,
                reason=rec.reason,
                action=rec.action,
                effort=rec.effort,
                coverage=rec.coverage
            ))

        # 6. Add SafePath if present
        if safepath:
            db.add(SafePathRecommendation(
                analysis_id=analysis_id,
                software_name=safepath.software_name,
                original_url=safepath.original_url,
                original_risk=safepath.original_risk,
                recommended_name=safepath.recommended_name,
                recommended_url=safepath.recommended_url,
                recommended_domain=safepath.recommended_domain,
                recommended_risk=safepath.recommended_risk,
                trust_level=safepath.trust_level,
                comparison_reason=safepath.comparison_reason,
                disclaimer=safepath.disclaimer
            ))

        # 7. Add AnalysisComparison if previous existed
        if historical.has_history and historical.previous_analysis_id:
            db.add(AnalysisComparison(
                current_analysis_id=analysis_id,
                previous_analysis_id=historical.previous_analysis_id,
                risk_delta=historical.score_delta,
                confidence_delta=0.0,
                verdict_changed=historical.verdict_changed,
                previous_verdict=historical.previous_verdict,
                current_verdict=verdict,
                previous_risk_score=historical.previous_risk_score or 0,
                current_risk_score=risk_score,
                summary=historical.status_summary
            ))

        # 8. Record System Audit Event
        db.add(SystemEvent(
            event_type="URL_ANALYSIS_COMPLETED",
            message=f"Analyzed {normalized_url} — verdict: {verdict}, score: {risk_score}",
            indicator=normalized_url,
            analysis_id=analysis_id
        ))

        db.commit()
        db.refresh(db_analysis)
        return db_analysis


security_memory = SecurityMemoryService()
