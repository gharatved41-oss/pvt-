"""Cryptographic Hash Analyzer for AutoSecTwin.
Analyzes MD5, SHA-1, and SHA-256 hashes against threat intelligence and security memory.
Does NOT download or execute any untrusted binary on the host machine.
"""
import time
import uuid
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.app.utils.hashing import identify_hash_type
from backend.app.providers.reputation_provider import BuiltinReputationProvider
from backend.app.providers.threat_intel_provider import ExternalThreatIntelProvider
from backend.app.services.security_memory import security_memory
from backend.app.services.explanation_engine import explanation_engine
from backend.app.schemas.analysis import (
    AnalysisResponse, RiskFactor, EvidenceItem, ExploitabilityAssessment,
    RecommendationItem
)


builtin_provider = BuiltinReputationProvider()
external_provider = ExternalThreatIntelProvider()


class HashAnalyzerService:
    """Coordinates cryptographic hash intelligence lookup safely."""

    async def analyze(
        self,
        db: Session,
        raw_hash: str,
        is_demo: bool = False
    ) -> AnalysisResponse:
        start_time = time.perf_counter()

        is_valid, hash_type, clean_hash = identify_hash_type(raw_hash)
        if not is_valid:
            raise ValueError(f"Invalid cryptographic hash format: '{raw_hash}'. Expected 32-char MD5, 40-char SHA-1, or 64-char SHA-256 hex string.")

        # Query Security Memory
        previous_records = security_memory.find_previous_analyses(db, clean_hash)
        most_recent_prev = previous_records[0] if previous_records else None

        # Query Threat Intel Providers
        provider_results = []
        p_builtin = await builtin_provider.analyze_hash(clean_hash)
        provider_results.append(p_builtin)
        p_ext = await external_provider.analyze_hash(clean_hash)
        provider_results.append(p_ext)

        # Risk calculation based on provider detections
        score = 0
        factors: List[RiskFactor] = []
        evidence_items: List[EvidenceItem] = []
        now = datetime.now(timezone.utc)

        has_malicious = any(p.classification == "MALICIOUS" for p in provider_results)
        has_suspicious = any(p.classification == "SUSPICIOUS" for p in provider_results)
        has_clean = any(p.classification == "CLEAN" for p in provider_results)

        if has_malicious:
            score = 88
            verdict = "MALICIOUS"
            risk_level = "HIGH"
            confidence = 0.95
            factors.append(RiskFactor(
                name="Signature Threat Match",
                impact=88,
                severity="CRITICAL",
                evidence=f"{hash_type} signature flagged by threat intelligence signatures as malicious."
            ))
            for p in provider_results:
                if p.classification == "MALICIOUS":
                    evidence_items.append(EvidenceItem(
                        category="threat_intel",
                        title=f"Malicious Signature Match ({p.provider_name})",
                        description=p.raw_reference or "Known malicious sample hash detected",
                        source=p.provider_name,
                        severity="CRITICAL",
                        impact_score=88,
                        observed_at=p.observed_at
                    ))
        elif has_suspicious:
            score = 60
            verdict = "SUSPICIOUS"
            risk_level = "SUSPICIOUS"
            confidence = 0.75
            factors.append(RiskFactor(
                name="Anomalous Hash Telemetry",
                impact=60,
                severity="HIGH",
                evidence="Heuristic detections present for this cryptographic sample."
            ))
        elif has_clean:
            score = 5
            verdict = "SAFE"
            risk_level = "LOW"
            confidence = 0.85
        else:
            score = 0
            verdict = "UNKNOWN"
            risk_level = "LOW"
            confidence = 0.30
            evidence_items.append(EvidenceItem(
                category="threat_intel",
                title="Hash Not Observed in Threat Catalogs",
                description="Hash was not matched in available signature repositories.",
                source="Threat Feed",
                severity="INFO",
                impact_score=0,
                observed_at=now
            ))

        exploitability = ExploitabilityAssessment(
            level="HIGH" if verdict == "MALICIOUS" else ("UNKNOWN" if verdict == "UNKNOWN" else "LOW"),
            reason="Executable payload identified in global threat telemetry." if verdict == "MALICIOUS" else "No active weaponization established from hash lookup alone.",
            confidence=confidence,
            factors=[f"Evaluated via {hash_type} cryptographic digest"]
        )

        recommendations = [
            RecommendationItem(
                priority="CRITICAL" if verdict == "MALICIOUS" else "INFO",
                title=f"Add {hash_type} hash to endpoint protection blocklist" if verdict == "MALICIOUS" else "Maintain file monitoring",
                reason="Hash identified as malicious binary in security intelligence." if verdict == "MALICIOUS" else "Standard baseline.",
                action=f"Block execution of binary with digest '{clean_hash}' on enterprise endpoints.",
                effort="LOW",
                coverage="Prevents workstation execution of matched binary."
            )
        ]

        summary, key_findings, limitations = explanation_engine.generate_explanation(
            clean_hash, verdict, score, risk_level, confidence,
            factors, evidence_items, exploitability
        )

        historical = security_memory.calculate_delta(
            score, verdict, most_recent_prev, len(previous_records)
        )

        analysis_id = f"AST-HASH-{uuid.uuid4().hex[:6].upper()}"
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        persisted = security_memory.persist_analysis(
            db=db,
            analysis_id=analysis_id,
            indicator_type="HASH",
            submitted_url=clean_hash,
            normalized_url=clean_hash,
            domain=None,
            hostname=None,
            scheme=None,
            path=None,
            query_present=False,
            risk_score=score,
            risk_level=risk_level,
            confidence=confidence,
            exploitability_level=exploitability.level,
            verdict=verdict,
            summary=summary,
            duration_ms=duration_ms,
            evidence_items=evidence_items,
            provider_results=provider_results,
            recommendations=recommendations,
            safepath=None,
            historical=historical,
            is_demo=is_demo
        )

        return AnalysisResponse(
            analysis_id=analysis_id,
            status="completed",
            indicator_type="HASH",
            submitted_url=clean_hash,
            normalized_url=clean_hash,
            domain=None,
            hostname=None,
            verdict=verdict,
            risk_score=score,
            risk_level=risk_level,
            confidence=confidence,
            freshness="FRESH",
            exploitability=exploitability,
            summary=summary,
            key_findings=key_findings,
            risk_factors=factors,
            evidence=evidence_items,
            recommendations=recommendations,
            safepath=None,
            historical=historical,
            limitations=limitations,
            created_at=persisted.created_at,
            duration_ms=duration_ms,
            is_demo=is_demo
        )


hash_analyzer = HashAnalyzerService()
