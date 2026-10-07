"""URL Analysis Coordinator for AutoSecTwin.
Safely analyzes indicators without executing untrusted content.
Orchestrates: Normalization -> SSRF Check -> Security Memory -> Intelligence Adapters
            -> Risk Engine -> SafePath -> Recommendations -> Explanation -> Persistence.
"""
import time
import uuid
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.app.utils.url_normalizer import normalize_url, URLValidationError
from backend.app.utils.ssrf_guard import validate_ssrf_safety, SSRFSecurityException
from backend.app.providers.reputation_provider import BuiltinReputationProvider
from backend.app.providers.threat_intel_provider import ExternalThreatIntelProvider, AbuseIPDBProvider
from backend.app.services.risk_engine import RiskEngine
from backend.app.services.safepath import safepath_engine
from backend.app.services.recommendation_engine import recommendation_engine
from backend.app.services.explanation_engine import explanation_engine
from backend.app.services.security_memory import security_memory, compute_freshness
from backend.app.services.enrichment_service import enrichment_service
from backend.app.services.attack_path_engine import attack_path_engine
from backend.app.schemas.analysis import AnalysisResponse, EvidenceItem, ExploitabilityAssessment
from backend.app.core.logging import logger


builtin_provider = BuiltinReputationProvider()
external_provider = ExternalThreatIntelProvider()
abuseipdb_provider = AbuseIPDBProvider()
risk_engine = RiskEngine()


class URLAnalyzerService:
    """
    Coordinates safe, isolated analysis of submitted URLs.
    """

    async def analyze(
        self,
        db: Session,
        raw_url: str,
        force_refresh: bool = False,
        is_demo: bool = False
    ) -> AnalysisResponse:
        start_time = time.perf_counter()

        # Step 1: Normalize and extract lexical indicators
        parsed_indicators = normalize_url(raw_url)
        normalized_url = parsed_indicators["normalized_url"]
        hostname = parsed_indicators["hostname"]
        domain = parsed_indicators["domain"]

        # Step 2: SSRF Safety Verification
        is_ssrf_safe, ssrf_reason = validate_ssrf_safety(hostname)
        if not is_ssrf_safe:
            raise SSRFSecurityException(f"SSRF Protection triggered: {ssrf_reason}")

        # Step 3: Query Security Memory for previous snapshots
        previous_records = security_memory.find_previous_analyses(db, normalized_url, domain)
        most_recent_prev = previous_records[0] if previous_records else None

        # Step 4: Collect Threat Intelligence through Adapters
        provider_results = []
        # Built-in native reputation engine
        res_builtin = await builtin_provider.analyze_url(normalized_url, parsed_indicators)
        provider_results.append(res_builtin)

        # External provider (VirusTotal etc. - gracefully handles unconfigured state)
        res_ext = await external_provider.analyze_url(normalized_url, parsed_indicators)
        provider_results.append(res_ext)

        # AbuseIPDB Live Threat Intelligence Adapter
        res_abuse = await abuseipdb_provider.analyze_url(normalized_url, parsed_indicators)
        provider_results.append(res_abuse)

        # Step 4.5: Deep Signal Enrichment (Entropy, SSL/TLS, Brand Mimicry, Redirect Lures)
        enriched = enrichment_service.evaluate_enrichment_signals(parsed_indicators)
        if enriched.get("detected_brand"):
            parsed_indicators["detected_brand_target"] = enriched["detected_brand"]

        # Step 5: Deterministic Risk Calculation
        (
            risk_score,
            risk_level,
            confidence,
            verdict,
            risk_factors,
            evidence_items,
            exploitability
        ) = risk_engine.calculate_risk(parsed_indicators, provider_results, previous_records)

        # Merge enriched factors and evidence
        for rf in enriched.get("risk_factors", []):
            if not any(f.name == rf.name for f in risk_factors):
                risk_factors.append(rf)
                risk_score = min(100, risk_score + rf.impact)
        for ev in enriched.get("evidence_items", []):
            if not any(e.title == ev.title for e in evidence_items):
                evidence_items.append(ev)

        # Recalculate verdict and level if enriched signals modified risk
        if enriched.get("has_rce"):
            risk_score = max(risk_score, 88)
            verdict = "MALICIOUS"
            risk_level = "HIGH"
        elif enriched.get("has_sqli") or enriched.get("has_traversal"):
            risk_score = max(risk_score, 72)
            verdict = "SUSPICIOUS"
            risk_level = "HIGH"
        elif enriched.get("has_xss") or enriched.get("has_admin_exposure"):
            risk_score = max(risk_score, 58)
            verdict = "SUSPICIOUS"
            risk_level = "SUSPICIOUS"
        elif risk_score >= 80:
            verdict = "MALICIOUS"
            risk_level = "HIGH"
        elif risk_score >= 45:
            verdict = "SUSPICIOUS"
            risk_level = "SUSPICIOUS"

        # Dynamically evaluate exploitability based on identified attack vectors
        if enriched.get("has_rce"):
            exploitability = ExploitabilityAssessment(
                level="HIGH",
                reason="Unrestricted OS Command Injection vector detected. Arbitrary remote code execution achievable without authentication.",
                confidence=0.95,
                factors=["Direct shell metacharacters exposed in public parameters", "Zero authentication hurdle", "High blast radius (Host Takeover)"]
            )
        elif enriched.get("has_sqli"):
            exploitability = ExploitabilityAssessment(
                level="HIGH",
                reason="Direct SQL Injection vector identified. Unsanitized parameter is directly concatenable into database queries.",
                confidence=0.92,
                factors=["Database syntax manipulation feasible", "Data exfiltration barrier: LOW", "Publicly reachable endpoint"]
            )
        elif enriched.get("has_traversal"):
            exploitability = ExploitabilityAssessment(
                level="HIGH",
                reason="Directory traversal pattern exposes local filesystem hierarchy. Sensitive configuration retrieval confirmed.",
                confidence=0.90,
                factors=["Filesystem root traversal possible", "Sensitive configuration disclosure"]
            )
        elif enriched.get("has_xss"):
            exploitability = ExploitabilityAssessment(
                level="MEDIUM",
                reason="Reflected Cross-Site Scripting vector detected. Requires user interaction or phishing lure delivery to execute.",
                confidence=0.85,
                factors=["Client-side DOM / script reflection", "Requires victim click / navigation", "Session token theft risk"]
            )
        elif enriched.get("has_admin_exposure"):
            exploitability = ExploitabilityAssessment(
                level="MEDIUM",
                reason="Administrative/diagnostic endpoint accessible without proper perimeter ACL enforcement.",
                confidence=0.88,
                factors=["Public route exposure", "Environment secrets readable if misconfigured"]
            )

        # Step 6: SafePath Alternative Evaluation
        safepath = safepath_engine.find_alternative(normalized_url, parsed_indicators, risk_score)

        # Step 7: Context-Aware Remediation Recommendations
        recommendations = recommendation_engine.generate_recommendations(
            parsed_indicators, verdict, risk_score, safepath
        )

        # Step 8: Evidence-Grounded Explanation Synthesis
        summary, key_findings, limitations = explanation_engine.generate_explanation(
            normalized_url, verdict, risk_score, risk_level, confidence,
            risk_factors, evidence_items, exploitability
        )

        # Step 8.5: AI Exploitability & MITRE ATT&CK Path Modeling
        attack_path = attack_path_engine.model_attack_path(
            target=normalized_url,
            verdict=verdict,
            risk_score=risk_score,
            parsed_indicators=parsed_indicators
        )

        # Step 9: Historical Delta Calculation
        historical = security_memory.calculate_delta(
            risk_score, verdict, most_recent_prev, len(previous_records)
        )

        # Analysis ID generation
        analysis_id = f"AST-{uuid.uuid4().hex[:8].upper()}"
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # Step 10: Persist immutable record into Security Memory
        persisted = security_memory.persist_analysis(
            db=db,
            analysis_id=analysis_id,
            indicator_type="URL",
            submitted_url=raw_url,
            normalized_url=normalized_url,
            domain=domain,
            hostname=hostname,
            scheme=parsed_indicators["scheme"],
            path=parsed_indicators["path"],
            query_present=parsed_indicators["query_present"],
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            exploitability_level=exploitability.level,
            verdict=verdict,
            summary=summary,
            duration_ms=duration_ms,
            evidence_items=evidence_items,
            provider_results=provider_results,
            recommendations=recommendations,
            safepath=safepath,
            historical=historical,
            is_demo=is_demo
        )

        return AnalysisResponse(
            analysis_id=analysis_id,
            status="completed",
            indicator_type="URL",
            submitted_url=raw_url,
            normalized_url=normalized_url,
            domain=domain,
            hostname=hostname,
            verdict=verdict,
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            freshness="FRESH",
            exploitability=exploitability,
            attack_path=attack_path,
            summary=summary,
            key_findings=key_findings,
            risk_factors=risk_factors,
            evidence=evidence_items,
            recommendations=recommendations,
            safepath=safepath,
            historical=historical,
            limitations=limitations,
            created_at=persisted.created_at,
            duration_ms=duration_ms,
            is_demo=is_demo
        )


url_analyzer = URLAnalyzerService()
