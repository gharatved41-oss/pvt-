"""Deterministic Risk & Exploitability Engine.
Calculates explainable risk scores (0-100) using transparent mathematical weighting.
AI does NOT invent the risk score; this engine is the single source of truth.
"""
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
from backend.app.schemas.analysis import RiskFactor, EvidenceItem, ExploitabilityAssessment
from backend.app.providers.base import ProviderResultData
from backend.app.config import settings


class RiskEngine:
    """
    Transparent, explainable risk scoring and exploitability assessment engine.
    """

    def calculate_risk(
        self,
        indicators: Dict[str, Any],
        provider_results: List[ProviderResultData],
        historical_records: List[Any]
    ) -> Tuple[int, str, float, str, List[RiskFactor], List[EvidenceItem], ExploitabilityAssessment]:
        """
        Calculates:
        1. risk_score (0-100)
        2. risk_level (LOW, GUARDED, SUSPICIOUS, HIGH)
        3. confidence (0.0 - 1.0)
        4. verdict (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN)
        5. risk_factors list
        6. evidence items
        7. exploitability assessment
        """
        score = 0
        factors: List[RiskFactor] = []
        evidence: List[EvidenceItem] = []
        now = datetime.now(timezone.utc)

        # -------------------------------------------------------------
        # 1. EVALUATE THREAT INTELLIGENCE & REPUTATION PROVIDERS (Up to 45 pts)
        # -------------------------------------------------------------
        active_providers = [p for p in provider_results if p.status == "AVAILABLE"]
        malicious_providers = [p for p in active_providers if p.classification == "MALICIOUS"]
        suspicious_providers = [p for p in active_providers if p.classification == "SUSPICIOUS"]

        if malicious_providers:
            impact = 40
            score += impact
            desc = f"{len(malicious_providers)} intelligence source(s) flagged this indicator as MALICIOUS."
            factors.append(RiskFactor(
                name="Threat Intelligence Detection",
                impact=impact,
                severity="CRITICAL",
                evidence=desc
            ))
            for p in malicious_providers:
                evidence.append(EvidenceItem(
                    category="threat_intel",
                    title=f"Malicious Classification by {p.provider_name}",
                    description=p.raw_reference or "High-confidence threat signature matched",
                    source=p.provider_name,
                    severity="HIGH",
                    impact_score=impact,
                    observed_at=p.observed_at
                ))
        elif suspicious_providers:
            impact = 22
            score += impact
            desc = f"{len(suspicious_providers)} intelligence source(s) classified indicator as SUSPICIOUS."
            factors.append(RiskFactor(
                name="Suspicious Provider Telemetry",
                impact=impact,
                severity="HIGH",
                evidence=desc
            ))
            for p in suspicious_providers:
                evidence.append(EvidenceItem(
                    category="threat_intel",
                    title=f"Suspicious Telemetry from {p.provider_name}",
                    description=p.raw_reference or "Anomalous behavioral or network patterns observed",
                    source=p.provider_name,
                    severity="MEDIUM",
                    impact_score=impact,
                    observed_at=p.observed_at
                ))

        # Check for unavailable providers
        unavailable_providers = [p for p in provider_results if p.status in ("UNAVAILABLE", "ERROR")]
        for p in unavailable_providers:
            evidence.append(EvidenceItem(
                category="threat_intel",
                title=f"Provider Telemetry Unavailable ({p.provider_name})",
                description=p.error_message or "Threat intelligence source unavailable; proceeding with local heuristic signals.",
                source=p.provider_name,
                severity="INFO",
                impact_score=0,
                observed_at=now
            ))

        # -------------------------------------------------------------
        # 2. EVALUATE LEXICAL & DOMAIN CHARACTERISTICS (Up to 35 pts)
        # -------------------------------------------------------------
        # Punycode / IDN Homograph
        if indicators.get("has_punycode"):
            impact = 18
            score += impact
            factors.append(RiskFactor(
                name="IDN Homograph / Punycode Deception",
                impact=impact,
                severity="HIGH",
                evidence=f"Hostname contains internationalized punycode ('{indicators.get('hostname')}') potentially spoofing a legitimate entity."
            ))
            evidence.append(EvidenceItem(
                category="domain_signals",
                title="Punycode Homograph Domain Detected",
                description=f"Raw hostname: {indicators.get('hostname')}, decoded: {indicators.get('decoded_hostname')}",
                source="URL Parser",
                severity="HIGH",
                impact_score=impact,
                observed_at=now
            ))

        # Brand impersonation
        brands = indicators.get("matched_brands", [])
        if brands:
            impact = 20
            score += impact
            factors.append(RiskFactor(
                name="Brand Impersonation Heuristic",
                impact=impact,
                severity="HIGH",
                evidence=f"Hostname embeds recognizable target brand(s) ({', '.join(brands)}) without being the authoritative domain."
            ))
            evidence.append(EvidenceItem(
                category="url_signals",
                title="Potential Brand Spoofing",
                description=f"Identified keyword(s) {brands} inside third-party domain '{indicators.get('domain')}'.",
                source="Heuristic Classifier",
                severity="HIGH",
                impact_score=impact,
                observed_at=now
            ))

        # Direct executable file payload
        if indicators.get("has_executable"):
            impact = 22
            score += impact
            exts = ", ".join(indicators.get("detected_extensions", []))
            factors.append(RiskFactor(
                name="Direct Executable / Script Payload Target",
                impact=impact,
                severity="HIGH",
                evidence=f"URL targets direct executable binary or script payload: {exts}."
            ))
            evidence.append(EvidenceItem(
                category="url_signals",
                title="Direct Executable Resource Referenced",
                description=f"Path '{indicators.get('path')}' references binary executable payload {exts}.",
                source="Static Path Analyzer",
                severity="HIGH",
                impact_score=impact,
                observed_at=now
            ))

        # Suspicious TLD
        if indicators.get("suspicious_tld"):
            impact = 14
            score += impact
            factors.append(RiskFactor(
                name="High-Abuse Top-Level Domain",
                impact=impact,
                severity="MEDIUM",
                evidence=f"Domain registered under high-abuse TLD .{indicators.get('tld')}."
            ))
            evidence.append(EvidenceItem(
                category="domain_signals",
                title="High-Abuse TLD Identified",
                description=f"TLD .{indicators.get('tld')} has statistically elevated rates of phishing and malicious infrastructure.",
                source="Reputation Classifier",
                severity="MEDIUM",
                impact_score=impact,
                observed_at=now
            ))

        # IP host address
        if indicators.get("is_ip"):
            impact = 12
            score += impact
            factors.append(RiskFactor(
                name="Naked IP Address Host",
                impact=impact,
                severity="MEDIUM",
                evidence="Host is specified as an IP address rather than a registered domain name."
            ))
            evidence.append(EvidenceItem(
                category="domain_signals",
                title="Host Is Naked IP Address",
                description=f"Direct IP {indicators.get('hostname')} bypasses standard DNS reputation architectures.",
                source="URL Parser",
                severity="MEDIUM",
                impact_score=impact,
                observed_at=now
            ))

        # High Entropy (DGA)
        entropy = indicators.get("hostname_entropy", 0.0)
        if entropy > 3.8:
            impact = 10
            score += impact
            factors.append(RiskFactor(
                name="High Hostname Entropy (Possible DGA)",
                impact=impact,
                severity="MEDIUM",
                evidence=f"Shannon entropy of host is {entropy}, characteristic of algorithmic domain generation."
            ))

        # -------------------------------------------------------------
        # 3. EVALUATE HISTORICAL SECURITY MEMORY (Up to 20 pts)
        # -------------------------------------------------------------
        if historical_records:
            prev_high_or_malicious = any(
                getattr(rec, "verdict", "") == "MALICIOUS" or getattr(rec, "risk_score", 0) >= 75
                for rec in historical_records
            )
            if prev_high_or_malicious:
                impact = 15
                score += impact
                factors.append(RiskFactor(
                    name="Historical Malicious Prior",
                    impact=impact,
                    severity="HIGH",
                    evidence=f"Security memory has {len(historical_records)} previous analysis record(s) identifying persistent malicious activity."
                ))
                evidence.append(EvidenceItem(
                    category="history",
                    title="Historical Malicious Association",
                    description=f"Prior analysis recorded high-risk security incidents for this indicator in security memory.",
                    source="AutoSecTwin Security Memory",
                    severity="HIGH",
                    impact_score=impact,
                    observed_at=now
                ))

        # Cap score at 100
        score = min(max(score, 0), 100)

        # -------------------------------------------------------------
        # 4. DETERMINE RISK LEVEL & VERDICT
        # -------------------------------------------------------------
        if score <= settings.RISK_THRESHOLD_LOW:
            risk_level = "LOW"
        elif score <= settings.RISK_THRESHOLD_GUARDED:
            risk_level = "GUARDED"
        elif score <= settings.RISK_THRESHOLD_SUSPICIOUS:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "HIGH"

        # Determine Verdict
        if score >= 75:
            verdict = "MALICIOUS"
        elif score >= 50:
            verdict = "SUSPICIOUS"
        elif score >= 25:
            verdict = "SUSPICIOUS"
        else:
            # Check if we have sufficient evidence to pronounce it SAFE or if it's UNKNOWN
            if len(active_providers) == 0 and len(factors) == 0:
                verdict = "UNKNOWN"
            else:
                verdict = "SAFE"

        # -------------------------------------------------------------
        # 5. CALCULATE CONFIDENCE (Decoupled from Risk Score)
        # -------------------------------------------------------------
        total_signals = len(factors) + len(active_providers)
        if len(active_providers) > 0 and len(factors) > 0:
            confidence = min(0.70 + (total_signals * 0.05), 0.98)
        elif len(active_providers) > 0:
            confidence = 0.80
        elif len(factors) > 0:
            confidence = 0.65
        else:
            confidence = 0.35  # Insufficient evidence

        confidence = round(confidence, 2)

        # -------------------------------------------------------------
        # 6. ASSESS CONTEXTUAL EXPLOITABILITY
        # -------------------------------------------------------------
        exploitability = self._assess_exploitability(indicators, score, verdict, factors)

        return score, risk_level, confidence, verdict, factors, evidence, exploitability

    def _assess_exploitability(
        self,
        indicators: Dict[str, Any],
        risk_score: int,
        verdict: str,
        factors: List[RiskFactor]
    ) -> ExploitabilityAssessment:
        """
        Assesses realistic reachability and threat relevance without generating exploit payloads.
        """
        has_exec = indicators.get("has_executable", False)
        is_ip = indicators.get("is_ip", False)
        spoofed = bool(indicators.get("matched_brands"))

        factors_list = []

        if verdict == "UNKNOWN":
            return ExploitabilityAssessment(
                level="UNKNOWN",
                reason="Available telemetry is insufficient to establish whether exploitation or compromise is feasible.",
                confidence=0.3,
                factors=["Insufficient telemetry"]
            )

        if has_exec:
            factors_list.append("Delivers direct executable binary without required intermediate stage")
        if spoofed:
            factors_list.append("Uses deceptive branding to lower victim skepticism")
        if is_ip:
            factors_list.append("Public IP endpoint bypasses domain blocklists")

        if risk_score >= 75 and (has_exec or spoofed):
            return ExploitabilityAssessment(
                level="HIGH",
                reason="Indicator is publicly accessible, delivers executable code or social engineering deception, requiring low attacker effort for compromise.",
                confidence=0.88,
                factors=factors_list
            )
        elif risk_score >= 45:
            return ExploitabilityAssessment(
                level="MEDIUM",
                reason="Suspicious lexical or network characteristics observed; compromise likely requires active user interaction or credential submission.",
                confidence=0.75,
                factors=factors_list or ["Interactive user prompt / landing page"]
            )
        else:
            return ExploitabilityAssessment(
                level="LOW",
                reason="No active weaponization, deceptive indicators, or binary dropper patterns identified in available telemetry.",
                confidence=0.80,
                factors=["Standard web resource without weaponized attributes"]
            )
