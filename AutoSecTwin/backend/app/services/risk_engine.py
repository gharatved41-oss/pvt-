"""Deterministic and explainable risk evaluation engine based strictly on observed passive evidence.

Separates risk severity, confidence levels, and exploitability.
Exploitability is strictly UNKNOWN until authorized active verification occurs in a sandbox.
A negative threat intelligence lookup (no-match) is explicitly NOT treated as proof of safety.
"""

from typing import List, Union

from app.models.evidence import SecurityEvidenceRecord
from app.schemas.evidence import EvidenceCollectionStatus, EvidenceItemCreate
from app.schemas.risk import (
    ConfidenceLevel,
    ExploitabilityStatus,
    RiskAssessmentResponse,
    RiskFactor,
    RiskLevel,
)

EvidenceInput = Union[SecurityEvidenceRecord, EvidenceItemCreate]


class DeterministicPassiveRiskEngine:
    """Evaluates passive security observations and threat intelligence deterministically."""

    BASELINE_SCORE = 10

    def evaluate(self, evidence_items: List[EvidenceInput]) -> RiskAssessmentResponse:
        """Calculate a transparent, explainable risk score and contributing factors.

        Args:
            evidence_items: Collection of observed evidence records.

        Returns:
            RiskAssessmentResponse with score, levels, factors, and limitations.
        """
        score = self.BASELINE_SCORE
        confidence = ConfidenceLevel.LOW
        has_threat_intel_match = False

        factors: List[RiskFactor] = [
            RiskFactor(
                signal_name="baseline_system_neutral",
                score_delta=self.BASELINE_SCORE,
                rationale="Standard neutral baseline score applied to all submitted targets.",
            )
        ]

        # Map evidence by signal name
        evidence_by_signal = {item.signal_name: item for item in evidence_items}

        # -------------------------------------------------------------
        # 1. Scheme Evaluation
        # -------------------------------------------------------------
        scheme_evidence = evidence_by_signal.get("url_scheme")
        if scheme_evidence and scheme_evidence.collection_status == EvidenceCollectionStatus.OBSERVED:
            observed_scheme = (scheme_evidence.observed_value or "").lower()
            if observed_scheme == "http":
                score += 20
                factors.append(
                    RiskFactor(
                        signal_name="url_scheme",
                        score_delta=20,
                        rationale="Target URL uses plaintext HTTP instead of encrypted HTTPS transport.",
                    )
                )
            elif observed_scheme == "https":
                # Encrypted transport is a positive hygiene factor
                score -= 5
                factors.append(
                    RiskFactor(
                        signal_name="url_scheme",
                        score_delta=-5,
                        rationale="Target URL specifies HTTPS with TLS transport encryption.",
                    )
                )

        # -------------------------------------------------------------
        # 2. Hostname Type Evaluation (Direct IP literal)
        # -------------------------------------------------------------
        host_evidence = evidence_by_signal.get("hostname_type")
        if host_evidence and host_evidence.collection_status == EvidenceCollectionStatus.OBSERVED:
            if "literal" in (host_evidence.observed_value or ""):
                score += 25
                factors.append(
                    RiskFactor(
                        signal_name="hostname_type",
                        score_delta=25,
                        rationale="Host is specified as a raw IP address literal rather than a verified domain name.",
                    )
                )

        # -------------------------------------------------------------
        # 3. Explicit Non-Standard Port
        # -------------------------------------------------------------
        port_evidence = evidence_by_signal.get("explicit_port")
        if port_evidence and port_evidence.collection_status == EvidenceCollectionStatus.OBSERVED:
            struct_data = port_evidence.structured_data or {}
            if not struct_data.get("is_standard_web_port", True):
                score += 10
                factors.append(
                    RiskFactor(
                        signal_name="explicit_port",
                        score_delta=10,
                        rationale=f"Target specifies non-standard web port '{port_evidence.observed_value}'.",
                    )
                )

        # -------------------------------------------------------------
        # 4. Excessive Subdomain Depth
        # -------------------------------------------------------------
        subdomain_evidence = evidence_by_signal.get("subdomain_depth")
        if subdomain_evidence and subdomain_evidence.collection_status == EvidenceCollectionStatus.OBSERVED:
            try:
                depth = int(subdomain_evidence.observed_value or "0")
                if depth >= 3:
                    score += 10
                    factors.append(
                        RiskFactor(
                            signal_name="subdomain_depth",
                            score_delta=10,
                            rationale=f"Elevated subdomain nesting depth observed ({depth} levels).",
                        )
                    )
            except ValueError:
                pass

        # -------------------------------------------------------------
        # 5. Sensitive Lexical Tokens
        # -------------------------------------------------------------
        token_evidence = evidence_by_signal.get("sensitive_lexical_tokens")
        if token_evidence and token_evidence.collection_status == EvidenceCollectionStatus.OBSERVED:
            score += 15
            factors.append(
                RiskFactor(
                    signal_name="sensitive_lexical_tokens",
                    score_delta=15,
                    rationale=(
                        f"URL path or query string contains authentication-related keywords: "
                        f"'{token_evidence.observed_value}'."
                    ),
                )
            )

        # -------------------------------------------------------------
        # 6. Threat Intelligence Reputation Evaluation
        # -------------------------------------------------------------
        for item in evidence_items:
            sig = item.signal_name.lower()
            if "reputation" in sig or "threat_intel" in sig:
                struct = item.structured_data or {}
                status_val = struct.get("lookup_status") or item.collection_status.value

                if status_val == "match" or item.collection_status == EvidenceCollectionStatus.OBSERVED:
                    verdict = (struct.get("threat_verdict") or item.observed_value or "").lower()
                    if "malicious" in verdict:
                        score += 40
                        has_threat_intel_match = True
                        factors.append(
                            RiskFactor(
                                signal_name=item.signal_name,
                                score_delta=40,
                                rationale=f"Threat intelligence confirmed malicious reputation entry ({verdict}).",
                            )
                        )
                    elif "suspicious" in verdict:
                        score += 25
                        has_threat_intel_match = True
                        factors.append(
                            RiskFactor(
                                signal_name=item.signal_name,
                                score_delta=25,
                                rationale=f"Threat intelligence identified suspicious telemetry ({verdict}).",
                            )
                        )
                    else:
                        score += 10
                        factors.append(
                            RiskFactor(
                                signal_name=item.signal_name,
                                score_delta=10,
                                rationale=f"Threat intelligence returned reputation observation: {item.observed_value}.",
                            )
                        )
                elif (
                    status_val in ("no_match", "unknown_indicator", "privacy_blocked")
                    or item.collection_status in (EvidenceCollectionStatus.ABSENT, EvidenceCollectionStatus.SKIPPED)
                ):
                    # Critical safety requirement: No reduction in risk score for no-match, unknown, or privacy-blocked!
                    if status_val == "privacy_blocked" or item.collection_status == EvidenceCollectionStatus.SKIPPED:
                        rationale = (
                            "Threat intelligence lookup was skipped locally by privacy guardrails. "
                            "No external indicator reputation query was performed."
                        )
                    elif status_val == "unknown_indicator":
                        rationale = (
                            "Target indicator not recorded in threat intelligence provider database (unknown indicator). "
                            "Absence in database is NOT evidence that the target is safe or benign."
                        )
                    else:
                        rationale = (
                            "No threat intelligence match recorded in provider database. "
                            "Absence of threat telemetry is NOT evidence that the target is safe or benign."
                        )

                    factors.append(
                        RiskFactor(
                            signal_name=item.signal_name,
                            score_delta=0,
                            rationale=rationale,
                        )
                    )

        # -------------------------------------------------------------
        # 7. Generic Collector Errors
        # -------------------------------------------------------------
        for item in evidence_items:
            if item.collection_status == EvidenceCollectionStatus.ERROR:
                score += 5
                factors.append(
                    RiskFactor(
                        signal_name=item.signal_name,
                        score_delta=5,
                        rationale=f"Evidence collection encountered an error: {item.observed_value}",
                    )
                )

        # Elevate confidence to MEDIUM if corroborated by external threat intelligence
        if has_threat_intel_match:
            confidence = ConfidenceLevel.MEDIUM

        # Clamp composite score between 0 and 100
        clamped_score = max(0, min(100, score))

        # Categorical risk classification
        if clamped_score <= 25:
            risk_level = RiskLevel.LOW
        elif clamped_score <= 50:
            risk_level = RiskLevel.MEDIUM
        elif clamped_score <= 75:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        limitations = [
            "Assessment is based on local lexical syntax, hostname characteristics, and integrated threat telemetry.",
            "No active target probing, penetration testing, or exploit execution was conducted in this milestone.",
            "A no-match reputation result indicates an absence of known IOCs, not verified safety.",
            "Confidence is calibrated strictly to the breadth of available evidence.",
            "Exploitability is marked UNKNOWN: syntactic signals and external reputation cannot confirm actionable exploitability without sandbox verification.",
        ]

        return RiskAssessmentResponse(
            risk_score=clamped_score,
            risk_level=risk_level,
            confidence_level=confidence,
            exploitability=ExploitabilityStatus.UNKNOWN,
            contributing_factors=factors,
            limitations=limitations,
        )
