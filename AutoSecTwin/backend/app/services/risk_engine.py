"""Deterministic and explainable risk evaluation engine based strictly on observed passive evidence.

Separates risk severity, confidence levels, and exploitability.
Exploitability is strictly UNKNOWN until authorized active verification occurs in a sandbox.
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
    """Evaluates passive security observations deterministically without opaque heuristics."""

    BASELINE_SCORE = 10

    def evaluate(self, evidence_items: List[EvidenceInput]) -> RiskAssessmentResponse:
        """Calculate a transparent, explainable risk score and contributing factors.

        Args:
            evidence_items: Collection of observed evidence records.

        Returns:
            RiskAssessmentResponse with score, levels, factors, and limitations.
        """
        score = self.BASELINE_SCORE
        factors: List[RiskFactor] = [
            RiskFactor(
                signal_name="baseline_system_neutral",
                score_delta=self.BASELINE_SCORE,
                rationale="Standard neutral baseline score applied to all submitted targets.",
            )
        ]

        # Map evidence by signal name
        evidence_by_signal = {item.signal_name: item for item in evidence_items}

        # 1. Scheme Evaluation
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

        # 2. Hostname Type Evaluation (Direct IP literal)
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

        # 3. Explicit Non-Standard Port
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

        # 4. Excessive Subdomain Depth
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

        # 5. Sensitive Lexical Tokens
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

        # 6. Any collector error status
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
            "Assessment is strictly based on local lexical syntax and hostname characteristics.",
            "No outbound network requests or live target investigations were conducted in this milestone.",
            "Confidence is rated LOW due to the purely syntactic and non-network nature of evidence.",
            "Exploitability is marked UNKNOWN: syntactic signals cannot confirm actionable vulnerability.",
        ]

        return RiskAssessmentResponse(
            risk_score=clamped_score,
            risk_level=risk_level,
            confidence_level=ConfidenceLevel.LOW,
            exploitability=ExploitabilityStatus.UNKNOWN,
            contributing_factors=factors,
            limitations=limitations,
        )
