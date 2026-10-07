"""AI-Assisted & Deterministic Security Explanation Engine.
Generates human-readable executive summaries, key findings, and explicit limitations.
AI is strictly an explanation layer grounded in observed evidence; it never invents scores or detections.
"""
from typing import Dict, Any, List, Tuple
from backend.app.schemas.analysis import RiskFactor, EvidenceItem, ExploitabilityAssessment
from backend.app.config import settings
from backend.app.core.logging import logger

try:
    from google import genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


class ExplanationEngine:
    """
    Produces grounded security explanations.
    Uses robust deterministic synthesis with Google Gemini AI intelligence enhancement.
    """

    def generate_explanation(
        self,
        url: str,
        verdict: str,
        risk_score: int,
        risk_level: str,
        confidence: float,
        factors: List[RiskFactor],
        evidence: List[EvidenceItem],
        exploitability: ExploitabilityAssessment
    ) -> Tuple[str, List[str], List[str]]:
        """
        Returns (summary: str, key_findings: List[str], limitations: List[str]).
        """
        # Grounded Key Findings
        findings: List[str] = []
        for factor in factors:
            findings.append(f"{factor.name}: {factor.evidence} (Impact: +{factor.impact} pts)")

        if not findings:
            if verdict == "SAFE":
                findings.append("No anomalous lexical, TLD, or threat reputation indicators identified.")
            elif verdict == "UNKNOWN":
                findings.append("Telemetry sources returned insufficient data to conclusively establish reputation.")

        # Default Grounded Deterministic Executive Summary
        if verdict == "MALICIOUS":
            summary = (
                f"SentinalX classified target as {verdict} ({risk_score}/100, {int(confidence*100)}% confidence). "
                f"Multiple corroborated signals demonstrate active malicious infrastructure, deceptive branding, "
                f"or executable distribution. Immediate perimeter containment is strongly advised."
            )
        elif verdict == "SUSPICIOUS":
            summary = (
                f"SentinalX identified elevated risk factors resulting in a {verdict} assessment ({risk_score}/100). "
                f"While full weaponization has not been conclusively established by all providers, "
                f"observed lexical anomalies or third-party signals exceed safe operational baselines."
            )
        elif verdict == "SAFE":
            summary = (
                f"Analysis completed with LOW RISK verdict ({risk_score}/100, {int(confidence*100)}% confidence). "
                f"No active malicious signatures, punycode spoofing, or deceptive attributes were observed. "
                f"Standard security hygiene applies."
            )
        else:  # UNKNOWN
            summary = (
                f"Insufficient evidence was available to assign a definitive security verdict. "
                f"Threat intelligence providers were inconclusive or telemetry was limited. "
                f"SentinalX does NOT claim an indicator is safe merely because no active blocklist matches exist."
            )

        # Optional Gemini Grounded Intelligence Synthesis
        if settings.AI_ENABLED and settings.GEMINI_API_KEY and HAS_GENAI:
            try:
                client = genai.Client(api_key=settings.GEMINI_API_KEY)
                evidence_summary = "; ".join([f"{e.title} ({e.severity})" for e in evidence[:4]])
                prompt = (
                    f"You are the SentinalX Cyber Defense Intelligence Core. Provide a professional, concise executive "
                    f"threat summary (maximum 2-3 sentences) for target indicator '{url}'.\n"
                    f"Verdict: {verdict}\n"
                    f"Risk Score: {risk_score}/100 ({risk_level})\n"
                    f"Exploitability: {exploitability.level} ({exploitability.rationale})\n"
                    f"Verified Evidence: {evidence_summary}\n\n"
                    f"Ground your assessment STRICTLY in the facts above. Do not hallucinate external attacks."
                )
                response = client.models.generate_content(
                    model='gemini-3.5-flash-lite',
                    contents=prompt
                )
                if response and response.text and response.text.strip():
                    summary = response.text.strip()
                    logger.info("Successfully synthesized grounded summary with Gemini AI.")
            except Exception as e:
                logger.warning(f"Gemini AI synthesis fallback to deterministic summary: {str(e)}")

        # Explicit Security Limitations
        limitations = [
            "SentinalX analyzes indicators statically and via threat intelligence; it does not execute untrusted binaries on the host device.",
            "Reputation analysis alone cannot confirm whether an individual endpoint on your network was already breached prior to analysis.",
            "Newly registered zero-day domains (bulletproof hosting) may initially exhibit low provider detections until indexed by global feeds."
        ]

        return summary, findings, limitations


explanation_engine = ExplanationEngine()
