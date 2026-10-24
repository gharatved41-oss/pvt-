"""Deterministic and explainable OS risk scoring engine.

Evaluates operating system security findings, configuration weaknesses,
evidence confidence, and assessment completeness.

Guarantees:
- Exploitability is strictly kept separate and defaults to UNKNOWN.
- Provider errors, timeouts, and missing inventories prevent a false 'LOW' risk rating.
- Scoring is transparent, bounded (0-100), deterministic, and unit-testable.
- Duplicate findings are deterministically deduplicated before scoring.
"""

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.os_assessment import OSRiskLevel
from app.schemas.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)
from app.services.os_matcher.vulnerability_matcher import MatchingEvaluationReport


class OSRiskEvaluationResult(BaseModel):
    """Transparent and explainable result of an OS risk evaluation."""

    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    risk_level: OSRiskLevel = Field(..., description="Categorical risk classification")
    confidence_level: OSConfidence = Field(..., description="Overall assessment confidence")
    exploitability_state: OSExploitability = Field(
        default=OSExploitability.UNKNOWN,
        description="Exploitability verification state (strictly 'unknown' unless verified)",
    )
    is_complete: bool = Field(default=True, description="False if sources were unavailable, timed out, or incomplete")
    vulnerability_subscore: float = Field(default=0.0, description="Points from software CVE vulnerabilities")
    misconfiguration_subscore: float = Field(default=0.0, description="Points from system security misconfigurations")
    context_subscore: float = Field(default=0.0, description="Points from environmental or network exposure context")
    uncertainty_adjustment: float = Field(default=0.0, description="Points added due to missing or degraded data sources")
    top_contributing_findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Findings contributing most heavily to the overall score",
    )
    score_rationale: List[str] = Field(
        default_factory=list,
        description="Human-readable explanation of score calculations",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit assessment boundaries and missing source warnings",
    )


class OSRiskEngine:
    """Calculates deterministic, explainable risk scores for operating system assessments."""

    POLICY_VERSION: str = "vulntwin_os_risk_policy_v1"

    # Base severity weights (max points per finding)
    SEVERITY_WEIGHTS = {
        OSSeverity.CRITICAL: 45.0,
        OSSeverity.HIGH: 25.0,
        OSSeverity.MEDIUM: 12.0,
        OSSeverity.LOW: 5.0,
        OSSeverity.UNRATED: 6.0,
    }

    # Confidence multipliers
    CONFIDENCE_MULTIPLIERS = {
        OSConfidence.HIGH: 1.0,
        OSConfidence.MEDIUM: 0.75,
        OSConfidence.LOW: 0.40,
    }

    # Misconfiguration specific weights
    MISCONFIG_WEIGHTS = {
        "CFG-WIN-DEFENDER": 20.0,
        "CFG-WIN-FIREWALL": 15.0,
        "CFG-LINUX-ASLR": 15.0,
        "CFG-WIN-UAC": 12.0,
        "CFG-WIN-RDP": 10.0,
        "CFG-LINUX-SSHD": 10.0,
        "CFG-LINUX-IPFWD": 8.0,
        "CFG-LINUX-UPDATES": 6.0,
    }

    def evaluate(
        self,
        findings: List[OSFindingCreate],
        matching_report: Optional[MatchingEvaluationReport] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> OSRiskEvaluationResult:
        """Evaluate findings and return a deterministic, explainable risk score.

        Args:
            findings: List of identified security findings (CVEs, misconfigurations).
            matching_report: Optional report from vulnerability matcher capturing provider health and limitations.
            context: Optional dictionary containing asset environment info (e.g., exposed services, OS details).

        Returns:
            OSRiskEvaluationResult containing score, level, subscores, and clear rationale.
        """
        rationale: List[str] = []
        limitations: List[str] = []
        is_complete = True
        ctx = context or {}

        if matching_report:
            if not matching_report.is_complete:
                is_complete = False
            limitations.extend(matching_report.limitations)

        # Context-based assessment incompleteness checks
        if ctx.get("is_complete") is False:
            is_complete = False
            limitations.append("Assessment context marked incomplete.")
        if ctx.get("missing_inventory") or ctx.get("missing_inventories"):
            is_complete = False
            limitations.append("System package or application inventory missing.")
        if ctx.get("evidence_stale") or ctx.get("stale_evidence"):
            is_complete = False
            limitations.append("Collected evidence timestamps exceed freshness threshold (stale evidence).")
        if ctx.get("provider_failures"):
            is_complete = False
            limitations.append(f"Advisory provider failures reported: {ctx.get('provider_failures')}")
        if ctx.get("unavailable_controls"):
            is_complete = False
            limitations.append(f"Security controls unavailable for inspection: {ctx.get('unavailable_controls')}")

        # 1. Deterministic Deduplication: Ensure duplicate findings on the same component do not multiply score
        deduped_findings: Dict[str, OSFindingCreate] = {}
        for f in findings:
            key = f"{f.finding_type.value}:{f.advisory_id}:{f.component_name}"
            if key not in deduped_findings:
                deduped_findings[key] = f
            else:
                existing = deduped_findings[key]
                # Retain the finding with higher valid CVSS score or confirmed fixed_version
                f_cvss = f.cvss_score if (f.cvss_score is not None and not math.isnan(f.cvss_score)) else 0.0
                e_cvss = existing.cvss_score if (existing.cvss_score is not None and not math.isnan(existing.cvss_score)) else 0.0
                if f_cvss > e_cvss or (f.fixed_version and not existing.fixed_version):
                    deduped_findings[key] = f

        unique_findings = list(deduped_findings.values())

        # Check if any finding indicates degraded or unavailable evidence
        for f in unique_findings:
            if f.match_basis in ("insufficient_evidence_provider_unavailable", "insufficient_evidence_missing_inventory"):
                is_complete = False
                limitations.append(f"Finding {f.advisory_id} for {f.component_name} lacked required evidence.")

        # 2. Score CVE Vulnerabilities
        cve_findings = [f for f in unique_findings if f.finding_type == OSFindingType.CVE_VULNERABILITY]
        cve_scores: List[float] = []

        for f in cve_findings:
            base_w = self.SEVERITY_WEIGHTS.get(f.severity, 6.0)
            # Use CVSS score if available, valid, and positive to refine base weight
            cvss = f.cvss_score
            if cvss is not None and not math.isnan(cvss) and not math.isinf(cvss) and cvss > 0:
                cvss_clamped = min(10.0, max(0.0, float(cvss)))
                if f.severity == OSSeverity.CRITICAL:
                    base_w = min(50.0, max(35.0, cvss_clamped * 4.8))
                elif f.severity == OSSeverity.HIGH:
                    base_w = min(30.0, max(20.0, cvss_clamped * 2.8))
                elif f.severity == OSSeverity.MEDIUM:
                    base_w = min(18.0, max(8.0, cvss_clamped * 1.6))
                elif f.severity == OSSeverity.LOW:
                    base_w = min(8.0, max(2.0, cvss_clamped * 0.8))

            conf_mult = self.CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.5)
            effective_score = base_w * conf_mult
            cve_scores.append(effective_score)

        # Aggregate CVE scores with diminishing returns: primary issue has 100% weight, subsequent issues decay
        cve_scores.sort(reverse=True)
        vulnerability_subscore = 0.0
        if cve_scores:
            vulnerability_subscore = cve_scores[0]
            for i, score in enumerate(cve_scores[1:], start=1):
                decay = 0.30 if i <= 3 else 0.15
                vulnerability_subscore += score * decay
        vulnerability_subscore = min(75.0, vulnerability_subscore)

        if cve_findings:
            rationale.append(
                f"Evaluated {len(cve_findings)} CVE vulnerabilities (primary flaw contribution: {cve_scores[0]:.1f} pts, total vuln subscore: {vulnerability_subscore:.1f} pts)."
            )

        # 3. Score System Misconfigurations
        misconfig_findings = [f for f in unique_findings if f.finding_type == OSFindingType.MISCONFIGURATION]
        misconfig_scores: List[float] = []

        for f in misconfig_findings:
            rule_id = f.advisory_id
            base_w = self.MISCONFIG_WEIGHTS.get(rule_id, 8.0)
            conf_mult = self.CONFIDENCE_MULTIPLIERS.get(f.confidence, 1.0)
            misconfig_scores.append(base_w * conf_mult)

        misconfig_scores.sort(reverse=True)
        misconfiguration_subscore = 0.0
        if misconfig_scores:
            misconfiguration_subscore = misconfig_scores[0]
            for score in misconfig_scores[1:]:
                misconfiguration_subscore += score * 0.40
        misconfiguration_subscore = min(35.0, misconfiguration_subscore)

        if misconfig_findings:
            rationale.append(
                f"Evaluated {len(misconfig_findings)} security misconfigurations (misconfig subscore: {misconfiguration_subscore:.1f} pts)."
            )

        # 4. Contextual Modifiers (Applied only when supported by confirmed evidence)
        context_subscore = 0.0
        if ctx.get("is_public_facing") is True:
            context_subscore += 10.0
            rationale.append("Asset context: host is confirmed public-facing (+10.0 pts).")
        if ctx.get("has_unrestricted_inbound_ports") is True:
            context_subscore += 5.0
            rationale.append("Asset context: inbound network services confirmed exposed (+5.0 pts).")

        # 5. Missing Evidence & Assessment Incompleteness Penalty
        # Requirement: "Do not treat missing evidence or unavailable advisory providers as low risk."
        uncertainty_adjustment = 0.0
        if not is_complete:
            # If the assessment is incomplete, it cannot be classified as clean or low risk
            raw_subtotal = vulnerability_subscore + misconfiguration_subscore + context_subscore
            if raw_subtotal < 30.0:
                uncertainty_adjustment = 30.0 - raw_subtotal
                rationale.append(
                    f"Incomplete assessment: advisory providers degraded, evidence stale, or inventory missing. Applied uncertainty risk floor (+{uncertainty_adjustment:.1f} pts) to prevent false low-risk classification."
                )

        # 6. Composite Score Calculation
        total_raw = vulnerability_subscore + misconfiguration_subscore + context_subscore + uncertainty_adjustment
        final_score = int(round(min(100.0, max(0.0, total_raw))))

        # Determine Categorical Risk Level
        if final_score >= 80:
            risk_level = OSRiskLevel.CRITICAL
        elif final_score >= 50:
            risk_level = OSRiskLevel.HIGH
        elif final_score >= 20:
            risk_level = OSRiskLevel.MEDIUM
        else:
            risk_level = OSRiskLevel.LOW

        # Overall Confidence: Minimum confidence across high-impact findings; force LOW if incomplete
        if not is_complete or any(f.confidence == OSConfidence.LOW for f in unique_findings[:3]):
            confidence_level = OSConfidence.LOW
        elif any(f.confidence == OSConfidence.MEDIUM for f in unique_findings[:3]):
            confidence_level = OSConfidence.MEDIUM
        else:
            confidence_level = OSConfidence.HIGH

        # Exploitability remains strictly UNKNOWN by default
        exploitability_state = OSExploitability.UNKNOWN

        # Extract top contributors with deterministic tie-breaking
        top_findings = []
        sorted_findings = sorted(
            unique_findings,
            key=lambda f: (
                self.SEVERITY_WEIGHTS.get(f.severity, 0.0) * self.CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.5),
                f.cvss_score if (f.cvss_score is not None and not math.isnan(f.cvss_score)) else 0.0,
                f.advisory_id,
                f.component_name,
            ),
            reverse=True,
        )
        for f in sorted_findings[:5]:
            top_findings.append({
                "advisory_id": f.advisory_id,
                "title": f.title,
                "component": f.component_name,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
            })

        return OSRiskEvaluationResult(
            risk_score=final_score,
            risk_level=risk_level,
            confidence_level=confidence_level,
            exploitability_state=exploitability_state,
            is_complete=is_complete,
            vulnerability_subscore=round(vulnerability_subscore, 1),
            misconfiguration_subscore=round(misconfiguration_subscore, 1),
            context_subscore=round(context_subscore, 1),
            uncertainty_adjustment=round(uncertainty_adjustment, 1),
            top_contributing_findings=top_findings,
            score_rationale=rationale,
            limitations=limitations,
        )
