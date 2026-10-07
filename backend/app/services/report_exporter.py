"""Report Exporter Service for SentinelX.
Generates comprehensive, formatted Markdown and JSON audit reports suitable for
CISO executive briefings, security engineers, and compliance audits.
"""
from typing import Dict, Any
from datetime import datetime, timezone
from backend.app.models.database import Analysis


class ReportExporter:
    """
    Renders audit reports from stored analyses.
    """

    def export_as_markdown(self, analysis: Analysis) -> str:
        """Renders an executive cybersecurity audit report in GitHub-flavored Markdown."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        md_lines = [
            "# 🛡️ SENTINELX // EXECUTIVE THREAT INTELLIGENCE AUDIT",
            f"**Audit ID:** `{analysis.analysis_id}` | **Generated:** `{now}`",
            "**Classification:** RESTRICTED // SECURITY OPERATIONS",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Target Asset:** `{analysis.submitted_url}`",
            f"- **Normalized Canonical Indicator:** `{analysis.normalized_url}`",
            f"- **Domain / Host:** `{analysis.domain or 'N/A'}`",
            f"- **Security Verdict:** **{analysis.verdict}**",
            f"- **Deterministic Risk Score:** **{analysis.risk_score} / 100** ({analysis.risk_level})",
            f"- **Confidence Index:** **{int(analysis.confidence * 100)}%**",
            f"- **AI Exploitability Assessment:** **{analysis.exploitability_level}**",
            "",
            f"> {analysis.summary or 'Deterministic evaluation completed with zero remote malware execution.'}",
            "",
            "---",
            "",
            "## 2. Supporting Telemetry & Evidence Chain",
            "",
            "| Severity | Category | Title | Observed Source |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for ev in analysis.evidence_items:
            md_lines.append(f"| **{ev.severity}** | `{ev.category}` | {ev.title} | {ev.source} |")

        md_lines.extend([
            "",
            "### Detailed Evidence Breakdown",
            ""
        ])

        for ev in analysis.evidence_items:
            md_lines.append(f"#### [{ev.severity}] {ev.title}")
            md_lines.append(f"- **Impact Score:** `+{ev.impact_score} pts`")
            md_lines.append(f"- **Observation Source:** `{ev.source}`")
            md_lines.append(f"- **Description:** {ev.description}")
            md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## 3. Recommended Remediation & Countermeasures",
            ""
        ])

        if analysis.recommendations:
            for rec in analysis.recommendations:
                md_lines.append(f"### [{rec.priority}] {rec.title}")
                md_lines.append(f"- **Root Cause Rationale:** {rec.reason}")
                md_lines.append(f"- **Prescribed Action:** `{rec.action}`")
                md_lines.append(f"- **Engineering Effort:** {rec.effort}")
                md_lines.append("")
        else:
            md_lines.append("No active remediation required. Asset matches authentic benign patterns.")

        if analysis.safepath:
            sp = analysis.safepath
            md_lines.extend([
                "---",
                "",
                "## 4. SafePath™ Verified Alternative",
                "",
                f"- **Detected Software Intent:** {sp.software_name}",
                f"- **Authentic Vendor Channel:** [{sp.recommended_name}]({sp.recommended_url})",
                f"- **Vendor Domain:** `{sp.recommended_domain}`",
                f"- **Baseline Risk Score:** `{sp.recommended_risk}/100` (vs `{sp.original_risk}/100` unverified source)",
                f"- **Security Guidance:** {sp.comparison_reason}",
                f"- *Disclaimer:* {sp.disclaimer}",
                ""
            ])

        md_lines.extend([
            "---",
            "",
            "## 5. Security Attestation & Constraints",
            "",
            "- **Zero-Execution Sandbox Guarantee:** SentinelX operates under strict static heuristics and controlled Digital Twin verification. No untrusted payloads are executed on host infrastructure.",
            "- **SSRF Guard:** Submissions are validated against RFC 1918, RFC 3927, and cloud metadata subnets prior to telemetry collection.",
            "- **Audit Authority:** SentinelX Core Risk Engine v2.4."
        ])

        return "\n".join(md_lines)


report_exporter = ReportExporter()
