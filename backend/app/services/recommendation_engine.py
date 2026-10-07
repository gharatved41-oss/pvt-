"""Context-Aware Security Recommendation Engine.
Produces prioritized, evidence-grounded remediation actions tailored to the specific observed threats.
Never outputs uncontextualized, generic advice.
"""
from typing import List, Dict, Any, Optional
from backend.app.schemas.analysis import RecommendationItem, SafePathAlternative


class RecommendationEngine:
    """
    Generates tailored, actionable security remediation recommendations
    grounded strictly in observed evidence.
    """

    def generate_recommendations(
        self,
        indicators: Dict[str, Any],
        verdict: str,
        risk_score: int,
        safepath: Optional[SafePathAlternative]
    ) -> List[RecommendationItem]:
        recommendations: List[RecommendationItem] = []
        domain = indicators.get("domain") or indicators.get("hostname")

        # 1. High/Critical Malicious Recommendations
        if verdict == "MALICIOUS" or risk_score >= 75:
            recommendations.append(RecommendationItem(
                priority="CRITICAL",
                title=f"Block domain '{domain}' at DNS and Gateway firewalls",
                reason=f"The indicator scored {risk_score}/100 with multiple high-confidence malicious threat signals.",
                action=f"Add '{domain}' and host '{indicators.get('hostname')}' to the organization's enterprise DNS sinkhole and perimeter egress blocklist.",
                effort="LOW",
                coverage="Prevents enterprise endpoints and users from establishing outbound connections to this threat."
            ))

            recommendations.append(RecommendationItem(
                priority="HIGH",
                title="Hunt for internal endpoint connections in SIEM / EDR",
                reason="If an employee clicked or received this indicator, active command-and-control or payload download may have occurred.",
                action=f"Query proxy, firewall, and DNS telemetry for any internal IP traffic directed towards '{domain}' over the past 30 days.",
                effort="MEDIUM",
                coverage="Identifies compromised internal hosts requiring forensic isolation."
            ))

        # 2. Credential Harvesting / Phishing Specific
        matched_brands = indicators.get("matched_brands", [])
        if matched_brands:
            recommendations.append(RecommendationItem(
                priority="HIGH",
                title=f"Check for credential exposure targeting {', '.join(matched_brands)}",
                reason=f"Indicator mimics brand patterns for {', '.join(matched_brands)}, suggesting an active phishing or credential harvesting campaign.",
                action="Force password resets and revoke active session tokens for any internal users identified in proxy logs contacting this URL.",
                effort="MEDIUM",
                coverage="Neutralizes stolen credentials before unauthorized account takeover occurs."
            ))

        # 3. SafePath Official Alternative Recommendation
        if safepath:
            recommendations.append(RecommendationItem(
                priority="HIGH",
                title=f"Redirect download request to official vendor ({safepath.recommended_domain})",
                reason=safepath.comparison_reason,
                action=f"Discard the untrusted binary link and obtain authentic installer from {safepath.recommended_url}.",
                effort="LOW",
                coverage="Ensures user receives authentic, digitally signed binaries without trojanized add-ons."
            ))

        # 4. Executable Payload Defense
        if indicators.get("has_executable") and verdict in ("SUSPICIOUS", "MALICIOUS"):
            recommendations.append(RecommendationItem(
                priority="MEDIUM",
                title="Quarantine downloaded binary from endpoint downloads folder",
                reason=f"URL targets direct binary file ({', '.join(indicators.get('detected_extensions', []))}).",
                action="Verify client machines did not execute downloaded binaries; submit file hash to local EDR for validation without launching.",
                effort="LOW",
                coverage="Prevents execution of untrusted installers on local workstations."
            ))

        # 4.1 SQL Injection Remediation Playbook
        if "union select" in str(indicators).lower() or "' or" in str(indicators).lower() or "--" in str(indicators).lower():
            recommendations.append(RecommendationItem(
                priority="CRITICAL",
                title="Implement Parameterized Queries / Prepared Statements",
                reason="Direct string concatenation into database queries enables unauthorized data exfiltration.",
                action="Refactor dynamic SQL queries to use parameterized prepared statements (e.g., PDO, SQLAlchemy, or ORM interfaces). Never concatenate raw user input into query buffers.",
                effort="LOW",
                coverage="Neutralizes 100% of classic SQL injection attack vectors across the database layer."
            ))

        # 4.2 Cross-Site Scripting (XSS) Remediation Playbook
        if "<script" in str(indicators).lower() or "javascript:" in str(indicators).lower() or "alert(" in str(indicators).lower():
            recommendations.append(RecommendationItem(
                priority="HIGH",
                title="Enforce Context-Aware Output Encoding & Strict CSP",
                reason="Unsanitized user parameters reflected into the DOM permit client session hijacking and cookie theft.",
                action="Sanitize dynamic HTML attributes with contextual escaping (e.g., DOMPurify) and deploy a strict Content-Security-Policy (CSP) header: `default-src 'self'`. Disable 'unsafe-inline'.",
                effort="MEDIUM",
                coverage="Prevents unauthorized inline script execution and stops token exfiltration."
            ))

        # 4.3 Sensitive Endpoint Exposure Remediation
        path_str = indicators.get("path", "").lower()
        if any(p in path_str for p in ["actuator", ".env", "wp-config", "metrics", "swagger"]):
            recommendations.append(RecommendationItem(
                priority="HIGH",
                title="Restrict Diagnostic & Environment Routes via Perimeter ACL",
                reason="Production frameworks exposing internal actuator endpoints or env files leak infrastructure configuration.",
                action="Block external access to diagnostic routes at the reverse proxy (Nginx / Cloudflare). Bind internal management endpoints exclusively to localhost (127.0.0.1) or private VPC subnets.",
                effort="LOW",
                coverage="Prevents external attackers from profiling server credentials, JVM memory, or environment secrets."
            ))

        # 5. Low Risk / Safe Indicators
        if verdict == "SAFE":
            recommendations.append(RecommendationItem(
                priority="INFO",
                title="Maintain standard baseline monitoring",
                reason="Current telemetry indicates standard legitimate operations with no active threat flags.",
                action="No immediate blocking required. Continue normal security telemetry logging.",
                effort="LOW",
                coverage="Maintains standard network operations without operational disruption."
            ))

        # 6. Unknown State
        if verdict == "UNKNOWN":
            recommendations.append(RecommendationItem(
                priority="MEDIUM",
                title="Exercise caution — verify indicator out-of-band",
                reason="Insufficient threat intelligence was available to verify domain safety.",
                action="Do not provide corporate credentials or install binaries until secondary threat intelligence sources corroborate safety.",
                effort="LOW",
                coverage="Protects against zero-day or newly registered malicious infrastructure."
            ))

        return recommendations


recommendation_engine = RecommendationEngine()
