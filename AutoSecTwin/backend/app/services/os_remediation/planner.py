"""Explainable OS remediation planner.

Translates confirmed vulnerabilities and system security weaknesses into
actionable, vendor-supported remediation recommendations with transparent
rationales, impact analyses, and verification steps.

Safety Policy:
- Recommendation only: NEVER executes commands or alters host OS configuration.
- Clearly distinguishes confirmed vendor fixes from unpatched or uncertain items.
- Avoids inventing unsupported fixes when evidence is insufficient.
"""

from typing import Any, Dict, List, Optional
from app.schemas.os_finding import (
    OSConfidence,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)
from app.schemas.os_remediation import (
    ActionCategory,
    OSRemediationPlan,
    OSRemediationRecommendation,
)


class OSRemediationPlanner:
    """Generates structured, explainable remediation recommendations for OS assessments."""

    # Curated authoritative vendor configuration guidance
    CONFIG_GUIDANCE: Dict[str, Dict[str, Any]] = {
        "CFG-WIN-DEFENDER": {
            "title": "Enable Microsoft Defender Antivirus Real-Time Protection",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Enable Microsoft Defender Real-Time Protection via Windows Security Center or Group Policy ('Turn off Windows Defender' = Disabled).",
            "security_benefit": "Restores behavioral monitoring and on-access scanning to intercept malicious binaries before execution.",
            "operational_impact": "Negligible. May cause minor I/O latency during large builds or bulk file transfers.",
            "prerequisites": ["Ensure no conflicting enterprise third-party antivirus is managing endpoint protection."],
            "verification_steps": ["Open Windows Security > Virus & threat protection and verify 'Real-time protection' is On."],
            "documentation_urls": [
                "https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus"
            ],
        },
        "CFG-WIN-FIREWALL": {
            "title": "Enable Windows Defender Firewall on All Profiles",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Enable the Windows Defender Firewall for Domain, Private, and Public network profiles.",
            "security_benefit": "Prevents unauthorized inbound connections and limits lateral movement across local network segments.",
            "operational_impact": "Existing network applications may prompt for permission if listening on non-standard ports.",
            "prerequisites": ["Verify any necessary business inbound ports are documented in custom firewall rules."],
            "verification_steps": ["Check 'Windows Defender Firewall with Advanced Security' console to verify all profiles are Active."],
            "documentation_urls": [
                "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/"
            ],
        },
        "CFG-WIN-UAC": {
            "title": "Enforce User Account Control (UAC) Elevation Prompts",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Configure UAC to prompt for consent on the secure desktop (ConsentPromptBehaviorAdmin = 5).",
            "security_benefit": "Blocks silent administrative privilege escalation by untrusted background processes.",
            "operational_impact": "Administrative tasks will require explicit interactive consent dialogs.",
            "prerequisites": ["Ensure primary user account has administrative elevation credentials."],
            "verification_steps": ["Open 'Change User Account Control settings' and confirm slider is at 'Notify me only when apps try to make changes' or higher."],
            "documentation_urls": [
                "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/"
            ],
        },
        "CFG-WIN-RDP": {
            "title": "Require Network Level Authentication (NLA) for Remote Desktop",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Enable Network Level Authentication for Remote Desktop (UserAuthentication = 1).",
            "security_benefit": "Mandates client pre-authentication before establishing an RDP session, mitigating remote code execution flaws (e.g. BlueKeep).",
            "operational_impact": "Legacy RDP clients lacking CredSSP support will be unable to connect.",
            "prerequisites": ["Ensure all connecting client devices support Credential Security Support Provider (CredSSP)."],
            "verification_steps": ["Open System Properties > Remote tab and confirm 'Allow connections only from computers running Remote Desktop with Network Level Authentication' is checked."],
            "documentation_urls": [
                "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
            ],
        },
        "CFG-LINUX-ASLR": {
            "title": "Enable Full Linux Address Space Layout Randomization (ASLR)",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Set 'kernel.randomize_va_space = 2' in '/etc/sysctl.d/99-security-aslr.conf' and reload sysctl.",
            "security_benefit": "Randomizes heap, stack, and memory mappings to thwart return-oriented programming (ROP) and buffer overflow exploitation.",
            "operational_impact": "Negligible. Supported natively by modern Linux kernels without application disruption.",
            "prerequisites": ["Root privileges to edit sysctl configuration."],
            "verification_steps": ["Run 'cat /proc/sys/kernel/randomize_va_space' and confirm output is '2'."],
            "documentation_urls": [
                "https://wiki.debian.org/Hardening#Address_Space_Layout_Randomization_.28ASLR.29"
            ],
        },
        "CFG-LINUX-SSHD": {
            "title": "Disable Direct Root Login Over SSH",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Set 'PermitRootLogin no' in '/etc/ssh/sshd_config' (or '/etc/ssh/sshd_config.d/') and restart sshd.",
            "security_benefit": "Prevents automated brute-force attacks against the root account; enforces auditability via sudo.",
            "operational_impact": "Administrators must connect via an unprivileged account and elevate using 'sudo'.",
            "prerequisites": ["Verify at least one non-root user account has functional sudo/wheel privileges before restarting sshd."],
            "verification_steps": ["Test SSH connection with an unprivileged account in a separate session; confirm 'ssh root@host' is rejected."],
            "documentation_urls": [
                "https://ubuntu.com/server/docs/openssh-server"
            ],
        },
        "CFG-LINUX-IPFWD": {
            "title": "Disable IPv4 Packet Forwarding on Non-Router Host",
            "action_category": ActionCategory.SECURITY_CONFIGURATION,
            "suggested_action": "Set 'net.ipv4.ip_forward = 0' in '/etc/sysctl.d/99-security-ipforward.conf' and reload sysctl.",
            "security_benefit": "Prevents the host from forwarding network packets between interfaces, reducing risk of multi-homed traffic bridging.",
            "operational_impact": "Do not apply if the machine acts as a VPN gateway, container router, or virtual switch.",
            "prerequisites": ["Confirm the system is an endpoint and not a dedicated router, gateway, or Docker NAT host."],
            "verification_steps": ["Run 'cat /proc/sys/net/ipv4/ip_forward' and confirm output is '0'."],
            "documentation_urls": [
                "https://wiki.debian.org/Hardening#Network"
            ],
        },
    }

    def generate_plan(
        self,
        findings: List[OSFindingCreate],
        assessment_id: Optional[str] = None,
        limitations: Optional[List[str]] = None,
    ) -> OSRemediationPlan:
        """Generate an explainable, prioritised remediation plan from assessment findings.

        Args:
            findings: List of identified findings (CVEs, misconfigurations).
            assessment_id: Optional assessment identifier.
            limitations: Optional list of assessment limitations or missing data warnings.

        Returns:
            OSRemediationPlan with detailed, actionable recommendations.
        """
        recs: List[OSRemediationRecommendation] = []
        verified_count = 0
        investigation_count = 0

        # Sort findings by severity (Critical first)
        severity_rank = {
            OSSeverity.CRITICAL: 0,
            OSSeverity.HIGH: 1,
            OSSeverity.MEDIUM: 2,
            OSSeverity.LOW: 3,
            OSSeverity.UNRATED: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 4))

        for idx, finding in enumerate(sorted_findings, start=1):
            rec_id = f"REC-{idx:03d}"

            if finding.finding_type == OSFindingType.CVE_VULNERABILITY:
                rec = self._plan_cve_remediation(rec_id, finding)
            elif finding.finding_type == OSFindingType.MISCONFIGURATION:
                rec = self._plan_misconfig_remediation(rec_id, finding)
            else:
                rec = self._plan_generic_remediation(rec_id, finding)

            if rec.is_verified_fix:
                verified_count += 1
            else:
                investigation_count += 1

            recs.append(rec)

        summary = (
            f"Remediation plan generated {len(recs)} actionable recommendations "
            f"({verified_count} with confirmed vendor fixes, {investigation_count} requiring manual investigation/unpatched mitigation). "
            f"All recommendations are advisory proposals and have NOT been executed on the host."
        )

        return OSRemediationPlan(
            assessment_id=assessment_id,
            recommendations=recs,
            total_recommendations=len(recs),
            verified_fix_count=verified_count,
            investigation_required_count=investigation_count,
            remediation_summary=summary,
            limitations=limitations or [],
        )

    def _plan_cve_remediation(
        self,
        rec_id: str,
        finding: OSFindingCreate,
    ) -> OSRemediationRecommendation:
        """Create structured recommendation for a CVE vulnerability finding."""
        cve_id = finding.advisory_id
        pkg = finding.component_name
        installed = finding.installed_version or "observed"
        fixed = finding.fixed_version

        # Case 1: Advisory publishes no fixed version (unpatched / 0-day)
        if not fixed:
            return OSRemediationRecommendation(
                recommendation_id=rec_id,
                finding_ref=cve_id,
                advisory_id=cve_id,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                component_name=pkg,
                title=f"Investigate unpatched vulnerability {cve_id} in {pkg}",
                rationale=f"Vulnerability {cve_id} affects {pkg} ({installed}), but no official vendor fixed version has been published yet.",
                supporting_evidence=f"Installed version '{installed}' matches advisory bulletin; fixed_version is unrecorded upstream.",
                action_category=ActionCategory.MANUAL_INVESTIGATION,
                suggested_action=f"No authoritative upstream fix has been released for {pkg}. Monitor vendor security bulletins, restrict external network access to {pkg}, or evaluate vendor workarounds.",
                security_benefit=f"Limits exposure window for {cve_id} while vendor patch is in development.",
                operational_impact="Restricting component access or disabling related features may impact dependent workflows.",
                prerequisites=["Consult vendor security tracker for temporary workarounds."],
                verification_steps=[f"Monitor authoritative security tracker for {pkg} release bulletins."],
                confidence=OSConfidence.LOW,
                is_verified_fix=False,
                uncertainty_notes="Advisory contains no fixed upstream version. Do not install unverified third-party binaries.",
                documentation_urls=[],
            )

        # Case 2: Standard package upgrade with confirmed vendor fix
        doc_urls = []
        if finding.advisory_source == "canonical_usn":
            doc_urls.append(f"https://ubuntu.com/security/notices/{finding.advisory_id}")
        elif finding.advisory_source == "debian_security_tracker":
            doc_urls.append(f"https://security-tracker.debian.org/tracker/{cve_id}")

        return OSRemediationRecommendation(
            recommendation_id=rec_id,
            finding_ref=cve_id,
            advisory_id=finding.advisory_id,
            cve_id=cve_id if cve_id.startswith("CVE-") else None,
            component_name=pkg,
            title=f"Upgrade {pkg} to version {fixed} or later",
            rationale=f"Installed {pkg} version '{installed}' is vulnerable to {cve_id}. Fixed in vendor release '{fixed}'.",
            supporting_evidence=f"Installed version: '{installed}' | Minimum fixed version: '{fixed}' | Severity: {finding.severity.value}",
            action_category=ActionCategory.PACKAGE_UPGRADE,
            suggested_action=f"Upgrade package '{pkg}' to version '{fixed}' or later using the official distribution package manager.",
            security_benefit=f"Eliminates {cve_id} flaw ({finding.title}).",
            operational_impact="May require service restart or system reboot if updating core libraries or system daemons.",
            prerequisites=[
                "Verify repository metadata is updated ('apt update').",
                "Ensure sufficient disk space for package installation.",
            ],
            verification_steps=[
                f"Verify installed version >= '{fixed}' using local package query tools."
            ],
            confidence=finding.confidence,
            is_verified_fix=True,
            uncertainty_notes=None,
            documentation_urls=doc_urls,
        )

    def _plan_misconfig_remediation(
        self,
        rec_id: str,
        finding: OSFindingCreate,
    ) -> OSRemediationRecommendation:
        """Create structured recommendation for a configuration probe finding."""
        rule_id = finding.advisory_id
        guidance = self.CONFIG_GUIDANCE.get(rule_id)

        if guidance:
            return OSRemediationRecommendation(
                recommendation_id=rec_id,
                finding_ref=rule_id,
                advisory_id=rule_id,
                component_name=finding.component_name,
                title=guidance["title"],
                rationale=finding.description or f"Configuration weakness '{rule_id}' detected on {finding.component_name}.",
                supporting_evidence=f"Rule: {rule_id} | Component: {finding.component_name} | Observed: {finding.installed_version or 'Non-compliant'}",
                action_category=guidance["action_category"],
                suggested_action=guidance["suggested_action"],
                security_benefit=guidance["security_benefit"],
                operational_impact=guidance["operational_impact"],
                prerequisites=guidance.get("prerequisites", []),
                verification_steps=guidance.get("verification_steps", []),
                confidence=OSConfidence.HIGH,
                is_verified_fix=True,
                uncertainty_notes=None,
                documentation_urls=guidance.get("documentation_urls", []),
            )

        # Fallback for generic or uncatalogued misconfigurations
        return OSRemediationRecommendation(
            recommendation_id=rec_id,
            finding_ref=rule_id,
            advisory_id=rule_id,
            component_name=finding.component_name,
            title=f"Harden security configuration for {finding.component_name}",
            rationale=finding.description or f"Non-compliant setting identified by rule {rule_id}.",
            supporting_evidence=f"Component: {finding.component_name} | Rule: {rule_id}",
            action_category=ActionCategory.SECURITY_CONFIGURATION,
            suggested_action=f"Review and adjust {finding.component_name} configuration according to vendor security benchmarks.",
            security_benefit="Hardens host defense-in-depth posture.",
            operational_impact="Ensure dependent services continue to function after configuration change.",
            prerequisites=["Review current configuration backup."],
            verification_steps=["Re-run security configuration probe to confirm compliance."],
            confidence=OSConfidence.MEDIUM,
            is_verified_fix=True,
            documentation_urls=[],
        )

    def _plan_generic_remediation(
        self,
        rec_id: str,
        finding: OSFindingCreate,
    ) -> OSRemediationRecommendation:
        """Fallback recommendation generator for generic findings."""
        return OSRemediationRecommendation(
            recommendation_id=rec_id,
            finding_ref=finding.advisory_id,
            advisory_id=finding.advisory_id,
            component_name=finding.component_name,
            title=f"Review security finding {finding.advisory_id}",
            rationale=finding.description or "Unclassified security finding.",
            supporting_evidence=f"Component: {finding.component_name} | Type: {finding.finding_type.value}",
            action_category=ActionCategory.MANUAL_INVESTIGATION,
            suggested_action=f"Investigate {finding.component_name} against security baselines.",
            security_benefit="Clarifies potential security exposure.",
            operational_impact="Low.",
            confidence=OSConfidence.LOW,
            is_verified_fix=False,
            uncertainty_notes="Generic finding without specific vendor remediation mapping.",
        )
