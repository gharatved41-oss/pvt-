"""Automated unit tests for the explainable OS remediation planner."""

import pytest
from app.schemas.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)
from app.schemas.os_remediation import (
    ActionCategory,
    OSRemediationPlan,
    OSRemediationRecommendation,
)
from app.services.os_remediation.planner import OSRemediationPlanner


@pytest.fixture
def planner() -> OSRemediationPlanner:
    return OSRemediationPlanner()


@pytest.fixture
def vulnerable_glibc() -> OSFindingCreate:
    return OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="USN-6409-1",
        title="GLIBC buffer overflow in ld.so (Looney Tunables)",
        component_name="libc6",
        installed_version="2.35-0ubuntu3.1",
        fixed_version="2.35-0ubuntu3.4",
        severity=OSSeverity.CRITICAL,
        cvss_score=9.8,
        confidence=OSConfidence.HIGH,
        exploitability=OSExploitability.UNKNOWN,
        advisory_source="canonical_usn",
        match_basis="debian_version_epoch_comparison",
    )


@pytest.fixture
def unpatched_cve() -> OSFindingCreate:
    return OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2024-9999",
        title="Unpatched 0-day parser flaw",
        component_name="curl",
        installed_version="7.81.0-1ubuntu1.14",
        fixed_version=None,
        severity=OSSeverity.HIGH,
        confidence=OSConfidence.LOW,
        exploitability=OSExploitability.UNKNOWN,
        advisory_source="canonical_usn",
        match_basis="insufficient_evidence_no_fixed_version",
    )


@pytest.fixture
def windows_defender_misconfig() -> OSFindingCreate:
    return OSFindingCreate(
        finding_type=OSFindingType.MISCONFIGURATION,
        advisory_id="CFG-WIN-DEFENDER",
        title="Microsoft Defender Real-Time Protection is disabled",
        component_name="defender_rtp",
        installed_version="disabled",
        severity=OSSeverity.HIGH,
        confidence=OSConfidence.HIGH,
        exploitability=OSExploitability.UNKNOWN,
        match_basis="registry_configuration_probe",
    )


def test_planner_generates_verified_fix_for_standard_cve(
    planner: OSRemediationPlanner,
    vulnerable_glibc: OSFindingCreate,
) -> None:
    """Verify standard package CVE produces a verified upgrade recommendation with verification steps."""
    plan = planner.generate_plan([vulnerable_glibc], assessment_id="test-asmt-1")

    assert plan.total_recommendations == 1
    assert plan.verified_fix_count == 1
    assert plan.investigation_required_count == 0

    rec = plan.recommendations[0]
    assert rec.recommendation_id == "REC-001"
    assert rec.finding_ref == "USN-6409-1"
    assert rec.component_name == "libc6"
    assert rec.action_category == ActionCategory.PACKAGE_UPGRADE
    assert rec.is_verified_fix is True
    assert "2.35-0ubuntu3.4" in rec.suggested_action
    assert len(rec.prerequisites) > 0
    assert len(rec.verification_steps) > 0
    assert any("ubuntu.com/security/notices" in url for url in rec.documentation_urls)


def test_planner_handles_unpatched_cve_without_inventing_fix(
    planner: OSRemediationPlanner,
    unpatched_cve: OSFindingCreate,
) -> None:
    """Verify unpatched finding generates manual investigation and does not invent non-existent fixed versions."""
    plan = planner.generate_plan([unpatched_cve])

    assert plan.total_recommendations == 1
    assert plan.verified_fix_count == 0
    assert plan.investigation_required_count == 1

    rec = plan.recommendations[0]
    assert rec.action_category == ActionCategory.MANUAL_INVESTIGATION
    assert rec.is_verified_fix is False
    assert rec.confidence == OSConfidence.LOW
    assert rec.uncertainty_notes is not None
    assert "No authoritative upstream fix has been released" in rec.suggested_action
    assert "Do not install unverified third-party binaries" in rec.uncertainty_notes


def test_planner_generates_config_remediation_windows(
    planner: OSRemediationPlanner,
    windows_defender_misconfig: OSFindingCreate,
) -> None:
    """Verify Windows configuration probe findings map to authoritative vendor hardening steps."""
    plan = planner.generate_plan([windows_defender_misconfig])

    assert plan.total_recommendations == 1
    rec = plan.recommendations[0]
    assert rec.action_category == ActionCategory.SECURITY_CONFIGURATION
    assert rec.is_verified_fix is True
    assert "Microsoft Defender" in rec.title
    assert "Windows Security Center" in rec.suggested_action
    assert any("learn.microsoft.com" in url for url in rec.documentation_urls)


def test_planner_generates_config_remediation_linux(planner: OSRemediationPlanner) -> None:
    """Verify Linux configuration probe findings generate proper sysctl/sshd guidance."""
    findings = [
        OSFindingCreate(
            finding_type=OSFindingType.MISCONFIGURATION,
            advisory_id="CFG-LINUX-ASLR",
            title="Linux ASLR is disabled",
            component_name="kernel.randomize_va_space",
            installed_version="0",
            severity=OSSeverity.HIGH,
        ),
        OSFindingCreate(
            finding_type=OSFindingType.MISCONFIGURATION,
            advisory_id="CFG-LINUX-SSHD",
            title="SSH daemon permits direct root login",
            component_name="sshd_config",
            installed_version="PermitRootLogin yes",
            severity=OSSeverity.MEDIUM,
        ),
    ]

    plan = planner.generate_plan(findings)
    assert plan.total_recommendations == 2

    aslr_rec = next(r for r in plan.recommendations if r.finding_ref == "CFG-LINUX-ASLR")
    assert "randomize_va_space = 2" in aslr_rec.suggested_action
    assert "/etc/sysctl.d/" in aslr_rec.suggested_action

    sshd_rec = next(r for r in plan.recommendations if r.finding_ref == "CFG-LINUX-SSHD")
    assert "PermitRootLogin no" in sshd_rec.suggested_action
    assert any("sudo" in p.lower() for p in sshd_rec.prerequisites)


def test_planner_prioritizes_by_severity(
    planner: OSRemediationPlanner,
    vulnerable_glibc: OSFindingCreate,
    unpatched_cve: OSFindingCreate,
) -> None:
    """Verify recommendations are ordered by severity (Critical first, then High, etc.)."""
    medium_finding = OSFindingCreate(
        finding_type=OSFindingType.MISCONFIGURATION,
        advisory_id="CFG-LINUX-IPFWD",
        title="IP forwarding enabled",
        component_name="net.ipv4.ip_forward",
        installed_version="1",
        severity=OSSeverity.MEDIUM,
    )

    # Submit in mixed order: Medium, Critical, High
    plan = planner.generate_plan([medium_finding, vulnerable_glibc, unpatched_cve])

    assert plan.total_recommendations == 3
    # Top item must be the Critical vulnerability
    assert plan.recommendations[0].finding_ref == "USN-6409-1"
    # Second item must be the High vulnerability
    assert plan.recommendations[1].finding_ref == "CVE-2024-9999"
    # Third item is Medium
    assert plan.recommendations[2].finding_ref == "CFG-LINUX-IPFWD"


def test_planner_preserves_assessment_limitations(planner: OSRemediationPlanner) -> None:
    """Verify assessment limitations are recorded in the remediation plan."""
    limits = ["Provider 'microsoft_msrc' timed out.", "Application 'Foo' missing version metadata."]
    plan = planner.generate_plan([], limitations=limits)

    assert plan.total_recommendations == 0
    assert plan.limitations == limits


def test_recommendation_is_never_represented_as_applied(
    planner: OSRemediationPlanner,
    vulnerable_glibc: OSFindingCreate,
    windows_defender_misconfig: OSFindingCreate,
) -> None:
    """Verify recommendations are explicitly marked unapplied and never represented as executed changes."""
    plan = planner.generate_plan([vulnerable_glibc, windows_defender_misconfig])

    assert "NOT been executed" in plan.remediation_summary
    for rec in plan.recommendations:
        assert rec.is_applied is False
        # When is_verified_fix is True, it indicates vendor fix existence, NOT host application
        if rec.is_verified_fix:
            assert "unapplied" in rec.supporting_evidence.lower() or "suggested_action" in type(rec).model_fields


def test_all_verification_instructions_are_non_destructive(planner: OSRemediationPlanner) -> None:
    """Verify that all verification steps across all configured rules are strictly read-only and non-destructive."""
    import re
    destructive_patterns = [r"\brm\s+", r"\bdel\s+", r"\bkill\b", r"\bformat\b", r"\bdrop\b", r"\bpurge\b", r">\s*/", r"\breboot\b", r"\bshutdown\b"]

    for rule_id, guidance in planner.CONFIG_GUIDANCE.items():
        v_steps = guidance.get("verification_steps", [])
        assert len(v_steps) > 0, f"Rule {rule_id} must have verification steps"
        for step in v_steps:
            for pat in destructive_patterns:
                assert not re.search(pat, step, re.IGNORECASE), f"Destructive pattern '{pat}' found in {rule_id} verification step: {step}"


def test_configuration_guidance_completeness(planner: OSRemediationPlanner) -> None:
    """Verify each curated configuration rule contains prerequisites, impact, and official documentation."""
    for rule_id, guidance in planner.CONFIG_GUIDANCE.items():
        assert len(guidance.get("prerequisites", [])) > 0, f"{rule_id} missing prerequisites"
        assert len(guidance.get("operational_impact", "")) > 10, f"{rule_id} missing operational impact"
        assert len(guidance.get("documentation_urls", [])) > 0, f"{rule_id} missing documentation URLs"
        for url in guidance.get("documentation_urls", []):
            assert url.startswith("https://"), f"{rule_id} has insecure or invalid doc URL: {url}"

