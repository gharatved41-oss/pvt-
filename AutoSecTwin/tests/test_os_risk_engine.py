"""Automated unit tests for the deterministic OS risk scoring engine."""

import pytest
from app.schemas.os_assessment import OSRiskLevel
from app.schemas.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingCreate,
    OSFindingType,
    OSSeverity,
)
from app.services.os_matcher.vulnerability_matcher import MatchingEvaluationReport
from app.services.os_risk_engine.engine import (
    OSRiskEngine,
    OSRiskEvaluationResult,
)


@pytest.fixture
def risk_engine() -> OSRiskEngine:
    return OSRiskEngine()


@pytest.fixture
def sample_critical_cve() -> OSFindingCreate:
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
def sample_medium_misconfig() -> OSFindingCreate:
    return OSFindingCreate(
        finding_type=OSFindingType.MISCONFIGURATION,
        advisory_id="CFG-WIN-FIREWALL",
        title="Windows Defender Firewall public profile is disabled",
        component_name="firewall_public",
        installed_version="disabled",
        severity=OSSeverity.MEDIUM,
        confidence=OSConfidence.HIGH,
        exploitability=OSExploitability.UNKNOWN,
        match_basis="registry_configuration_probe",
    )


def test_clean_system_scores_zero(risk_engine: OSRiskEngine) -> None:
    """Verify that a fully assessed clean host with zero findings scores 0 (LOW)."""
    result = risk_engine.evaluate(findings=[])
    assert result.risk_score == 0
    assert result.risk_level == OSRiskLevel.LOW
    assert result.confidence_level == OSConfidence.HIGH
    assert result.exploitability_state == OSExploitability.UNKNOWN
    assert result.is_complete is True


def test_deterministic_scores_identical_inputs(
    risk_engine: OSRiskEngine,
    sample_critical_cve: OSFindingCreate,
    sample_medium_misconfig: OSFindingCreate,
) -> None:
    """Verify that evaluating the exact same findings produces identical deterministic scores."""
    findings = [sample_critical_cve, sample_medium_misconfig]

    res1 = risk_engine.evaluate(findings=findings)
    res2 = risk_engine.evaluate(findings=findings)

    assert res1.risk_score == res2.risk_score
    assert res1.risk_level == res2.risk_level
    assert res1.vulnerability_subscore == res2.vulnerability_subscore
    assert res1.misconfiguration_subscore == res2.misconfiguration_subscore
    assert res1.score_rationale == res2.score_rationale


def test_different_risk_conditions_produce_stratified_scores(
    risk_engine: OSRiskEngine,
    sample_critical_cve: OSFindingCreate,
    sample_medium_misconfig: OSFindingCreate,
) -> None:
    """Verify that different risk conditions produce logically stratified scores."""
    # 1. Clean
    clean_res = risk_engine.evaluate([])

    # 2. Medium misconfiguration only
    med_res = risk_engine.evaluate([sample_medium_misconfig])

    # 3. Critical CVE only
    crit_res = risk_engine.evaluate([sample_critical_cve])

    # 4. Critical CVE + misconfiguration + public exposure
    combined_res = risk_engine.evaluate(
        [sample_critical_cve, sample_medium_misconfig],
        context={"is_public_facing": True},
    )

    assert clean_res.risk_score == 0
    assert 10 <= med_res.risk_score < 30
    assert crit_res.risk_score >= 35
    assert combined_res.risk_score > crit_res.risk_score
    assert combined_res.risk_level in (OSRiskLevel.HIGH, OSRiskLevel.CRITICAL)


def test_incomplete_assessment_applies_uncertainty_floor(risk_engine: OSRiskEngine) -> None:
    """Verify that provider timeouts or missing sources never result in a false clean rating."""
    mock_report = MatchingEvaluationReport(
        findings=[],
        evaluations=[],
        limitations=["Provider 'canonical_usn' timed out after 10s."],
        provider_statuses={"canonical_usn": {"status": "degraded"}},
        is_complete=False,
    )

    # Even with 0 findings, an incomplete assessment must NOT score 0
    result = risk_engine.evaluate(findings=[], matching_report=mock_report)

    assert result.is_complete is False
    assert result.risk_score >= 30, "Uncertainty floor must prevent false low risk"
    assert result.risk_level != OSRiskLevel.LOW
    assert result.confidence_level == OSConfidence.LOW
    assert any("uncertainty risk floor" in r.lower() for r in result.score_rationale)
    assert any("timed out" in lim for lim in result.limitations)


def test_exploitability_strictly_unknown(
    risk_engine: OSRiskEngine,
    sample_critical_cve: OSFindingCreate,
) -> None:
    """Verify exploitability state remains strictly UNKNOWN by default."""
    result = risk_engine.evaluate([sample_critical_cve])
    assert result.exploitability_state == OSExploitability.UNKNOWN


def test_duplicate_findings_deduplication(
    risk_engine: OSRiskEngine,
    sample_critical_cve: OSFindingCreate,
) -> None:
    """Verify duplicate findings are deterministically deduplicated and do not multiply the score."""
    # Submit the same finding 3 times
    duplicate_findings = [sample_critical_cve, sample_critical_cve, sample_critical_cve]

    res_single = risk_engine.evaluate([sample_critical_cve])
    res_dup = risk_engine.evaluate(duplicate_findings)

    assert res_single.risk_score == res_dup.risk_score
    assert res_single.vulnerability_subscore == res_dup.vulnerability_subscore


def test_confidence_multipliers_reduce_uncertain_findings(risk_engine: OSRiskEngine) -> None:
    """Verify LOW confidence findings (e.g. unpatched/missing evidence) contribute less than HIGH confidence."""
    high_conf = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2023-1111",
        title="High confidence flaw",
        component_name="pkg-a",
        installed_version="1.0",
        fixed_version="1.1",
        severity=OSSeverity.HIGH,
        confidence=OSConfidence.HIGH,
    )
    low_conf = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2023-1111",
        title="Low confidence flaw (no fixed version)",
        component_name="pkg-a",
        installed_version="1.0",
        fixed_version=None,
        severity=OSSeverity.HIGH,
        confidence=OSConfidence.LOW,
    )

    res_high = risk_engine.evaluate([high_conf])
    res_low = risk_engine.evaluate([low_conf])

    assert res_high.risk_score > res_low.risk_score
    assert res_low.confidence_level == OSConfidence.LOW


def test_context_modifiers_increase_score(
    risk_engine: OSRiskEngine,
    sample_medium_misconfig: OSFindingCreate,
) -> None:
    """Verify asset context (e.g. public network exposure) properly modifies the composite score."""
    res_internal = risk_engine.evaluate([sample_medium_misconfig], context={"is_public_facing": False})
    res_public = risk_engine.evaluate([sample_medium_misconfig], context={"is_public_facing": True})

    assert res_public.risk_score == res_internal.risk_score + 10
    assert any("public-facing" in r for r in res_public.score_rationale)


def test_risk_tier_boundaries(risk_engine: OSRiskEngine) -> None:
    """Verify exact risk-tier boundaries: LOW (0-19), MEDIUM (20-49), HIGH (50-79), CRITICAL (80-100)."""
    # 0 finding -> score 0 -> LOW
    assert risk_engine.evaluate([]).risk_level == OSRiskLevel.LOW

    # Single LOW finding without CVSS: 5.0 * 1.0 = 5.0 -> score 5 -> LOW
    low_finding = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2023-LOW",
        title="Low flaw",
        component_name="pkg-low",
        severity=OSSeverity.LOW,
        confidence=OSConfidence.HIGH,
    )
    res_low = risk_engine.evaluate([low_finding])
    assert res_low.risk_score == 5
    assert res_low.risk_level == OSRiskLevel.LOW

    # Boundary test: Score clamped between 0 and 100
    # Create 10 Critical CVEs with high CVSS + context modifiers to test upper clamp
    critical_findings = [
        OSFindingCreate(
            finding_type=OSFindingType.CVE_VULNERABILITY,
            advisory_id=f"CVE-2024-{i:04d}",
            title=f"Critical flaw {i}",
            component_name=f"pkg-{i}",
            severity=OSSeverity.CRITICAL,
            cvss_score=10.0,
            confidence=OSConfidence.HIGH,
        )
        for i in range(10)
    ]
    res_overflow = risk_engine.evaluate(
        critical_findings,
        context={"is_public_facing": True, "has_unrestricted_inbound_ports": True},
    )
    assert res_overflow.risk_score <= 100
    assert res_overflow.risk_score == 90  # 75.0 (cve cap) + 15.0 (context)
    assert res_overflow.risk_level == OSRiskLevel.CRITICAL


def test_malformed_cvss_inputs_cannot_distort_score(risk_engine: OSRiskEngine) -> None:
    """Verify NaN, inf, negative, and excessive CVSS values do not crash or corrupt score."""
    import math

    # Case 1: NaN CVSS (constructed via model_construct to simulate unvalidated/bypassed input)
    nan_finding = OSFindingCreate.model_construct(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2024-NAN",
        title="NaN CVSS flaw",
        component_name="pkg-nan",
        severity=OSSeverity.HIGH,
        cvss_score=float("nan"),
        confidence=OSConfidence.HIGH,
    )
    res_nan = risk_engine.evaluate([nan_finding])
    assert not math.isnan(res_nan.risk_score)
    assert 0 <= res_nan.risk_score <= 100
    assert res_nan.risk_score == 25  # Falls back to base HIGH weight 25.0

    # Case 2: Negative CVSS
    neg_finding = OSFindingCreate.model_construct(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2024-NEG",
        title="Negative CVSS flaw",
        component_name="pkg-neg",
        severity=OSSeverity.MEDIUM,
        cvss_score=-5.0,
        confidence=OSConfidence.HIGH,
    )
    res_neg = risk_engine.evaluate([neg_finding])
    assert res_neg.risk_score == 12  # Falls back to base MEDIUM weight 12.0

    # Case 3: Overflow CVSS (> 10.0)
    overflow_finding = OSFindingCreate.model_construct(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2024-OVER",
        title="Overflow CVSS flaw",
        component_name="pkg-over",
        severity=OSSeverity.HIGH,
        cvss_score=999.0,
        confidence=OSConfidence.HIGH,
    )
    res_over = risk_engine.evaluate([overflow_finding])
    # Clamped to 10.0 -> min(30.0, max(20.0, 10.0 * 2.8)) = 28.0 -> 28 pts
    assert res_over.risk_score == 28


def test_inconsistent_severity_and_cvss_bounded(risk_engine: OSRiskEngine) -> None:
    """Verify that an inconsistent CVSS (e.g. CVSS 10.0 on LOW severity) cannot break out of its tier."""
    inconsistent_low = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="CVE-2024-LOW-HIGH-CVSS",
        title="Low severity but CVSS 10.0",
        component_name="pkg-low",
        severity=OSSeverity.LOW,
        cvss_score=10.0,
        confidence=OSConfidence.HIGH,
    )
    res = risk_engine.evaluate([inconsistent_low])
    # LOW tier max is bounded to 8.0 pts
    assert res.risk_score == 8
    assert res.risk_level == OSRiskLevel.LOW


def test_duplicate_findings_with_different_version_metadata(risk_engine: OSRiskEngine) -> None:
    """Verify findings with same advisory_id and component are deduplicated even with different version metadata."""
    f1 = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="USN-6409-1",
        title="GLIBC flaw",
        component_name="libc6",
        installed_version="2.35-0ubuntu3.1",
        fixed_version="2.35-0ubuntu3.4",
        severity=OSSeverity.CRITICAL,
        cvss_score=9.8,
    )
    f2 = OSFindingCreate(
        finding_type=OSFindingType.CVE_VULNERABILITY,
        advisory_id="USN-6409-1",
        title="GLIBC flaw duplicate",
        component_name="libc6",
        installed_version=None,
        fixed_version=None,
        severity=OSSeverity.CRITICAL,
        cvss_score=9.8,
    )

    res_single = risk_engine.evaluate([f1])
    res_merged = risk_engine.evaluate([f1, f2])

    assert res_single.risk_score == res_merged.risk_score
    assert len(res_merged.top_contributing_findings) == 1


def test_missing_inventory_and_stale_evidence_triggers_uncertainty_floor(risk_engine: OSRiskEngine) -> None:
    """Verify that missing inventories or stale evidence in context trigger the uncertainty floor."""
    # Clean findings but missing inventory context
    res_missing_inv = risk_engine.evaluate([], context={"missing_inventory": True})
    assert res_missing_inv.risk_score >= 30
    assert res_missing_inv.is_complete is False
    assert res_missing_inv.confidence_level == OSConfidence.LOW
    assert any("inventory missing" in lim.lower() for lim in res_missing_inv.limitations)

    # Clean findings but stale evidence context
    res_stale = risk_engine.evaluate([], context={"evidence_stale": True})
    assert res_stale.risk_score >= 30
    assert res_stale.is_complete is False
    assert res_stale.confidence_level == OSConfidence.LOW
    assert any("stale evidence" in lim.lower() for lim in res_stale.limitations)


def test_public_exposure_strictly_requires_boolean_true(risk_engine: OSRiskEngine) -> None:
    """Verify public-exposure modifiers are applied only when supported by boolean True evidence."""
    finding = OSFindingCreate(
        finding_type=OSFindingType.MISCONFIGURATION,
        advisory_id="CFG-WIN-FIREWALL",
        title="Firewall disabled",
        component_name="firewall",
        severity=OSSeverity.MEDIUM,
    )

    # String "false" must NOT add 10 points
    res_str_false = risk_engine.evaluate([finding], context={"is_public_facing": "false"})
    # Non-boolean empty dict must NOT add 10 points
    res_none = risk_engine.evaluate([finding], context={"is_public_facing": None})
    # Boolean True DOES add 10 points
    res_bool_true = risk_engine.evaluate([finding], context={"is_public_facing": True})

    assert res_str_false.risk_score == res_none.risk_score
    assert res_bool_true.risk_score == res_none.risk_score + 10

