"""Automated unit tests for Milestone 1: Dedicated OS Security models, schemas, and lifecycle."""

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from app.models.os_asset import OSAssetRecord
from app.models.os_assessment import OSAssessmentRecord, OSAssessmentStatus
from app.models.os_evidence import OSEvidenceRecord, OSEvidenceStatus, OSPermissionState
from app.models.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingRecord,
    OSFindingType,
    OSSeverity,
)
from app.schemas.os_assessment import (
    OSAssetResponse,
    OSAssessmentDetailResponse,
    OSAssessmentResponse,
)
from app.schemas.os_evidence import OSEvidenceItemResponse
from app.schemas.os_finding import OSFindingResponse


def test_dedicated_os_tables_created(db_session: Session) -> None:
    """Verify that all dedicated OS tables exist in SQLite alongside legacy tables."""
    inspector = inspect(db_session.bind)
    table_names = inspector.get_table_names()

    # Legacy tables must remain intact
    assert "analyses" in table_names
    assert "security_evidence" in table_names

    # Dedicated OS tables must exist
    assert "os_assets" in table_names
    assert "os_assessments" in table_names
    assert "os_evidence" in table_names
    assert "os_findings" in table_names


def test_os_asset_creation_and_attributes(db_session: Session) -> None:
    """Verify creating and persisting an OSAssetRecord with hardware & OS metadata."""
    asset = OSAssetRecord(
        host_identifier="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hostname="secops-workstation",
        os_family="linux",
        os_name="Ubuntu 22.04.4 LTS",
        os_version="22.04",
        os_build="6.5.0-28-generic",
        architecture="x86_64",
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    assert asset.id is not None
    assert len(asset.id) == 36
    assert asset.hostname == "secops-workstation"
    assert asset.os_family == "linux"
    assert asset.architecture == "x86_64"
    assert asset.collected_at is not None


def test_os_assessment_state_machine_valid_transitions() -> None:
    """Verify that valid state machine transitions are permitted."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.PENDING.value)
    assert assessment.can_transition_to(OSAssessmentStatus.RUNNING.value) is True
    assert assessment.can_transition_to(OSAssessmentStatus.FAILED.value) is True

    assessment.status = OSAssessmentStatus.RUNNING.value
    assert assessment.can_transition_to(OSAssessmentStatus.COMPLETED.value) is True
    assert assessment.can_transition_to(OSAssessmentStatus.FAILED.value) is True


def test_os_assessment_state_machine_invalid_transitions() -> None:
    """Verify that illegal transitions are strictly rejected by the state machine."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.PENDING.value)
    # Direct jump from pending to completed is invalid
    assert assessment.can_transition_to(OSAssessmentStatus.COMPLETED.value) is False

    assessment.status = OSAssessmentStatus.COMPLETED.value
    # Completed is a terminal state
    assert assessment.can_transition_to(OSAssessmentStatus.RUNNING.value) is False
    assert assessment.can_transition_to(OSAssessmentStatus.PENDING.value) is False
    assert assessment.can_transition_to(OSAssessmentStatus.FAILED.value) is False

    assessment.status = OSAssessmentStatus.FAILED.value
    # Failed is a terminal state
    assert assessment.can_transition_to(OSAssessmentStatus.RUNNING.value) is False
    assert assessment.can_transition_to(OSAssessmentStatus.COMPLETED.value) is False


def test_exploitability_strictly_defaults_to_unknown(db_session: Session) -> None:
    """Verify that exploitability state strictly defaults to 'unknown' in models and schemas."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.PENDING.value)
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(assessment)

    assert assessment.exploitability_state == OSExploitability.UNKNOWN.value

    # Verify Finding exploitability default
    finding = OSFindingRecord(
        assessment_id=assessment.id,
        finding_type=OSFindingType.CVE_VULNERABILITY.value,
        advisory_id="CVE-2023-4911",
        title="ld.so buffer overflow",
        component_name="glibc",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    assert finding.exploitability == OSExploitability.UNKNOWN.value


def test_evidence_explicit_statuses_and_permission_denial(db_session: Session) -> None:
    """Verify explicit evidence collection outcomes, especially UNAVAILABLE due to denied permissions."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.RUNNING.value)
    db_session.add(assessment)
    db_session.commit()

    # Evidence 1: Successfully observed package
    observed_ev = OSEvidenceRecord(
        assessment_id=assessment.id,
        collector_name="linux_dpkg_collector",
        check_id="dpkg_package_inventory",
        signal_name="installed_package",
        observed_value="openssl 3.0.2-0ubuntu1.10",
        structured_data={"package": "openssl", "version": "3.0.2-0ubuntu1.10"},
        collection_status=OSEvidenceStatus.OBSERVED.value,
        permission_state=OSPermissionState.GRANTED.value,
    )

    # Evidence 2: Permission denied on root-only configuration file
    denied_ev = OSEvidenceRecord(
        assessment_id=assessment.id,
        collector_name="linux_ssh_collector",
        check_id="ssh_hardening_check",
        signal_name="ssh_root_login",
        observed_value=None,
        structured_data={"path": "/etc/ssh/sshd_config", "error": "Permission denied"},
        collection_status=OSEvidenceStatus.UNAVAILABLE.value,
        permission_state=OSPermissionState.DENIED.value,
        explanatory_notes="Could not read sshd_config due to file permissions. Audit limitation recorded.",
    )

    db_session.add_all([observed_ev, denied_ev])
    db_session.commit()

    # Retrieve and verify
    ev_items = list(
        db_session.scalars(
            select(OSEvidenceRecord)
            .where(OSEvidenceRecord.assessment_id == assessment.id)
            .order_by(OSEvidenceRecord.observation_timestamp.asc())
        ).all()
    )
    assert len(ev_items) == 2
    assert ev_items[0].collection_status == "observed"
    assert ev_items[0].permission_state == "granted"

    assert ev_items[1].collection_status == "unavailable"
    assert ev_items[1].permission_state == "denied"
    assert "Audit limitation" in ev_items[1].explanatory_notes


def test_findings_unrated_cvss_and_vendor_severity(db_session: Session) -> None:
    """Verify that findings without numerical CVSS scores store None cleanly while capturing vendor severity."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.RUNNING.value)
    db_session.add(assessment)
    db_session.commit()

    # Finding with qualitative vendor severity but no numerical CVSS score
    finding = OSFindingRecord(
        assessment_id=assessment.id,
        finding_type=OSFindingType.MISSING_PATCH.value,
        advisory_id="USN-6500-1",
        title="Linux kernel security update",
        component_name="linux-image-generic",
        installed_version="6.5.0-26-generic",
        fixed_version="6.5.0-28-generic",
        cvss_score=None,
        severity=OSSeverity.HIGH.value,
        confidence=OSConfidence.HIGH.value,
        exploitability=OSExploitability.UNKNOWN.value,
        advisory_source="canonical_usn",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    assert finding.cvss_score is None
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.exploitability == "unknown"


def test_os_assessment_cascade_deletion(db_session: Session) -> None:
    """Verify that deleting an OSAssessmentRecord cascade-deletes associated evidence and findings."""
    assessment = OSAssessmentRecord(status=OSAssessmentStatus.COMPLETED.value)
    db_session.add(assessment)
    db_session.commit()

    evidence = OSEvidenceRecord(
        assessment_id=assessment.id,
        collector_name="test_collector",
        check_id="test_check",
        signal_name="test_signal",
    )
    db_session.add(evidence)
    db_session.commit()

    finding = OSFindingRecord(
        assessment_id=assessment.id,
        evidence_id=evidence.id,
        advisory_id="CVE-2024-0001",
        title="Test Vulnerability",
        component_name="test-component",
    )
    db_session.add(finding)
    db_session.commit()

    # Verify entities exist
    assert db_session.scalar(select(OSAssessmentRecord).where(OSAssessmentRecord.id == assessment.id)) is not None
    assert db_session.scalar(select(OSEvidenceRecord).where(OSEvidenceRecord.assessment_id == assessment.id)) is not None
    assert db_session.scalar(select(OSFindingRecord).where(OSFindingRecord.assessment_id == assessment.id)) is not None

    # Delete parent assessment
    db_session.delete(assessment)
    db_session.commit()

    # Verify children cascade deleted
    assert db_session.scalar(select(OSAssessmentRecord).where(OSAssessmentRecord.id == assessment.id)) is None
    assert db_session.scalar(select(OSEvidenceRecord).where(OSEvidenceRecord.assessment_id == assessment.id)) is None
    assert db_session.scalar(select(OSFindingRecord).where(OSFindingRecord.assessment_id == assessment.id)) is None


def test_os_finding_evidence_set_null_on_evidence_delete(db_session: Session) -> None:
    """Verify that deleting an individual evidence item sets finding.evidence_id to NULL without deleting the finding."""
    from sqlalchemy import text

    db_session.execute(text("PRAGMA foreign_keys = ON"))

    assessment = OSAssessmentRecord(status=OSAssessmentStatus.RUNNING.value)
    db_session.add(assessment)
    db_session.commit()

    evidence = OSEvidenceRecord(
        assessment_id=assessment.id,
        collector_name="test_collector",
        check_id="check_socket",
        signal_name="listening_port",
        observed_value="0.0.0.0:22",
    )
    db_session.add(evidence)
    db_session.commit()

    finding = OSFindingRecord(
        assessment_id=assessment.id,
        evidence_id=evidence.id,
        advisory_id="CONFIG-SSH-01",
        title="Exposed SSH Service",
        component_name="sshd",
    )
    db_session.add(finding)
    db_session.commit()

    assert finding.evidence_id == evidence.id

    # Delete the evidence item
    db_session.delete(evidence)
    db_session.commit()

    # Refresh finding: evidence_id should be SET NULL while finding remains intact
    db_session.refresh(finding)
    assert finding.id is not None
    assert finding.evidence_id is None


def test_pydantic_os_schema_serialization(db_session: Session) -> None:
    """Verify Pydantic schemas serialize ORM entities accurately."""
    asset = OSAssetRecord(
        host_identifier="abc123hash",
        hostname="production-node",
        os_family="windows",
        os_name="Windows 11 Pro",
        os_version="23H2",
        os_build="22631.3447",
        architecture="x86_64",
    )
    db_session.add(asset)
    db_session.commit()

    assessment = OSAssessmentRecord(
        asset_id=asset.id,
        status=OSAssessmentStatus.COMPLETED.value,
        risk_policy_version="policy_v1.0",
        risk_score=45,
        risk_level="medium",
        confidence_level="high",
        exploitability_state="unknown",
    )
    db_session.add(assessment)
    db_session.commit()

    evidence = OSEvidenceRecord(
        assessment_id=assessment.id,
        collector_name="win_registry_collector",
        check_id="win_uninstall_keys",
        signal_name="installed_software",
        observed_value="Python 3.12.2",
    )
    db_session.add(evidence)
    db_session.commit()

    finding = OSFindingRecord(
        assessment_id=assessment.id,
        evidence_id=evidence.id,
        advisory_id="CVE-2024-0002",
        title="Sample Advisory",
        component_name="python",
        severity=OSSeverity.MEDIUM.value,
        confidence=OSConfidence.HIGH.value,
    )
    db_session.add(finding)
    db_session.commit()

    db_session.refresh(assessment)

    # Test Pydantic model_validate
    asset_schema = OSAssetResponse.model_validate(asset)
    assert asset_schema.hostname == "production-node"
    assert asset_schema.os_family == "windows"

    assessment_schema = OSAssessmentResponse.model_validate(assessment)
    assert assessment_schema.id == assessment.id
    assert assessment_schema.risk_score == 45
    assert assessment_schema.exploitability_state == OSExploitability.UNKNOWN

    detail_schema = OSAssessmentDetailResponse.model_validate(assessment)
    assert detail_schema.asset is not None
    assert detail_schema.asset.hostname == "production-node"
    assert len(detail_schema.evidence_items) == 1
    assert detail_schema.evidence_items[0].signal_name == "installed_software"
    assert len(detail_schema.findings) == 1
    assert detail_schema.findings[0].advisory_id == "CVE-2024-0002"
