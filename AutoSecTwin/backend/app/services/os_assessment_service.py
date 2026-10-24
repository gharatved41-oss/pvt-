"""Database service operations and orchestration for OS security assessments, assets, evidence, and risk evaluation."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.os_assessment import OSAssessmentRecord, OSAssessmentStatus
from app.models.os_asset import OSAssetRecord
from app.models.os_evidence import OSEvidenceRecord, OSEvidenceStatus, OSPermissionState
from app.models.os_finding import (
    OSConfidence,
    OSExploitability,
    OSFindingRecord,
    OSFindingType,
    OSSeverity,
)
from app.schemas.os_assessment import (
    OSAssetCreateRequest,
    OSAssessmentCreateRequest,
)
from app.schemas.os_evidence import OSEvidenceItemCreate
from app.schemas.os_finding import OSFindingCreate
from app.schemas.os_remediation import OSRemediationPlan
from app.services.os_collectors import (
    LinuxDpkgStatusCollector,
    LinuxKernelHardeningCollector,
    LinuxOSReleaseCollector,
    LinuxPackageUpdateStatusCollector,
    LinuxSSHConfigCollector,
    OSCollectorManager,
    WindowsDefenderStatusCollector,
    WindowsFirewallProfileCollector,
    WindowsInstalledSoftwareCollector,
    WindowsOSIdentityCollector,
    WindowsSecuritySettingsCollector,
    evaluate_security_configuration_evidence,
)
from app.services.os_matcher import (
    CanonicalUSNProvider,
    DebianSecurityTrackerProvider,
    MatchingEvaluationReport,
    MicrosoftMSRCProvider,
    OSVulnerabilityMatcher,
)
from app.services.os_remediation.planner import OSRemediationPlanner
from app.services.os_risk_engine.engine import (
    OSRiskEngine,
    OSRiskEvaluationResult,
)
from app.utils.os_detect import (
    detect_os_family,
    detect_os_info,
    get_anonymized_host_identifier,
)

logger = logging.getLogger("vulntwin_ai.os_assessment_service")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidStatusTransitionError(Exception):
    """Raised when an illegal lifecycle status transition is requested."""

    pass


class AssetNotFoundError(Exception):
    """Raised when a requested OS asset record is not found."""

    pass


class AssessmentNotFoundError(Exception):
    """Raised when a requested OS assessment record is not found."""

    pass


class UnauthorizedAssessmentError(Exception):
    """Raised when an assessment is attempted on an unauthorized target or with an unauthorized mode."""

    pass


class UnsupportedOperatingSystemError(Exception):
    """Raised when an assessment is requested on an unsupported platform family."""

    pass


class MateriallyIncompleteAssessmentError(Exception):
    """Raised when an assessment cannot complete because required stages failed or inventory is missing."""

    pass


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Asset Database Operations
# ---------------------------------------------------------------------------

def create_os_asset(
    db: Session, asset_data: OSAssetCreateRequest, owner_id: Optional[str] = None
) -> OSAssetRecord:
    """Persist a new OS asset record from validated input."""
    family = asset_data.os_family.lower().strip()
    if family not in ("windows", "linux"):
        raise UnsupportedOperatingSystemError(
            f"Unsupported operating system family '{asset_data.os_family}'. "
            "VulnTwin AI only supports 'windows' and 'linux'."
        )

    record = OSAssetRecord(
        host_identifier=asset_data.host_identifier,
        hostname=asset_data.hostname,
        os_family=family,
        os_name=asset_data.os_name,
        os_version=asset_data.os_version,
        os_build=asset_data.os_build,
        architecture=asset_data.architecture,
        collected_at=utc_now(),
        owner_id=owner_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_os_asset_by_id(db: Session, asset_id: str) -> Optional[OSAssetRecord]:
    """Retrieve an OS asset record by its UUID."""
    statement = select(OSAssetRecord).where(OSAssetRecord.id == asset_id)
    return db.scalars(statement).first()


def list_os_assets(
    db: Session, limit: int = 20, offset: int = 0, owner_id: Optional[str] = None
) -> Tuple[List[OSAssetRecord], int]:
    """Retrieve paginated OS asset records along with total count."""
    count_stmt = select(func.count(OSAssetRecord.id))
    select_stmt = select(OSAssetRecord).order_by(OSAssetRecord.collected_at.desc())
    if owner_id is not None:
        count_stmt = count_stmt.where(OSAssetRecord.owner_id == owner_id)
        select_stmt = select_stmt.where(OSAssetRecord.owner_id == owner_id)

    total = db.scalar(count_stmt) or 0
    records = list(db.scalars(select_stmt.offset(offset).limit(limit)).all())
    return records, total


def get_or_create_local_asset(db: Session, owner_id: Optional[str] = None) -> OSAssetRecord:
    """Detect local machine profile and retrieve or register corresponding OSAssetRecord."""
    info = detect_os_info()
    host_id = info.get("host_identifier") or get_anonymized_host_identifier()

    statement = select(OSAssetRecord).where(OSAssetRecord.host_identifier == host_id)
    if owner_id is not None:
        statement = statement.where(OSAssetRecord.owner_id == owner_id)
    existing = db.scalars(statement).first()
    if existing:
        return existing

    record = OSAssetRecord(
        host_identifier=host_id,
        hostname=info.get("hostname") or "localhost",
        os_family=info.get("os_family") or "unknown",
        os_name=info.get("os_name") or "Generic OS",
        os_version=str(info.get("os_version") or ""),
        os_build=str(info.get("os_build") or ""),
        architecture=info.get("architecture") or "x86_64",
        collected_at=utc_now(),
        owner_id=owner_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ---------------------------------------------------------------------------
# Assessment Lifecycle Operations
# ---------------------------------------------------------------------------

def create_os_assessment(
    db: Session, payload: OSAssessmentCreateRequest, owner_id: Optional[str] = None
) -> OSAssessmentRecord:
    """Create and persist a new OS assessment record in 'pending' status."""
    mode = payload.assessment_type.lower().strip()
    if mode != "local_read_only":
        raise UnauthorizedAssessmentError(
            f"Unauthorized assessment type '{payload.assessment_type}'. "
            "Only 'local_read_only' assessments are authorized."
        )

    asset: Optional[OSAssetRecord] = None
    if payload.asset_id:
        asset = get_os_asset_by_id(db, payload.asset_id)
        if not asset:
            raise AssetNotFoundError(
                f"OS Asset with ID '{payload.asset_id}' was not found."
            )
    else:
        # Default to local machine profile if no asset_id provided
        asset = get_or_create_local_asset(db, owner_id=owner_id)

    # Verify platform support
    if asset.os_family.lower() not in ("windows", "linux"):
        raise UnsupportedOperatingSystemError(
            f"Unsupported operating system family '{asset.os_family}'. "
            "VulnTwin AI only supports 'windows' and 'linux'."
        )

    assessment = OSAssessmentRecord(
        asset_id=asset.id,
        assessment_type="local_read_only",
        status=OSAssessmentStatus.PENDING.value,
        risk_policy_version=OSRiskEngine.POLICY_VERSION,
        exploitability_state=OSExploitability.UNKNOWN.value,
        created_at=utc_now(),
        owner_id=owner_id,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


def get_os_assessment_by_id(
    db: Session, assessment_id: str
) -> Optional[OSAssessmentRecord]:
    """Retrieve an OS assessment record by its UUID."""
    statement = select(OSAssessmentRecord).where(OSAssessmentRecord.id == assessment_id)
    return db.scalars(statement).first()


def list_os_assessments(
    db: Session, limit: int = 20, offset: int = 0, owner_id: Optional[str] = None
) -> Tuple[List[OSAssessmentRecord], int]:
    """Retrieve paginated OS assessment records along with total count."""
    count_stmt = select(func.count(OSAssessmentRecord.id))
    select_stmt = select(OSAssessmentRecord).order_by(OSAssessmentRecord.created_at.desc())
    if owner_id is not None:
        count_stmt = count_stmt.where(OSAssessmentRecord.owner_id == owner_id)
        select_stmt = select_stmt.where(OSAssessmentRecord.owner_id == owner_id)

    total = db.scalar(count_stmt) or 0
    records = list(db.scalars(select_stmt.offset(offset).limit(limit)).all())
    return records, total


def transition_os_status(
    db: Session,
    record: OSAssessmentRecord,
    new_status: str,
    error_message: Optional[str] = None,
) -> OSAssessmentRecord:
    """Validate and persist a state machine transition on an OSAssessmentRecord."""
    if not record.can_transition_to(new_status):
        raise InvalidStatusTransitionError(
            f"Cannot transition OS assessment '{record.id}' from status '{record.status}' to '{new_status}'."
        )

    record.status = new_status
    if error_message is not None:
        record.error_message = error_message
    elif new_status == OSAssessmentStatus.COMPLETED.value:
        record.error_message = None

    if new_status in (OSAssessmentStatus.COMPLETED.value, OSAssessmentStatus.FAILED.value):
        record.completed_at = utc_now()

    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# ---------------------------------------------------------------------------
# Evidence & Finding Persistence
# ---------------------------------------------------------------------------

def add_os_evidence_items(
    db: Session,
    assessment_id: str,
    evidence_items: List[OSEvidenceItemCreate],
) -> List[OSEvidenceRecord]:
    """Persist multiple evidence records associated with an OS assessment ID."""
    records: List[OSEvidenceRecord] = []
    for item in evidence_items:
        rec = OSEvidenceRecord(
            assessment_id=assessment_id,
            collector_name=item.collector_name,
            check_id=item.check_id,
            signal_name=item.signal_name,
            observed_value=item.observed_value,
            structured_data=item.structured_data,
            collection_status=item.collection_status.value if hasattr(item.collection_status, "value") else str(item.collection_status),
            permission_state=item.permission_state.value if hasattr(item.permission_state, "value") else str(item.permission_state),
            explanatory_notes=item.explanatory_notes,
            observation_timestamp=utc_now(),
        )
        db.add(rec)
        records.append(rec)

    db.commit()
    for rec in records:
        db.refresh(rec)
    return records


def get_os_evidence_by_assessment_id(
    db: Session, assessment_id: str
) -> List[OSEvidenceRecord]:
    """Retrieve all evidence observations collected for an OS assessment."""
    statement = (
        select(OSEvidenceRecord)
        .where(OSEvidenceRecord.assessment_id == assessment_id)
        .order_by(OSEvidenceRecord.observation_timestamp.asc())
    )
    return list(db.scalars(statement).all())


def add_os_findings(
    db: Session,
    assessment_id: str,
    findings: List[OSFindingCreate],
) -> List[OSFindingRecord]:
    """Persist security findings identified during assessment."""
    records: List[OSFindingRecord] = []
    for f in findings:
        rec = OSFindingRecord(
            assessment_id=assessment_id,
            evidence_id=f.evidence_id,
            finding_type=f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type),
            advisory_id=f.advisory_id,
            title=f.title,
            component_name=f.component_name,
            installed_version=f.installed_version,
            fixed_version=f.fixed_version,
            cvss_score=f.cvss_score,
            cvss_version=f.cvss_version,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
            exploitability=OSExploitability.UNKNOWN.value,  # Strictly UNKNOWN by default
            advisory_source=f.advisory_source,
            match_basis=f.match_basis,
            description=f.description,
            created_at=utc_now(),
        )
        db.add(rec)
        records.append(rec)

    db.commit()
    for rec in records:
        db.refresh(rec)
    return records


def get_os_findings_by_assessment_id(
    db: Session, assessment_id: str
) -> List[OSFindingRecord]:
    """Retrieve all security findings associated with an assessment."""
    statement = (
        select(OSFindingRecord)
        .where(OSFindingRecord.assessment_id == assessment_id)
        .order_by(OSFindingRecord.created_at.asc())
    )
    return list(db.scalars(statement).all())


# ---------------------------------------------------------------------------
# Default Component Factories
# ---------------------------------------------------------------------------

def get_default_os_collector_manager(os_family: str) -> OSCollectorManager:
    """Instantiate OS collector manager populated with safe read-only collectors."""
    manager = OSCollectorManager()
    fam = os_family.lower().strip()

    if fam == "linux":
        manager.register(LinuxOSReleaseCollector())
        manager.register(LinuxDpkgStatusCollector())
        manager.register(LinuxKernelHardeningCollector())
        manager.register(LinuxSSHConfigCollector())
        manager.register(LinuxPackageUpdateStatusCollector())
    elif fam == "windows":
        manager.register(WindowsOSIdentityCollector())
        manager.register(WindowsInstalledSoftwareCollector())
        manager.register(WindowsDefenderStatusCollector())
        manager.register(WindowsFirewallProfileCollector())
        manager.register(WindowsSecuritySettingsCollector())

    return manager


def get_default_os_vulnerability_matcher(os_family: Optional[str] = None) -> OSVulnerabilityMatcher:
    """Instantiate vulnerability matcher configured with authoritative providers."""
    matcher = OSVulnerabilityMatcher()
    matcher.register_provider(CanonicalUSNProvider())
    matcher.register_provider(DebianSecurityTrackerProvider())
    matcher.register_provider(MicrosoftMSRCProvider())
    return matcher


# ---------------------------------------------------------------------------
# Execution Pipeline
# ---------------------------------------------------------------------------

def run_local_os_assessment(
    db: Session,
    record: OSAssessmentRecord,
    collector_manager: Optional[OSCollectorManager] = None,
    vulnerability_matcher: Optional[OSVulnerabilityMatcher] = None,
    risk_engine: Optional[OSRiskEngine] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[OSAssessmentRecord, List[OSEvidenceRecord], List[OSFindingRecord], OSRiskEvaluationResult]:
    """Execute end-to-end authorized local read-only OS assessment and scoring.

    Enforces:
    - Only assess local machine or authorized asset.
    - Lifecycle transition: pending -> running -> completed (or failed).
    - Exploitability strictly maintained as UNKNOWN.
    - Incomplete collection, missing inventory, or provider failure treated as uncertainty or failure.
    - Materially incomplete assessments are never reported as completed.
    - Recommendations remain unapplied proposals.
    """
    ctx = dict(context or {})

    # Pre-execution validation
    if record.status != OSAssessmentStatus.PENDING.value:
        raise InvalidStatusTransitionError(
            f"Assessment '{record.id}' is in status '{record.status}', cannot start assessment."
        )

    asset = record.asset or (get_os_asset_by_id(db, record.asset_id) if record.asset_id else None)
    if not asset:
        asset = get_or_create_local_asset(db)
        record.asset_id = asset.id
        db.add(record)
        db.commit()
        db.refresh(record)

    os_family = asset.os_family.lower().strip()
    if os_family not in ("windows", "linux"):
        transition_os_status(
            db,
            record,
            OSAssessmentStatus.FAILED.value,
            error_message=f"Assessment failed: Unsupported operating system family '{asset.os_family}'. Only 'linux' and 'windows' are supported.",
        )
        raise UnsupportedOperatingSystemError(
            f"Unsupported operating system family '{asset.os_family}'."
        )

    # Authorization Check: verify local machine or explicit authorization
    local_host_id = get_anonymized_host_identifier()
    is_local = asset.host_identifier == local_host_id or asset.hostname in ("localhost", "127.0.0.1", "")
    is_authorized = ctx.get("is_authorized", False)
    if not is_local and not is_authorized:
        transition_os_status(
            db,
            record,
            OSAssessmentStatus.FAILED.value,
            error_message="Assessment failed: Target asset is not the local host and is not authorized.",
        )
        raise UnauthorizedAssessmentError(
            "Target asset is not the local host and has not been explicitly authorized."
        )

    # Step 1: Transition pending -> running
    transition_os_status(db, record, OSAssessmentStatus.RUNNING.value)

    if collector_manager is None:
        collector_manager = get_default_os_collector_manager(os_family)

    if vulnerability_matcher is None:
        vulnerability_matcher = get_default_os_vulnerability_matcher(os_family)

    if risk_engine is None:
        risk_engine = OSRiskEngine()

    try:
        # Step 2: Safe Read-Only Evidence Collection
        evidence_items = collector_manager.run_all(os_family=os_family, context=ctx)

        # Check for catastrophic collector failure (zero evidence items returned or all errored)
        if not evidence_items or all(e.collection_status == OSEvidenceStatus.ERROR for e in evidence_items):
            raise MateriallyIncompleteAssessmentError(
                "Evidence collection returned zero valid items; required collection stage failed."
            )

        persisted_evidence = add_os_evidence_items(db, record.id, evidence_items)

        # Step 3: Evaluate Configuration Hardening Evidence
        all_finding_creates: List[OSFindingCreate] = []
        config_findings = evaluate_security_configuration_evidence(evidence_items)
        all_finding_creates.extend(config_findings)

        # Step 4: Vulnerability Matching on Installed Components
        matching_report: Optional[MatchingEvaluationReport] = None
        has_inventory = False

        packages = []
        dpkg_ev_id = None
        codename = ""

        apps = []
        apps_ev_id = None

        for ev in persisted_evidence:
            if ev.check_id in ("dpkg_installed_packages", "linux_dpkg_collector") and ev.structured_data:
                pkgs = ev.structured_data.get("packages", [])
                if pkgs:
                    packages = pkgs
                    dpkg_ev_id = ev.id
                    has_inventory = True
            elif ev.check_id in ("windows_installed_software", "installed_software") and ev.structured_data:
                app_list = ev.structured_data.get("installed_applications", [])
                if app_list:
                    apps = app_list
                    apps_ev_id = ev.id
                    has_inventory = True
            elif ev.check_id == "linux_os_release" and ev.structured_data:
                codename = ev.structured_data.get("version_codename") or ""

        if packages:
            matching_report = vulnerability_matcher.evaluate_linux_packages(
                packages=packages,
                codename=codename or (asset.os_version or "jammy"),
                architecture=asset.architecture or "amd64",
                evidence_id=dpkg_ev_id,
            )
            all_finding_creates.extend(matching_report.findings)
        elif apps:
            matching_report = vulnerability_matcher.evaluate_windows_applications(
                applications=apps,
                windows_build=asset.os_build or "",
                evidence_id=apps_ev_id,
            )
            all_finding_creates.extend(matching_report.findings)

        # Check material completeness:
        # If inventory is required and completely missing, or context marks missing_inventory
        if ctx.get("missing_inventory") or ctx.get("materially_incomplete"):
            raise MateriallyIncompleteAssessmentError(
                "Assessment is materially incomplete: required component inventory was missing or degraded."
            )

        # If a required provider failed completely and context demands failure
        if ctx.get("fail_on_provider_error") and matching_report and not matching_report.is_complete:
            raise MateriallyIncompleteAssessmentError(
                f"Required advisory providers failed: {matching_report.limitations}"
            )

        # Step 5: Persist findings
        persisted_findings = add_os_findings(db, record.id, all_finding_creates)

        # Step 6: Deterministic Risk Engine Evaluation
        risk_result = risk_engine.evaluate(
            findings=all_finding_creates,
            matching_report=matching_report,
            context=ctx,
        )

        # Update assessment metrics
        record.risk_score = risk_result.risk_score
        record.risk_level = risk_result.risk_level.value
        record.confidence_level = risk_result.confidence_level.value
        record.exploitability_state = OSExploitability.UNKNOWN.value  # Enforce strictly UNKNOWN

        # Step 7: Transition running -> completed
        transition_os_status(db, record, OSAssessmentStatus.COMPLETED.value)

        return record, persisted_evidence, persisted_findings, risk_result

    except MateriallyIncompleteAssessmentError as exc:
        logger.warning(
            "OS assessment '%s' failed due to material incompleteness: %s",
            record.id,
            exc,
        )
        transition_os_status(
            db,
            record,
            OSAssessmentStatus.FAILED.value,
            error_message=f"Materially incomplete: {exc}",
        )
        raise

    except Exception as exc:
        logger.error(
            "Fatal error running OS assessment '%s': %s",
            record.id,
            exc,
            exc_info=True,
        )
        transition_os_status(
            db,
            record,
            OSAssessmentStatus.FAILED.value,
            error_message=f"Assessment error: {type(exc).__name__}: {exc}",
        )
        raise


# ---------------------------------------------------------------------------
# Explainable Risk & Remediation Retrieval
# ---------------------------------------------------------------------------

def get_os_risk_evaluation(
    db: Session,
    assessment_id: str,
    risk_engine: Optional[OSRiskEngine] = None,
) -> OSRiskEvaluationResult:
    """Calculate and return transparent, explainable risk score and rationale for an assessment."""
    assessment = get_os_assessment_by_id(db, assessment_id)
    if not assessment:
        raise AssessmentNotFoundError(
            f"OS Assessment with ID '{assessment_id}' was not found."
        )

    findings = get_os_findings_by_assessment_id(db, assessment_id)
    finding_creates = [
        OSFindingCreate(
            finding_type=OSFindingType(f.finding_type),
            advisory_id=f.advisory_id,
            title=f.title,
            component_name=f.component_name,
            installed_version=f.installed_version,
            fixed_version=f.fixed_version,
            cvss_score=f.cvss_score,
            cvss_version=f.cvss_version,
            severity=OSSeverity(f.severity),
            confidence=OSConfidence(f.confidence),
            exploitability=OSExploitability.UNKNOWN,
            advisory_source=f.advisory_source,
            match_basis=f.match_basis,
            description=f.description,
            evidence_id=f.evidence_id,
        )
        for f in findings
    ]

    engine = risk_engine or OSRiskEngine()
    context: Dict[str, Any] = {}
    if assessment.status == OSAssessmentStatus.FAILED.value:
        context["is_complete"] = False
        context["limitations"] = [f"Assessment terminated in failed state: {assessment.error_message}"]
    elif assessment.confidence_level == OSConfidence.LOW.value and assessment.risk_score is not None and assessment.risk_score >= 30:
        context["is_complete"] = False
        context["provider_failures"] = ["Advisory provider degraded or unavailable during assessment."]

    return engine.evaluate(findings=finding_creates, context=context)


def get_os_remediation_plan(
    db: Session,
    assessment_id: str,
    planner: Optional[OSRemediationPlanner] = None,
) -> OSRemediationPlan:
    """Generate and return recommendation-only remediation plan for an assessment."""
    assessment = get_os_assessment_by_id(db, assessment_id)
    if not assessment:
        raise AssessmentNotFoundError(
            f"OS Assessment with ID '{assessment_id}' was not found."
        )

    findings = get_os_findings_by_assessment_id(db, assessment_id)
    finding_creates = [
        OSFindingCreate(
            finding_type=OSFindingType(f.finding_type),
            advisory_id=f.advisory_id,
            title=f.title,
            component_name=f.component_name,
            installed_version=f.installed_version,
            fixed_version=f.fixed_version,
            cvss_score=f.cvss_score,
            cvss_version=f.cvss_version,
            severity=OSSeverity(f.severity),
            confidence=OSConfidence(f.confidence),
            exploitability=OSExploitability.UNKNOWN,
            advisory_source=f.advisory_source,
            match_basis=f.match_basis,
            description=f.description,
            evidence_id=f.evidence_id,
        )
        for f in findings
    ]

    limitations = []
    if assessment.error_message:
        limitations.append(assessment.error_message)

    p = planner or OSRemediationPlanner()
    return p.generate_plan(
        findings=finding_creates,
        assessment_id=assessment_id,
        limitations=limitations,
    )
