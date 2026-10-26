import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from ..core.database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst", nullable=False)  # admin, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    approvals = relationship("RemediationApproval", back_populates="user")
    audit_events = relationship("AuditEvent", back_populates="user")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), index=True, nullable=False)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255), nullable=False)
    os_type = Column(String(50), nullable=False)  # linux, windows
    os_version = Column(String(100), nullable=False)
    environment = Column(String(50), default="staging", nullable=False)  # production, staging, development
    criticality = Column(String(50), default="high", nullable=False)  # critical, high, medium, low
    status = Column(String(50), default="active", nullable=False)  # active, inactive, maintenance
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    snapshots = relationship("InventorySnapshot", back_populates="asset", cascade="all, delete-orphan")
    assessments = relationship("Assessment", back_populates="asset", cascade="all, delete-orphan")
    twins = relationship("DigitalTwin", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("VulnerabilityFinding", back_populates="asset", cascade="all, delete-orphan")


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    format = Column(String(50), nullable=False)  # json, csv, collector
    raw_filename = Column(String(255), default="")
    packages_count = Column(Integer, default=0)
    parsed_packages = Column(JSON, default=list)  # list of {"name": str, "version": str, "architecture": str, "status": str}
    configuration_metadata = Column(JSON, default=dict)  # ports, firewall, services, kernel, etc.
    created_at = Column(DateTime, default=utc_now, nullable=False)

    asset = relationship("Asset", back_populates="snapshots")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="pending", nullable=False)  # pending, running, completed, failed
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    average_risk_score = Column(Float, default=0.0)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, default="")

    asset = relationship("Asset", back_populates="assessments")
    findings = relationship("VulnerabilityFinding", back_populates="assessment", cascade="all, delete-orphan")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(50), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    affected_component = Column(String(150), nullable=False)
    installed_version = Column(String(100), nullable=False)
    fixed_version = Column(String(100), default="N/A")
    cvss_v3_score = Column(Float, default=0.0)
    cvss_v3_vector = Column(String(100), default="")
    severity = Column(String(50), nullable=False)  # critical, high, medium, low
    
    # State tracking: detected, suspected, confirmed, fixed, unresolved, inconclusive
    detection_status = Column(String(50), default="detected", nullable=False)
    
    # AI/ML Risk Analysis outputs
    risk_score = Column(Float, default=0.0)  # 0 to 100
    risk_category = Column(String(50), default="Medium")  # Critical, High, Medium, Low
    confidence_score = Column(Float, default=0.85)  # 0.0 to 1.0
    contributing_factors = Column(JSON, default=dict)  # breakdown weights & reasons
    recommended_priority = Column(String(50), default="P2")  # P0 (immediate), P1, P2, P3
    risk_explanation = Column(Text, default="")
    
    description = Column(Text, default="")
    references = Column(JSON, default=list)
    remediation_summary = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    asset = relationship("Asset", back_populates="findings")
    assessment = relationship("Assessment", back_populates="findings")
    evidence_records = relationship("EvidenceRecord", back_populates="finding", cascade="all, delete-orphan")
    validation_runs = relationship("ValidationRun", back_populates="finding", cascade="all, delete-orphan")
    remediations = relationship("RemediationRecommendation", back_populates="finding", cascade="all, delete-orphan")
    retests = relationship("RetestResult", back_populates="finding", cascade="all, delete-orphan")


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)  # package_manifest, config_directive, banner_grab, validation_log
    title = Column(String(255), nullable=False)
    raw_evidence = Column(Text, nullable=False)
    metadata_info = Column(JSON, default=dict)
    collected_at = Column(DateTime, default=utc_now, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="evidence_records")


class DigitalTwin(Base):
    __tablename__ = "digital_twins"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    provider = Column(String(50), default="mock_isolated", nullable=False)  # mock_isolated, virtualbox, vmware
    template_name = Column(String(100), nullable=False)  # ubuntu-22.04-cve-lab, win-srv2022-lab, etc.
    status = Column(String(50), default="ready", nullable=False)  # provisioning, ready, testing, remediating, stopped, error
    ip_address = Column(String(45), default="192.168.100.105")
    network_isolated = Column(Boolean, default=True, nullable=False)
    snapshot_status = Column(String(100), default="baseline-snapshot-created")
    target_config = Column(JSON, default=dict)
    current_config = Column(JSON, default=dict)
    config_parity_score = Column(Float, default=98.5)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    asset = relationship("Asset", back_populates="twins")
    validation_runs = relationship("ValidationRun", back_populates="twin")
    retests = relationship("RetestResult", back_populates="twin")


class ValidationProcedure(Base):
    __tablename__ = "validation_procedures"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    procedure_code = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    target_cve = Column(String(50), index=True, nullable=False)
    target_component = Column(String(100), nullable=False)
    safety_level = Column(String(50), default="safe_non_destructive", nullable=False)
    preconditions = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    test_logic_type = Column(String(50), default="version_feature_handshake", nullable=False)
    parameters = Column(JSON, default=dict)


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    twin_id = Column(String(36), ForeignKey("digital_twins.id", ondelete="CASCADE"), nullable=False, index=True)
    procedure_id = Column(String(36), ForeignKey("validation_procedures.id"), nullable=True)
    procedure_code = Column(String(50), nullable=False)
    status = Column(String(50), default="completed", nullable=False)  # running, completed, failed
    outcome = Column(String(50), nullable=False)  # confirmed, not_reproduced, inconclusive, not_tested
    start_time = Column(DateTime, default=utc_now, nullable=False)
    completion_time = Column(DateTime, default=utc_now, nullable=False)
    preconditions_met = Column(Boolean, default=True, nullable=False)
    test_output = Column(Text, nullable=False)
    error_details = Column(Text, default="")
    limitations = Column(Text, default="Simulated isolated lab sandbox test. No production impact.")
    created_at = Column(DateTime, default=utc_now, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="validation_runs")
    twin = relationship("DigitalTwin", back_populates="validation_runs")
    procedure = relationship("ValidationProcedure")


class RemediationRecommendation(Base):
    __tablename__ = "remediation_recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)  # package_update, config_hardening, service_reconfiguration
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    vendor_advisory_url = Column(String(500), default="")
    prerequisites = Column(JSON, default=list)
    compatibility_concerns = Column(Text, default="Low impact; verified in twin")
    command_preview = Column(Text, nullable=False)
    rollback_instructions = Column(Text, default="")
    expected_outcome = Column(Text, default="")
    # recommended, awaiting_approval, approved, applied_in_twin, retest_pending, resolved, failed, rejected
    status = Column(String(50), default="recommended", nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="remediations")
    approvals = relationship("RemediationApproval", back_populates="recommendation", cascade="all, delete-orphan")


class RemediationApproval(Base):
    __tablename__ = "remediation_approvals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    recommendation_id = Column(String(36), ForeignKey("remediation_recommendations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    status = Column(String(50), nullable=False)  # approved, rejected
    justification = Column(Text, nullable=False)
    target_environment = Column(String(50), default="twin_lab", nullable=False)  # strict: twin_lab only
    approved_at = Column(DateTime, default=utc_now, nullable=False)

    recommendation = relationship("RemediationRecommendation", back_populates="approvals")
    user = relationship("User", back_populates="approvals")


class RetestResult(Base):
    __tablename__ = "retest_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    twin_id = Column(String(36), ForeignKey("digital_twins.id", ondelete="CASCADE"), nullable=False, index=True)
    original_finding_status = Column(String(50), nullable=False)
    post_fix_status = Column(String(50), nullable=False)  # resolved, remains_present, inconclusive
    package_version_before = Column(String(100), nullable=False)
    package_version_after = Column(String(100), nullable=False)
    retest_detection_output = Column(Text, nullable=False)
    retest_validation_output = Column(Text, nullable=False)
    remaining_risk_score = Column(Float, default=0.0)
    conclusion = Column(Text, nullable=False)
    executed_at = Column(DateTime, default=utc_now, nullable=False)

    finding = relationship("VulnerabilityFinding", back_populates="retests")
    twin = relationship("DigitalTwin", back_populates="retests")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(50), index=True, nullable=False)  # auth, assessment, validation, remediation, twin, security
    action = Column(String(100), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user_email = Column(String(255), default="system")
    ip_address = Column(String(45), default="127.0.0.1")
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    user = relationship("User", back_populates="audit_events")
