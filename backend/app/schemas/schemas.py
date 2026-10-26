from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

# --- Auth Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user: Dict[str, Any]

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[int] = None

class UserCreate(BaseModel):
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str = Field(..., min_length=6)
    full_name: str
    role: Optional[str] = "analyst"

class UserLogin(BaseModel):
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

# --- Asset Schemas ---
class AssetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    ip_address: str
    hostname: str
    os_type: str = Field(..., pattern="^(linux|windows)$")
    os_version: str
    environment: str = "staging"  # production, staging, development
    criticality: str = "high"  # critical, high, medium, low
    description: Optional[str] = ""

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None

class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    ip_address: str
    hostname: str
    os_type: str
    os_version: str
    environment: str
    criticality: str
    status: str
    description: str
    created_at: datetime
    updated_at: datetime

# --- Inventory Snapshot Schemas ---
class PackageItem(BaseModel):
    name: str
    version: str
    architecture: Optional[str] = "x86_64"
    status: Optional[str] = "installed"
    description: Optional[str] = ""

class InventorySnapshotCreate(BaseModel):
    format: str = "json"  # json, csv, manual
    raw_filename: Optional[str] = "manual_entry"
    packages: List[PackageItem]
    configuration_metadata: Optional[Dict[str, Any]] = {}

class InventorySnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str
    format: str
    raw_filename: str
    packages_count: int
    parsed_packages: List[Dict[str, Any]]
    configuration_metadata: Dict[str, Any]
    created_at: datetime

# --- Vulnerability Finding Schemas ---
class EvidenceRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    evidence_type: str
    title: str
    raw_evidence: str
    metadata_info: Dict[str, Any]
    collected_at: datetime

class VulnerabilityFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    assessment_id: str
    asset_id: str
    cve_id: str
    title: str
    affected_component: str
    installed_version: str
    fixed_version: str
    cvss_v3_score: float
    cvss_v3_vector: str
    severity: str
    detection_status: str
    risk_score: float
    risk_category: str
    confidence_score: float
    contributing_factors: Dict[str, Any]
    recommended_priority: str
    risk_explanation: str
    description: str
    references: List[str]
    remediation_summary: str
    created_at: datetime
    updated_at: datetime
    evidence_records: Optional[List[EvidenceRecordResponse]] = []

# --- Assessment Schemas ---
class AssessmentCreate(BaseModel):
    asset_id: str
    title: str
    notes: Optional[str] = ""

class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str
    title: str
    status: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    notes: str
    findings: Optional[List[VulnerabilityFindingResponse]] = []

# --- Digital Twin Schemas ---
class DigitalTwinCreate(BaseModel):
    asset_id: str
    name: str
    template_name: str
    provider: Optional[str] = "mock_isolated"

class DigitalTwinResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str
    name: str
    provider: str
    template_name: str
    status: str
    ip_address: str
    network_isolated: bool
    snapshot_status: str
    target_config: Dict[str, Any]
    current_config: Dict[str, Any]
    config_parity_score: float
    created_at: datetime
    updated_at: datetime

class TwinActionRequest(BaseModel):
    action: str = Field(..., pattern="^(reset_snapshot|create_snapshot|start|stop|sync_config|verify_isolation)$")

# --- Validation Schemas ---
class ValidationProcedureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    procedure_code: str
    name: str
    target_cve: str
    target_component: str
    safety_level: str
    preconditions: str
    description: str
    test_logic_type: str

class ValidationRunCreate(BaseModel):
    finding_id: str
    twin_id: str
    procedure_code: Optional[str] = None

class ValidationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    twin_id: str
    procedure_code: str
    status: str
    outcome: str
    start_time: datetime
    completion_time: datetime
    preconditions_met: bool
    test_output: str
    error_details: str
    limitations: str
    created_at: datetime

# --- Remediation Schemas ---
class RemediationApprovalCreate(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")
    justification: str

class RemediationRecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    action_type: str
    title: str
    description: str
    vendor_advisory_url: str
    prerequisites: List[str]
    compatibility_concerns: str
    command_preview: str
    rollback_instructions: str
    expected_outcome: str
    status: str
    created_at: datetime
    updated_at: datetime

class RemediationApplyRequest(BaseModel):
    twin_id: str
    require_confirmed_validation: Optional[bool] = False

# --- Retest Schemas ---
class RetestRequest(BaseModel):
    finding_id: str
    twin_id: str

class RetestResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str
    twin_id: str
    original_finding_status: str
    post_fix_status: str
    package_version_before: str
    package_version_after: str
    retest_detection_output: str
    retest_validation_output: str
    remaining_risk_score: float
    conclusion: str
    executed_at: datetime

# --- Comparison Schemas ---
class BeforeAfterComparison(BaseModel):
    finding_id: str
    cve_id: str
    component: str
    original_version: str
    new_version: str
    original_status: str
    final_status: str
    original_risk: float
    remaining_risk: float
    remediation_applied: str
    retest_outcome: str
    retest_evidence: str

# --- Audit Event Schemas ---
class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    event_type: str
    action: str
    user_id: Optional[str]
    user_email: str
    ip_address: str
    details: Dict[str, Any]
    created_at: datetime

# --- Dashboard & Metrics Schemas ---
class DashboardMetrics(BaseModel):
    total_assets: int
    total_assessments: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    status_breakdown: Dict[str, int]
    remediation_breakdown: Dict[str, int]
    average_asset_risk: float
    recent_assessments: List[Dict[str, Any]]
    recent_findings: List[Dict[str, Any]]
    recent_audit_events: List[Dict[str, Any]]

# --- Health Schemas ---
class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    database_connected: bool
    twin_provider: str
    ml_model_loaded: bool
    offline_cve_catalog_size: int
    nvd_api_configured: bool
