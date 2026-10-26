export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DetectionStatus = 'detected' | 'suspected' | 'confirmed' | 'fixed' | 'unresolved' | 'inconclusive';

export type RemediationStatus = 'recommended' | 'awaiting_approval' | 'approved' | 'applied_in_twin' | 'resolved' | 'failed' | 'rejected';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
}

export interface Asset {
  id: string;
  name: string;
  ip_address: string;
  hostname: string;
  os_type: 'linux' | 'windows';
  os_version: string;
  environment: 'production' | 'staging' | 'development';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface InventoryPackage {
  name: string;
  version: string;
  architecture: string;
  status: string;
  description?: string;
}

export interface InventorySnapshot {
  id: string;
  asset_id: string;
  format: string;
  raw_filename: string;
  packages_count: number;
  parsed_packages: InventoryPackage[];
  configuration_metadata: Record<string, any>;
  created_at: string;
}

export interface EvidenceRecord {
  id: string;
  finding_id: string;
  evidence_type: string;
  title: string;
  raw_evidence: string;
  metadata_info: Record<string, any>;
  collected_at: string;
}

export interface VulnerabilityFinding {
  id: string;
  assessment_id: string;
  asset_id: string;
  cve_id: string;
  title: string;
  affected_component: string;
  installed_version: string;
  fixed_version: string;
  cvss_v3_score: number;
  cvss_v3_vector: string;
  severity: Severity;
  detection_status: DetectionStatus;
  risk_score: number;
  risk_category: string;
  confidence_score: number;
  contributing_factors: Record<string, any>;
  recommended_priority: string;
  risk_explanation: string;
  description: string;
  references: string[];
  remediation_summary: string;
  created_at: string;
  updated_at: string;
  evidence_records?: EvidenceRecord[];
}

export interface Assessment {
  id: string;
  asset_id: string;
  title: string;
  status: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  average_risk_score: number;
  started_at: string;
  completed_at?: string;
  notes: string;
  findings?: VulnerabilityFinding[];
}

export interface DigitalTwin {
  id: string;
  asset_id: string;
  name: string;
  provider: string;
  template_name: string;
  status: string;
  ip_address: string;
  network_isolated: boolean;
  snapshot_status: string;
  target_config: Record<string, any>;
  current_config: Record<string, any>;
  config_parity_score: number;
  created_at: string;
  updated_at: string;
}

export interface ValidationProcedure {
  procedure_code: string;
  name: string;
  cve_id: string;
  component: string;
  safety_level: string;
  preconditions: string;
  description: string;
  safe_probe: string;
}

export interface ValidationRun {
  id: string;
  finding_id: string;
  twin_id: string;
  procedure_code: string;
  status: string;
  outcome: 'confirmed' | 'not_reproduced' | 'inconclusive' | 'not_tested';
  start_time: string;
  completion_time: string;
  preconditions_met: boolean;
  test_output: string;
  error_details: string;
  limitations: string;
  created_at: string;
}

export interface RemediationRecommendation {
  id: string;
  finding_id: string;
  action_type: string;
  title: string;
  description: string;
  vendor_advisory_url: string;
  prerequisites: string[];
  compatibility_concerns: string;
  command_preview: string;
  rollback_instructions: string;
  expected_outcome: string;
  status: RemediationStatus;
  created_at: string;
  updated_at: string;
}

export interface RetestResult {
  id: string;
  finding_id: string;
  twin_id: string;
  original_finding_status: string;
  post_fix_status: 'resolved' | 'remains_present' | 'inconclusive';
  package_version_before: string;
  package_version_after: string;
  retest_detection_output: string;
  retest_validation_output: string;
  remaining_risk_score: number;
  conclusion: string;
  executed_at: string;
}

export interface BeforeAfterComparison {
  finding_id: string;
  cve_id: string;
  component: string;
  original_version: string;
  new_version: string;
  original_status: string;
  final_status: string;
  original_risk: number;
  remaining_risk: number;
  remediation_applied: string;
  retest_outcome: string;
  retest_evidence: string;
}

export interface DashboardMetrics {
  total_assets: number;
  total_assessments: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  status_breakdown: Record<string, number>;
  remediation_breakdown: Record<string, number>;
  average_risk_score: number;
  severity_distribution: Array<{ name: string; count: number; color: string }>;
  status_distribution: Array<{ name: string; count: number; color: string }>;
  recent_assessments: any[];
  recent_findings: any[];
  recent_audit_events: any[];
}

export interface AuditEvent {
  id: string;
  event_type: string;
  action: string;
  user_email: string;
  ip_address: string;
  details: Record<string, any>;
  created_at: string;
}

export interface SystemSettings {
  project_name: string;
  version: string;
  database_backend: string;
  twin_provider: string;
  twin_isolation_network: string;
  nvd_api_connected: boolean;
  nvd_api_key_configured: boolean;
  nvd_timeout_seconds: number;
  max_validation_timeout: number;
  ml_model_status: string;
  offline_cve_catalog: string;
  supported_os_types: string[];
}
