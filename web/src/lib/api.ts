/**
 * AutoSecTwin / VulnTwin AI Backend API Client
 * Connects Next.js frontend with the FastAPI backend engine.
 */

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8001/api/v1';

export interface UserQuotaResponse {
  user_identifier: string;
  role: string;
  scans_today: number;
  daily_limit: number;
  remaining_scans: number;
  unlimited: boolean;
  can_analyze: boolean;
}

export interface AttackStage {
  stage: string;
  name: string;
  mitre_id: string;
  mitre_technique: string;
  description: string;
  attacker_cost: string;
  likelihood: string;
}

export interface ExploitabilityAssessment {
  feasibility_score: number;
  barrier_to_exploit: string;
  required_access: string;
  mitre_stages: AttackStage[];
}

export interface AnalysisResponse {
  analysis_id: string;
  target: string;
  target_type: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  risk_score: number;
  confidence: number;
  summary: string;
  analyzed_at: string;
  indicators: Record<string, unknown>;
  evidence: Array<{
    category: string;
    description: string;
    severity: string;
    points: number;
  }>;
  recommendations: Array<{
    priority: string;
    action: string;
    category: string;
  }>;
  exploitability?: ExploitabilityAssessment;
  quota?: UserQuotaResponse;
}

export interface TwinComponent {
  id: string;
  name: string;
  type: string;
  status: 'HEALTHY' | 'VULNERABLE' | 'PATCHED' | 'PROBING';
  controls: Array<{ name: string; active: boolean }>;
}

export interface TwinFinding {
  id: string;
  title: string;
  severity: string;
  risk_points: number;
  component_id: string;
  component_name: string;
  root_cause: string;
  impact: string;
  remediation: string;
  priority: string;
  verified_on_twin: boolean;
  verification_log: string;
  status: 'OPEN' | 'RESOLVED' | 'VERIFIED_SAFE';
}

export interface DigitalTwinModel {
  twin_id: string;
  target: string;
  risk_score: number;
  verdict: string;
  initial_posture: number;
  current_posture: number;
  components: TwinComponent[];
  findings: TwinFinding[];
  remediations: Array<{
    id: string;
    title: string;
    finding_id: string;
    action_type: string;
    status: string;
  }>;
  before_after_delta?: {
    before_risk_score: number;
    after_risk_score: number;
    before_posture: number;
    after_posture: number;
    posture_improvement_points: number;
    open_findings_before: number;
    open_findings_after: number;
    status: string;
  };
}

export interface SafePathVendor {
  key: string;
  software_name: string;
  vendor: string;
  official_domain: string;
  official_url: string;
  trust_level: string;
  baseline_risk: number;
}

export interface SafePathCatalogResponse {
  catalog_count: number;
  disclaimer: string;
  vendors: SafePathVendor[];
}

export class ApiClient {
  private baseUrl: string;

  constructor(baseUrl = API_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private getHeaders(userIdentifier?: string, role?: string, token?: string): HeadersInit {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    if (userIdentifier) {
      headers['x-user-identifier'] = userIdentifier;
    }
    if (role) {
      headers['x-user-role'] = role;
    }
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
  }

  async checkHealth(): Promise<{ status: string; project: string; version: string }> {
    const res = await fetch(`${this.baseUrl}/health`, {
      method: 'GET',
    });
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return res.json();
  }

  async getQuota(userIdentifier = 'anonymous', role = 'user'): Promise<UserQuotaResponse> {
    const res = await fetch(`${this.baseUrl}/user/quota`, {
      method: 'GET',
      headers: this.getHeaders(userIdentifier, role),
    });
    if (!res.ok) throw new Error(`Failed to retrieve quota: ${res.statusText}`);
    return res.json();
  }

  async analyzeUrl(
    url: string,
    options?: { forceRefresh?: boolean; userIdentifier?: string; role?: string; token?: string }
  ): Promise<AnalysisResponse> {
    const res = await fetch(`${this.baseUrl}/analyze/url`, {
      method: 'POST',
      headers: this.getHeaders(options?.userIdentifier, options?.role, options?.token),
      body: JSON.stringify({
        url,
        force_refresh: options?.forceRefresh ?? false,
      }),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Analysis failed with HTTP status ${res.status}`);
    }

    return res.json();
  }

  async analyzeHash(
    hashValue: string,
    options?: { userIdentifier?: string; role?: string; token?: string }
  ): Promise<AnalysisResponse> {
    const res = await fetch(`${this.baseUrl}/analyze/hash`, {
      method: 'POST',
      headers: this.getHeaders(options?.userIdentifier, options?.role, options?.token),
      body: JSON.stringify({ hash: hashValue }),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Hash analysis failed with HTTP status ${res.status}`);
    }

    return res.json();
  }

  async createTwin(
    target: string,
    riskScore: number,
    verdict: string,
    indicators: Record<string, unknown> = {}
  ): Promise<DigitalTwinModel> {
    const res = await fetch(`${this.baseUrl}/twin/create`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        target,
        risk_score: riskScore,
        verdict,
        indicators,
      }),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Twin creation failed: ${res.statusText}`);
    }

    return res.json();
  }

  async remediateTwin(twinId: string): Promise<DigitalTwinModel> {
    const res = await fetch(`${this.baseUrl}/twin/remediate`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ twin_id: twinId }),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Remediation execution failed: ${res.statusText}`);
    }

    return res.json();
  }

  async getSafePathCatalog(): Promise<SafePathCatalogResponse> {
    const res = await fetch(`${this.baseUrl}/safepath/catalog`, {
      method: 'GET',
    });

    if (!res.ok) {
      throw new Error(`Failed to retrieve SafePath catalog: ${res.statusText}`);
    }

    return res.json();
  }
}

export const api = new ApiClient();
