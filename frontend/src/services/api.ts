import axios from 'axios';
import {
  Asset, Assessment, VulnerabilityFinding, DigitalTwin, ValidationRun,
  RemediationRecommendation, RetestResult, BeforeAfterComparison,
  DashboardMetrics, AuditEvent, SystemSettings, User
} from '../types';

const API_BASE_URL = '/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT token from localStorage if present
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('vuln_twin_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 unauthorized
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear token if expired/invalid
      localStorage.removeItem('vuln_twin_token');
      localStorage.removeItem('vuln_twin_user');
    }
    return Promise.reject(error);
  }
);

export const api = {
  // Auth
  login: async (email: string, password: string) => {
    const res = await apiClient.post('/auth/login', { email, password });
    if (res.data.access_token) {
      localStorage.setItem('vuln_twin_token', res.data.access_token);
      localStorage.setItem('vuln_twin_user', JSON.stringify(res.data.user));
    }
    return res.data;
  },
  register: async (email: string, password: string, full_name: string, role = 'analyst') => {
    const res = await apiClient.post('/auth/register', { email, password, full_name, role });
    return res.data;
  },
  getCurrentUser: async (): Promise<User> => {
    const res = await apiClient.get('/auth/me');
    return res.data;
  },
  logout: () => {
    localStorage.removeItem('vuln_twin_token');
    localStorage.removeItem('vuln_twin_user');
  },

  // Dashboard
  getDashboardMetrics: async (): Promise<DashboardMetrics> => {
    const res = await apiClient.get('/dashboard/metrics');
    return res.data;
  },

  // Assets
  getAssets: async (): Promise<Asset[]> => {
    const res = await apiClient.get('/assets');
    return res.data;
  },
  getAsset: async (id: string): Promise<Asset> => {
    const res = await apiClient.get(`/assets/${id}`);
    return res.data;
  },
  createAsset: async (data: Partial<Asset>): Promise<Asset> => {
    const res = await apiClient.post('/assets', data);
    return res.data;
  },
  deleteAsset: async (id: string) => {
    const res = await apiClient.delete(`/assets/${id}`);
    return res.data;
  },
  importInventory: async (assetId: string, formData: FormData) => {
    const res = await apiClient.post(`/assets/${assetId}/inventory`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },
  getAssetSnapshots: async (assetId: string) => {
    const res = await apiClient.get(`/assets/${assetId}/snapshots`);
    return res.data;
  },

  // Assessments
  getAssessments: async (assetId?: string): Promise<Assessment[]> => {
    const res = await apiClient.get('/assessments', { params: { asset_id: assetId } });
    return res.data;
  },
  getAssessment: async (id: string): Promise<Assessment> => {
    const res = await apiClient.get(`/assessments/${id}`);
    return res.data;
  },
  runAssessment: async (assetId: string, title?: string, notes?: string): Promise<Assessment> => {
    const res = await apiClient.post('/assessments', { asset_id: assetId, title, notes });
    return res.data;
  },

  // Vulnerabilities
  getVulnerabilities: async (params?: {
    asset_id?: string;
    assessment_id?: string;
    severity?: string;
    detection_status?: string;
    search?: string;
  }): Promise<VulnerabilityFinding[]> => {
    const res = await apiClient.get('/vulnerabilities', { params });
    return res.data;
  },
  getVulnerability: async (id: string): Promise<VulnerabilityFinding> => {
    const res = await apiClient.get(`/vulnerabilities/${id}`);
    return res.data;
  },
  getFindingEvidence: async (id: string) => {
    const res = await apiClient.get(`/vulnerabilities/${id}/evidence`);
    return res.data;
  },

  // AI/ML Risk Simulator
  evaluateRisk: async (data: any) => {
    const res = await apiClient.post('/risk/evaluate', data);
    return res.data;
  },

  // Digital Twins
  getTwins: async (assetId?: string): Promise<DigitalTwin[]> => {
    const res = await apiClient.get('/twins', { params: { asset_id: assetId } });
    return res.data;
  },
  getTwinTemplates: async () => {
    const res = await apiClient.get('/twins/templates');
    return res.data;
  },
  createTwin: async (data: { asset_id: string; name: string; template_name: string }): Promise<DigitalTwin> => {
    const res = await apiClient.post('/twins', data);
    return res.data;
  },
  executeTwinAction: async (twinId: string, action: string) => {
    const res = await apiClient.post(`/twins/${twinId}/actions`, { action });
    return res.data;
  },

  // Controlled Validation
  getValidationProcedures: async () => {
    const res = await apiClient.get('/validation/procedures');
    return res.data;
  },
  getValidationRuns: async (findingId?: string, twinId?: string): Promise<ValidationRun[]> => {
    const res = await apiClient.get('/validation/runs', { params: { finding_id: findingId, twin_id: twinId } });
    return res.data;
  },
  executeValidation: async (findingId: string, twinId: string, procedureCode?: string): Promise<ValidationRun> => {
    const res = await apiClient.post('/validation/execute', {
      finding_id: findingId,
      twin_id: twinId,
      procedure_code: procedureCode,
    });
    return res.data;
  },

  // Remediation
  getRemediations: async (findingId?: string, status?: string): Promise<RemediationRecommendation[]> => {
    const res = await apiClient.get('/remediation/recommendations', { params: { finding_id: findingId, status } });
    return res.data;
  },
  reviewRemediation: async (recId: string, status: 'approved' | 'rejected', justification: string) => {
    const res = await apiClient.post(`/remediation/recommendations/${recId}/approval`, { status, justification });
    return res.data;
  },
  applyRemediationInTwin: async (recId: string, twinId: string) => {
    const res = await apiClient.post(`/remediation/recommendations/${recId}/apply-in-twin`, { twin_id: twinId });
    return res.data;
  },

  // Retesting & Verification
  getRetestResults: async (findingId?: string, twinId?: string): Promise<RetestResult[]> => {
    const res = await apiClient.get('/retesting/results', { params: { finding_id: findingId, twin_id: twinId } });
    return res.data;
  },
  executeRetest: async (findingId: string, twinId: string): Promise<RetestResult> => {
    const res = await apiClient.post('/retesting/execute', { finding_id: findingId, twin_id: twinId });
    return res.data;
  },
  getBeforeAfterComparison: async (findingId: string): Promise<BeforeAfterComparison> => {
    const res = await apiClient.get(`/retesting/comparison/${findingId}`);
    return res.data;
  },

  // Reports
  downloadPdfReport: (assessmentId: string) => {
    window.open(`${API_BASE_URL}/reports/assessments/${assessmentId}/pdf`, '_blank');
  },
  downloadCsvReport: (assessmentId: string) => {
    window.open(`${API_BASE_URL}/reports/assessments/${assessmentId}/csv`, '_blank');
  },

  // Audit Logs
  getAuditLogs: async (eventType?: string): Promise<AuditEvent[]> => {
    const res = await apiClient.get('/audit', { params: { event_type: eventType } });
    return res.data;
  },

  // Settings & Health
  getSettings: async (): Promise<SystemSettings> => {
    const res = await apiClient.get('/settings');
    return res.data;
  },
  getHealth: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  },
};
