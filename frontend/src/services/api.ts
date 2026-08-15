import axios from 'axios';

import type {
  AgentStatus,
  AISecurityAnalystOutput,
  ActiveMapRequest,
  ActiveMapResponse,
  ActiveRunRequest,
  AskPhantomScanResponse,
  ActiveScoreResponse,
  AITutorRequest,
  AITutorResponse,
  AuditLog,
  AuthorizedTestJobResponse,
  AuthorizedTestJobResultsResponse,
  AuthorizedTestRunResponse,
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
  AuthorizationStatusResponse,
  ComplianceReportRequestPayload,
  ComplianceReportResponse,
  ComplexityResult,
  ExecutionStatusResponse,
  Finding,
  FindingAIExplanation,
  FindingVerificationResponse,
  GitHubActionsWorkflowResponse,
  GitHubConnectResponse,
  GitHubInstallation,
  GitHubInstallationListResponse,
  GitHubRepoListResponse,
  GitHubStatusResponse,
  HealthResponse,
  JobEvent,
  JobEventsResponse,
  LabManifestResponse,
  LabScenarioRequest,
  LabScenarioResponse,
  LabStatusResponse,
  LearningInsight,
  MultiSourceScanHistoryItem,
  MultiSourceScanPayload,
  MultiSourceScanResponse,
  PRCommentRecord,
  PRDescriptionRequest,
  PRDescriptionResponse,
  RemediationStatus,
  RiskStatus,
  ScanArtifactsResponse,
  ScanHistoryItem,
  ScanQualityReport,
  ScanRequestPayload,
  ScanResponse,
  SelfAuditStatusResponse,
  SourceCorrelationsResponse,
  StopScanResponse
} from '../types';

const configuredBaseUrl =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const baseUrl = configuredBaseUrl
  .replace(/\/api\/?$/, "")
  .replace(/\/$/, "");

export const API_BASE_URL = baseUrl;

export const apiClient = axios.create({
  baseURL: baseUrl,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Auth interceptor - add token to requests
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('phantom_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor - handle 401 errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear auth state and redirect to login
      localStorage.removeItem('phantom_token');
      localStorage.removeItem('phantom_user_role');
      localStorage.removeItem('phantom_username');
      localStorage.removeItem('phantom_user_name');
      localStorage.removeItem('phantom_user_email');
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

export function apiErrorMessage(error: unknown, fallback = 'PhantomScan could not complete the request.'): string {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as unknown;
    if (typeof data === 'string') return data;
    if (data && typeof data === 'object') {
      const record = data as Record<string, unknown>;
      const nested = record.detail;
      if (typeof nested === 'string') return nested;
      if (Array.isArray(nested) && nested.length > 0) {
        const msgs = nested
          .map((item: Record<string, unknown>) => (typeof item?.msg === 'string' ? item.msg : null))
          .filter(Boolean);
        if (msgs.length > 0) return msgs.join('; ');
      }
      if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
        const nestedRecord = nested as Record<string, unknown>;
        if (typeof nestedRecord.message === 'string') return nestedRecord.message;
        if (typeof nestedRecord.code === 'string') return nestedRecord.code;
      }
    }
    return error.message || fallback;
  }
  return error instanceof Error ? error.message : fallback;
}

export function getWebSocketUrl(path: string): string {
  const configured = import.meta.env.VITE_WS_BASE_URL as string | undefined;
  const webSocketBase = (configured || baseUrl.replace(/^http/, 'ws')).replace(/\/$/, '');
  const token = localStorage.getItem('phantom_token');
  const wsPath = path.startsWith('/') ? path : '/' + path;
  const tokenParam = token ? (wsPath.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token) : '';
  return webSocketBase + wsPath + tokenParam;
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/api/health');
  return response.data;
}

export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  const response = await apiClient.get<ScanHistoryItem[]>('/api/scan/history');
  return response.data;
}

export async function getScan(id: number | string): Promise<ScanResponse> {
  const response = await apiClient.get<ScanResponse>(`/api/scan/${id}`);
  return response.data;
}

export async function getScanArtifacts(id: number | string): Promise<ScanArtifactsResponse> {
  const response = await apiClient.get<ScanArtifactsResponse>(`/api/scan/${id}/artifacts`);
  return response.data;
}

export async function getAIAnalysis(id: number | string, refresh = false): Promise<AISecurityAnalystOutput> {
  const response = await apiClient.get<AISecurityAnalystOutput>(`/api/ai/scan/${id}/analysis`, { params: refresh ? { refresh: true } : undefined });
  return response.data;
}

export async function askPhantomScan(id: number | string, question: string): Promise<AskPhantomScanResponse> {
  const response = await apiClient.post<AskPhantomScanResponse>(`/api/ai/scan/${id}/ask`, { question });
  return response.data;
}

export async function explainFinding(findingId: number, language: 'en' | 'hi' = 'en'): Promise<FindingAIExplanation> {
  const response = await apiClient.get<FindingAIExplanation>(`/api/ai/findings/${findingId}/explain`, { params: { language } });
  return response.data;
}

export async function tutorChat(payload: AITutorRequest): Promise<AITutorResponse> {
  const response = await apiClient.post<AITutorResponse>('/api/ai/tutor/chat', payload);
  return response.data;
}

export async function generatePRDescription(scanId: number, payload: PRDescriptionRequest): Promise<PRDescriptionResponse> {
  const response = await apiClient.post<PRDescriptionResponse>(`/api/scan/${scanId}/pr-description`, payload);
  return response.data;
}

export async function getGitHubStatus(): Promise<GitHubStatusResponse> {
  const response = await apiClient.get<GitHubStatusResponse>('/api/github/status');
  return response.data;
}

export async function connectGitHub(): Promise<GitHubConnectResponse> {
  const response = await apiClient.post<GitHubConnectResponse>('/api/github/connect');
  return response.data;
}

export async function listGitHubRepos(): Promise<GitHubRepoListResponse> {
  const response = await apiClient.get<GitHubRepoListResponse>('/api/github/repos');
  return response.data;
}

export async function listGitHubInstallations(): Promise<GitHubInstallation[]> {
  const response = await apiClient.get<GitHubInstallationListResponse>('/api/github/installations');
  return response.data.installations;
}

export async function disconnectGitHub(): Promise<{ status: string }> {
  const response = await apiClient.delete<{ status: string }>('/api/github/disconnect');
  return response.data;
}

export async function startMultiSourceScan(payload: MultiSourceScanPayload): Promise<MultiSourceScanResponse> {
  const response = await apiClient.post<MultiSourceScanResponse>('/api/multi-source/scan', payload);
  return response.data;
}

export async function getMultiSourceHistory(): Promise<MultiSourceScanHistoryItem[]> {
  const response = await apiClient.get<MultiSourceScanHistoryItem[]>('/api/multi-source/history');
  return response.data;
}

export async function getMultiSourceStatus(scanId: number): Promise<MultiSourceScanResponse> {
  const response = await apiClient.get<MultiSourceScanResponse>(`/api/multi-source/${scanId}`);
  return response.data;
}

export async function getSourceCorrelations(scanId: number): Promise<SourceCorrelationsResponse> {
  const response = await apiClient.get<SourceCorrelationsResponse>(`/api/multi-source/${scanId}/correlations`);
  return response.data;
}

export async function stopMultiSourceScan(scanId: number): Promise<{ scan_id: string; status: string }> {
  const response = await apiClient.post<{ scan_id: string; status: string }>(`/api/multi-source/${scanId}/stop`);
  return response.data;
}

export async function getSARIF(scanId: number, download = false): Promise<unknown> {
  const response = await apiClient.get(`/api/ci/scan/${scanId}/sarif`, { params: download ? { download: true } : undefined });
  return response.data;
}

export async function getWorkflowTemplate(): Promise<string> {
  const response = await apiClient.get<string>('/api/ci/workflow/template', { responseType: 'text' });
  return response.data;
}

export async function createComplianceReport(payload: ComplianceReportRequestPayload): Promise<ComplianceReportResponse> {
  const response = await apiClient.post<ComplianceReportResponse>('/api/ci/reports/compliance', payload);
  return response.data;
}

export async function getPRCommentPreview(scanId: number): Promise<{ scan_id: number; comment: string }> {
  const response = await apiClient.get<{ scan_id: number; comment: string }>(`/api/ci/scan/${scanId}/pr-comment`);
  return response.data;
}

export async function listPRComments(scanId: number): Promise<PRCommentRecord[]> {
  const response = await apiClient.get<PRCommentRecord[]>(`/api/ci/scan/${scanId}/pr-comments`);
  return response.data;
}

export async function startScan(payload: ScanRequestPayload): Promise<ScanResponse> {
  const response = await apiClient.post<ScanResponse>('/api/scan/start', payload);
  return response.data;
}

export async function stopScan(id: number | string): Promise<StopScanResponse> {
  const response = await apiClient.post<StopScanResponse>(`/api/scan/${id}/stop`);
  return response.data;
}

export async function getFindings(scanId?: number): Promise<Finding[]> {
  const response = await apiClient.get<Finding[]>('/api/findings', { params: scanId ? { scan_id: scanId } : undefined });
  return response.data;
}

export async function activeMap(payload: ActiveMapRequest): Promise<ActiveMapResponse> {
  const response = await apiClient.post<ActiveMapResponse>('/api/active/map', payload);
  return response.data;
}

export async function activeScore(payload: ActiveMapRequest): Promise<ActiveScoreResponse> {
  const response = await apiClient.post<ActiveScoreResponse>('/api/active/score', payload);
  return response.data;
}

export async function getLabStatus(): Promise<LabStatusResponse> {
  const response = await apiClient.get<LabStatusResponse>('/api/lab/status');
  return response.data;
}

export async function getLabManifest(): Promise<LabManifestResponse> {
  const response = await apiClient.get<LabManifestResponse>('/api/lab/manifest');
  return response.data;
}

export async function setLabScenario(payload: LabScenarioRequest): Promise<LabScenarioResponse> {
  const response = await apiClient.post<LabScenarioResponse>('/api/lab/scenario', payload);
  return response.data;
}

export async function resetLab(): Promise<LabScenarioResponse> {
  const response = await apiClient.post<LabScenarioResponse>('/api/lab/reset');
  return response.data;
}

export async function verifyFindingFix(findingId: number): Promise<FindingVerificationResponse> {
  const response = await apiClient.post<FindingVerificationResponse>(`/api/findings/${findingId}/verify`);
  return response.data;
}

export async function updateFindingRemediation(findingId: number, remediationStatus: RemediationStatus): Promise<Finding> {
  const response = await apiClient.patch<Finding>(`/api/findings/${findingId}/remediation`, {
    remediation_status: remediationStatus
  });
  return response.data;
}

export async function updateFindingRiskStatus(findingId: number, riskStatus: RiskStatus): Promise<Finding> {
  const response = await apiClient.patch<Finding>(`/api/findings/${findingId}/risk`, {
    risk_status: riskStatus
  });
  return response.data;
}

export async function getLogs(scanId?: number): Promise<AuditLog[]> {
  const response = await apiClient.get<AuditLog[]>('/api/logs', { params: scanId ? { scan_id: scanId } : undefined });
  return response.data;
}

export async function getAgentStatuses(scanId?: number): Promise<AgentStatus[]> {
  const response = await apiClient.get<AgentStatus[]>('/api/agents/status', { params: scanId ? { scan_id: scanId } : undefined });
  return response.data;
}

export async function getSelfAuditStatus(): Promise<SelfAuditStatusResponse> {
  const response = await apiClient.get<SelfAuditStatusResponse>('/api/self-audit/status');
  return response.data;
}

export async function createAuthorizationChallenge(
  payload: AuthorizationChallengeRequest
): Promise<AuthorizationChallengeResponse> {
  const response = await apiClient.post<AuthorizationChallengeResponse>('/api/authorization/challenge', payload);
  return response.data;
}

export async function verifyAuthorization(id: number): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.post<AuthorizationStatusResponse>(`/api/authorization/${id}/verify`);
  return response.data;
}

export async function getAuthorizationStatus(targetUrl: string): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.get<AuthorizationStatusResponse>('/api/authorization/status', {
    params: { target_url: targetUrl }
  });
  return response.data;
}

export async function revokeAuthorization(id: number): Promise<AuthorizationStatusResponse> {
  const response = await apiClient.post<AuthorizationStatusResponse>(`/api/authorization/${id}/revoke`);
  return response.data;
}

export async function startAuthorizedTest(payload: ActiveRunRequest): Promise<AuthorizedTestRunResponse> {
  const response = await apiClient.post<AuthorizedTestRunResponse>('/api/active/run', payload);
  return response.data;
}

export async function getAuthorizedTestJobStatus(jobId: string): Promise<AuthorizedTestJobResponse> {
  const response = await apiClient.get<AuthorizedTestJobResponse>(`/api/active/jobs/${jobId}`);
  return response.data;
}

export async function getAuthorizedTestJobResults(jobId: string): Promise<AuthorizedTestJobResultsResponse> {
  const response = await apiClient.get<AuthorizedTestJobResultsResponse>(`/api/active/jobs/${jobId}/results`);
  return response.data;
}

export async function getExecutionStatus(): Promise<ExecutionStatusResponse> {
  const response = await apiClient.get<ExecutionStatusResponse>('/api/execution/status');
  return response.data;
}

export async function getJobEvents(jobId: string, afterSequence = 0): Promise<JobEventsResponse> {
  const response = await apiClient.get<JobEventsResponse>(`/api/active/jobs/${jobId}/events`, {
    params: { after_sequence: afterSequence }
  });
  return response.data;
}

export async function addToPrivateScope(targetUrl: string): Promise<{ success: boolean; message: string; target_url: string }> {
  const response = await apiClient.post('/api/admin/scope/add', { target_url: targetUrl });
  return response.data;
}

export async function listPrivateScope(): Promise<Array<{ id: number; target_url: string; added_by: string; added_at: string | null; last_used: string | null }>> {
  const response = await apiClient.get('/api/admin/scope/list');
  return response.data;
}

export async function removeFromPrivateScope(targetUrl: string): Promise<{ success: boolean; message: string }> {
  const response = await apiClient.delete('/api/admin/scope/remove', { params: { target_url: targetUrl } });
  return response.data;
}

export async function getUserRole(): Promise<{ role: string }> {
  const response = await apiClient.get('/api/admin/scope/role');
  return response.data;
}

export async function startDos(targetUrl: string, intensity: string, duration: number): Promise<any> {
  const response = await apiClient.post('/api/admin/dos/start', { target_url: targetUrl, intensity, duration });
  return response.data;
}

export async function stopDos(jobId: string): Promise<any> {
  const response = await apiClient.post(`/api/admin/dos/stop/${jobId}`);
  return response.data;
}

export async function getDosStatus(jobId: string): Promise<any> {
  const response = await apiClient.get(`/api/admin/dos/status/${jobId}`);
  return response.data;
}

export async function getDosHistory(): Promise<any[]> {
  const response = await apiClient.get('/api/admin/dos/history');
  return response.data;
}

export async function getJobEvidence(jobId: string, findingId?: number): Promise<any[]> {
  const response = await apiClient.get(`/api/active/jobs/${jobId}/evidence`, {
    params: findingId ? { finding_id: findingId } : {}
  });
  return response.data;
}

export async function activeComplexity(payload: ActiveMapRequest): Promise<ComplexityResult> {
  const response = await apiClient.post<ComplexityResult>('/api/active/complexity', payload);
  return response.data;
}

export async function getLearningInsights(scanId?: number, status?: string): Promise<LearningInsight[]> {
  const response = await apiClient.get<LearningInsight[]>('/api/learning/insights', {
    params: { scan_id: scanId ?? undefined, status: status ?? undefined }
  });
  return response.data;
}

export async function applyLearningInsight(
  insightId: number,
  appliedSettings?: Record<string, unknown>
): Promise<LearningInsight> {
  const response = await apiClient.post<LearningInsight>(`/api/learning/insights/${insightId}/apply`, {
    applied_settings: appliedSettings
  });
  return response.data;
}

export async function dismissLearningInsight(insightId: number): Promise<LearningInsight> {
  const response = await apiClient.post<LearningInsight>(`/api/learning/insights/${insightId}/dismiss`);
  return response.data;
}

export async function getScanQualityReport(): Promise<ScanQualityReport> {
  const response = await apiClient.get<ScanQualityReport>('/api/learning/quality');
  return response.data;
}
