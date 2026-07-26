import axios from 'axios';

import type {
  AgentStatus,
  AISecurityAnalystOutput,
  ActiveMapRequest,
  ActiveMapResponse,
  AskPhantomScanResponse,
  ActiveScoreResponse,
  AuditLog,
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
  AuthorizationStatusResponse,
  Finding,
  FindingAIExplanation,
  FindingVerificationResponse,
  HealthResponse,
  LabManifestResponse,
  LabScenarioRequest,
  LabScenarioResponse,
  LabStatusResponse,
  RemediationStatus,
  RiskStatus,
  ScanArtifactsResponse,
  ScanHistoryItem,
  ScanRequestPayload,
  ScanResponse,
  SelfAuditStatusResponse,
  StopScanResponse
} from '../types';

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL || 'https://phantom-scan-backend.onrender.com';
const baseUrl = configuredBaseUrl.replace(/\/api\/?$/, '').replace(/\/$/, '');
export const API_BASE_URL = baseUrl;

export const apiClient = axios.create({
  baseURL: baseUrl,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

export function apiErrorMessage(error: unknown, fallback = 'PhantomScan could not complete the request.'): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data as unknown;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail === 'object') {
      const record = detail as Record<string, unknown>;
      const nested = record.detail;
      if (typeof nested === 'string') return nested;
      if (nested && typeof nested === 'object') {
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
  return `${webSocketBase}${path.startsWith('/') ? path : `/${path}`}`;
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
