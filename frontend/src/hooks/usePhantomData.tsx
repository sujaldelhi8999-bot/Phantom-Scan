import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';

import {
  getAgentStatuses,
  getExecutionStatus,
  getFindings,
  getHealth,
  getLogs,
  getScanArtifacts,
  getScanHistory,
  getSelfAuditStatus,
  getWebSocketUrl
} from '../services/api';
import type {
  AgentStatus,
  AuditLog,
  ConnectionState,
  ExecutionLifecycle,
  ExecutionStatusResponse,
  Finding,
  HealthResponse,
  ScanArtifactsResponse,
  ScanHistoryItem,
  SelfAuditStatusResponse
} from '../types';

const EXECUTION_POLL_INTERVAL = 2000;
const TERMINAL_EXECUTION: ExecutionLifecycle[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
const ACTIVE_EXECUTION: ExecutionLifecycle[] = ['QUEUED', 'STARTING', 'RUNNING', 'PAUSED'];

interface PhantomDataContextValue {
  health: HealthResponse | null;
  scans: ScanHistoryItem[];
  findings: Finding[];
  logs: AuditLog[];
  agents: AgentStatus[];
  selfAudit: SelfAuditStatusResponse | null;
  artifactsByScanId: Record<number, ScanArtifactsResponse>;
  loading: boolean;
  refreshing: boolean;
  error: string | null;
  realtimeState: ConnectionState;
  realtimeHealthy: boolean;
  refresh: () => Promise<void>;
  executionStatus: ExecutionStatusResponse | null;
  executionActive: boolean;
}

const PhantomDataContext = createContext<PhantomDataContextValue | null>(null);

function isHealthResponse(value: unknown): value is HealthResponse {
  return typeof value === 'object' && value !== null && 'database' in value && 'scheduler' in value;
}

export function PhantomDataProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [selfAudit, setSelfAudit] = useState<SelfAuditStatusResponse | null>(null);
  const [artifactsByScanId, setArtifactsByScanId] = useState<Record<number, ScanArtifactsResponse>>({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [realtimeState, setRealtimeState] = useState<ConnectionState>('idle');
  const [executionStatus, setExecutionStatus] = useState<ExecutionStatusResponse | null>(null);
  const refreshInFlight = useRef(false);
  const execPollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = async () => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try {
      const [healthResult, scansResult, findingsResult, logsResult, agentsResult, selfAuditResult] = await Promise.allSettled([
        getHealth(),
        getScanHistory(),
        getFindings(),
        getLogs(),
        getAgentStatuses(),
        getSelfAuditStatus()
      ]);

      if (healthResult.status === 'fulfilled') setHealth(healthResult.value);
      if (scansResult.status === 'fulfilled') setScans(scansResult.value);
      if (findingsResult.status === 'fulfilled') setFindings(findingsResult.value);
      if (logsResult.status === 'fulfilled') setLogs(logsResult.value);
      if (agentsResult.status === 'fulfilled') setAgents(agentsResult.value);
      if (selfAuditResult.status === 'fulfilled') setSelfAudit(selfAuditResult.value);

      const failures = [healthResult, scansResult, findingsResult, logsResult, agentsResult, selfAuditResult].filter(
        (result) => result.status === 'rejected'
      );
      setError(failures.length ? 'Some PhantomScan backend data could not be refreshed.' : null);

      const artifactScans = scansResult.status === 'fulfilled' ? scansResult.value.slice(0, 8) : scans.slice(0, 8);
      const artifactResults = await Promise.allSettled(artifactScans.map((scan) => getScanArtifacts(scan.id)));
      const nextArtifacts: Record<number, ScanArtifactsResponse> = {};
      for (const result of artifactResults) {
        if (result.status === 'fulfilled') {
          nextArtifacts[result.value.scan_id] = result.value;
        }
      }
      setArtifactsByScanId((current) => ({ ...current, ...nextArtifacts }));
    } finally {
      setLoading(false);
      setRefreshing(false);
      refreshInFlight.current = false;
    }
  };

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnect: number | undefined;
    let active = true;

    const connect = () => {
      if (!active) return;
      setRealtimeState('connecting');
      try {
        socket = new WebSocket(getWebSocketUrl('/ws/status'));
      } catch {
        setRealtimeState('error');
        reconnect = window.setTimeout(connect, 5000);
        return;
      }
      socket.onopen = () => setRealtimeState('open');
      socket.onerror = () => setRealtimeState('error');
      socket.onmessage = (event: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(event.data) as Record<string, unknown>;
          const payload = typeof parsed.payload === 'object' && parsed.payload !== null ? parsed.payload : parsed;
          if (isHealthResponse(payload)) setHealth(payload);
        } catch {
          setRealtimeState('error');
        }
      };
      socket.onclose = () => {
        if (!active) return;
        setRealtimeState('closed');
        reconnect = window.setTimeout(connect, 5000);
      };
    };

    connect();
    return () => {
      active = false;
      if (reconnect) window.clearTimeout(reconnect);
      socket?.close();
    };
  }, []);

  const realtimeHealthy = realtimeState === 'open' && health?.status === 'ok';

  const execActive = executionStatus ? ACTIVE_EXECUTION.includes(executionStatus.lifecycle) : false;

  const fetchExecutionStatus = async () => {
    try {
      const result = await getExecutionStatus();
      if (result) {
        setExecutionStatus(result);
        if (TERMINAL_EXECUTION.includes(result.lifecycle)) {
          if (execPollingRef.current) {
            clearInterval(execPollingRef.current);
            execPollingRef.current = null;
          }
        }
      }
    } catch {
      // silent
    }
  };

  useEffect(() => {
    const startPolling = () => {
      if (execPollingRef.current) {
        clearInterval(execPollingRef.current);
        execPollingRef.current = null;
      }
      execPollingRef.current = setInterval(() => void fetchExecutionStatus(), EXECUTION_POLL_INTERVAL);
    };

    fetchExecutionStatus().then(() => {
      if (execActive && !execPollingRef.current) {
        startPolling();
      }
    });

    return () => {
      if (execPollingRef.current) {
        clearInterval(execPollingRef.current);
        execPollingRef.current = null;
      }
    };
  }, [execActive]);

  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        void fetchExecutionStatus();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, []);

  // When refresh is called, also refetch execution status
  const origRefresh = refresh;
  const superRefresh = async () => {
    await origRefresh();
    await fetchExecutionStatus();
  };

  return (
    <PhantomDataContext.Provider
      value={{
        health,
        scans,
        findings,
        logs,
        agents,
        selfAudit,
        artifactsByScanId,
        loading,
        refreshing,
        error,
        realtimeState,
        realtimeHealthy,
        refresh: superRefresh,
        executionStatus,
        executionActive: execActive,
      }}
    >
      {children}
    </PhantomDataContext.Provider>
  );
}

export function usePhantomData() {
  const context = useContext(PhantomDataContext);
  if (!context) throw new Error('usePhantomData must be used inside PhantomDataProvider');
  return context;
}
