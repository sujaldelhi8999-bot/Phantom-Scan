import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Code2,
  ExternalLink,
  FileSearch,
  GitBranch,
  Lock,
  RefreshCw,
  ScanLine,
  ShieldCheck,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { useAuth } from '../../context/AuthContext';
import { apiClient, apiErrorMessage } from '../../services/api';
import {
  Button,
  EmptyState,
  ErrorState,
  Input,
  Page,
  PageHeader,
  Panel,
  SeverityBadge,
} from '../../components/ui/Primitives';

interface SastSource {
  source_type: string;
  source_identifier: string;
  status: string;
  findings_count: number;
  findings_by_severity: Record<string, number>;
  scan_duration_seconds: number;
  error_message: string | null;
  artifacts: Record<string, unknown>;
}

interface SastFinding {
  id: number;
  title: string;
  severity: string;
  category: string;
  confidence: string;
  target: string;
  endpoint: string;
  evidence: string;
  impact: string;
  module: string | null;
  cwe: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  recommended_fix: string | null;
  recommendation: string | null;
}

interface SastScan {
  scan_id: number;
  repo_url: string;
  overall_status: string;
  overall_progress: number;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  sources: SastSource[];
  findings: SastFinding[];
  error_message?: string | null;
}

const TERMINAL = new Set(['complete', 'error', 'cancelled']);

const toolLabels: Record<string, string> = {
  semgrep: 'Static Analysis',
  trufflehog: 'Secrets',
  gitleaks: 'Secrets',
  'pip-audit': 'Dependencies',
  'npm-audit': 'Dependencies',
};

function severityColor(severity: string) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    INFO: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
  };
  return map[severity?.toUpperCase()] ?? map.INFO;
}

export default function CodeAnalysis() {
  const { user } = useAuth();
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [starting, setStarting] = useState(false);
  const [scan, setScan] = useState<SastScan | null>(null);
  const [error, setError] = useState('');
  const [polling, setPolling] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, []);

  const startScan = async () => {
    if (!repoUrl.trim()) return;
    setStarting(true);
    setError('');
    setScan(null);
    try {
      const response = await apiClient.post<{ scan_id: number }>('/api/sast/scan-repo', null, {
        params: { repo_url: repoUrl.trim(), branch: branch.trim() || 'main' },
      });
      setScan({
        scan_id: response.data.scan_id,
        repo_url: repoUrl.trim(),
        overall_status: 'queued',
        overall_progress: 0,
        total_findings: 0,
        findings_by_severity: {},
        sources: [],
        findings: [],
      });
      toast.success('Repository scan started');
      setPolling(true);
    } catch (err) {
      const msg = apiErrorMessage(err, 'Failed to start repository scan');
      setError(msg);
      toast.error(msg);
    } finally {
      setStarting(false);
    }
  };

  useEffect(() => {
    if (!polling || !scan) return;
    let cancelled = false;

    const poll = async () => {
      try {
        const response = await apiClient.get<SastScan>(`/api/sast/${scan.scan_id}`);
        if (cancelled) return;
        setScan((prev) => (prev ? { ...prev, ...response.data } : response.data));
        if (TERMINAL.has(response.data.overall_status)) {
          setPolling(false);
          if (response.data.overall_status === 'complete') {
            toast.success(`Scan complete — ${response.data.total_findings} findings`);
          } else {
            toast.error(`Scan ended: ${response.data.overall_status}`);
          }
        }
      } catch (err) {
        if (cancelled) return;
        const msg = apiErrorMessage(err, 'Failed to fetch scan status');
        setError(msg);
        setPolling(false);
      }
    };

    poll();
    pollTimer.current = setInterval(poll, 4000);
    return () => {
      cancelled = true;
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [polling, scan?.scan_id]);

  if (!user || user.role !== 'admin') {
    return (
      <Page>
        <PageHeader title="Code Analysis" description="Admin-only feature" />
        <Panel>
          <div className="flex items-center gap-3 p-6">
            <Lock className="h-5 w-5 text-red-500" />
            <div>
              <p className="text-sm font-semibold text-red-600 dark:text-red-400">Admin access required</p>
              <p className="text-xs text-[var(--text-muted)]">Log in as admin to scan GitHub repositories.</p>
            </div>
          </div>
        </Panel>
      </Page>
    );
  }

  const active = scan && !TERMINAL.has(scan.overall_status);

  return (
    <Page>
      <PageHeader
        title="Code Analysis"
        description="Clone a public GitHub repository and scan it for secrets, insecure patterns, and vulnerable dependencies."
      />

      <div className="space-y-5">
        <Panel>
          <div className="p-4">
            <label className="mb-1.5 block text-xs font-medium text-[var(--text-default)]">GitHub repository URL</label>
            <div className="flex gap-2">
              <Input
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="flex-1 font-mono"
                onKeyDown={(e) => { if (e.key === 'Enter') startScan(); }}
              />
              <Input
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
                className="w-28 font-mono"
                aria-label="Branch"
              />
              <Button variant="primary" onClick={startScan} disabled={starting || polling || !repoUrl.trim()}>
                {starting ? (
                  <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Starting...</>
                ) : (
                  <><ScanLine className="h-3.5 w-3.5" /> Scan Repository</>
                )}
              </Button>
            </div>
            <p className="mt-2 flex items-center gap-1.5 text-[11px] text-[var(--text-subtle)]">
              <GitBranch className="h-3 w-3" />
              Runs Semgrep, TruffleHog, Gitleaks, pip-audit / npm-audit, and IaC rules against the cloned repo.
            </p>
          </div>
        </Panel>

        {error ? <ErrorState title="Code analysis failed" description={error} /> : null}

        {!scan ? (
          <Panel>
            <EmptyState
              icon={<Code2 className="h-5 w-5" />}
              title="No repository scanned yet"
              description="Paste a public GitHub repository URL above (e.g. https://github.com/expressjs/express) and start a scan."
            />
          </Panel>
        ) : (
          <>
            {/* Scan status */}
            <Panel>
              <div className="p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span
                      className={`flex h-2 w-2 shrink-0 rounded-full ${
                        scan.overall_status === 'complete' ? 'bg-green-500' : active ? 'animate-pulse bg-amber-500' : 'bg-red-500'
                      }`}
                    />
                    <span className="truncate font-mono text-xs text-[var(--text-default)]">{scan.repo_url}</span>
                    <span className="rounded-md bg-[var(--surface-tertiary)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                      {scan.overall_status}
                    </span>
                  </div>
                  {active ? (
                    <div className="flex items-center gap-3">
                      <div className="h-1.5 w-40 overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                        <div
                          className="h-full rounded-full bg-[var(--brand)] transition-all"
                          style={{ width: `${Math.max(3, scan.overall_progress)}%` }}
                        />
                      </div>
                      <span className="text-[11px] font-medium text-[var(--text-muted)]">{scan.overall_progress}%</span>
                    </div>
                  ) : null}
                  <div className="flex items-center gap-3 text-xs">
                    {scan.overall_status === 'complete' ? (
                      <>
                        <ShieldCheck className="h-4 w-4 text-green-500" />
                        <span className="font-semibold text-[var(--text-default)]">{scan.total_findings} findings</span>
                        <div className="flex gap-1">
                          {Object.entries(scan.findings_by_severity).map(([sev, count]) => (
                            <span key={sev} className={`rounded-md px-1.5 py-0.5 text-[10px] font-bold ${severityColor(sev)}`}>
                              {sev} {count}
                            </span>
                          ))}
                        </div>
                      </>
                    ) : null}
                  </div>
                </div>
              </div>
            </Panel>

            {/* Source phases */}
            {scan.sources.length > 0 ? (
              <Panel>
                <div className="divide-y divide-[var(--border-light)]">
                  {scan.sources.map((source) => (
                    <div key={source.source_type} className="flex items-center justify-between gap-3 p-3">
                      <div className="flex items-center gap-2.5">
                        <FileSearch className="h-4 w-4 text-[var(--text-muted)]" />
                        <span className="text-xs font-medium text-[var(--text-default)]">
                          {toolLabels[source.source_type] ?? source.source_type}
                        </span>
                        <span className="truncate font-mono text-[11px] text-[var(--text-subtle)]">{source.source_identifier}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {source.findings_count > 0 ? (
                          <span className="text-[11px] font-bold text-[var(--text-default)]">{source.findings_count} findings</span>
                        ) : null}
                        <span
                          className={`rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                            source.status === 'completed'
                              ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                              : source.status === 'running'
                                ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'
                                : source.status === 'failed'
                                  ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                                  : 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'
                          }`}
                        >
                          {source.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
                {scan.sources.some((s) => s.status === 'failed' && s.error_message) ? (
                  <p className="border-t border-[var(--border-light)] px-3 py-2 text-[11px] text-[var(--text-subtle)]">
                    {scan.sources.filter((s) => s.status === 'failed' && s.error_message).map((s) => s.error_message).join(' ')}
                  </p>
                ) : null}
              </Panel>
            ) : null}

            {/* Findings */}
            {scan.overall_status === 'complete' && scan.findings.length === 0 ? (
              <Panel>
                <EmptyState
                  icon={<ShieldCheck className="h-5 w-5" />}
                  title="No findings"
                  description="No secrets, insecure patterns, or vulnerable dependencies were detected in this repository."
                />
              </Panel>
            ) : null}

            {scan.findings.length > 0 ? (
              <Panel>
                <div className="p-3">
                  <h3 className="px-1 pb-2 text-xs font-bold uppercase tracking-wide text-[var(--text-muted)]">
                    Findings ({scan.findings.length})
                  </h3>
                  <div className="space-y-1.5">
                    {scan.findings.map((finding) => (
                      <button
                        key={finding.id}
                        type="button"
                        onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
                        className="w-full rounded-xl border border-[var(--border-light)] bg-white dark:bg-gray-900 p-3 text-left transition-colors hover:border-[var(--border-strong)]"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={finding.severity as never} />
                              <span className="text-xs font-semibold text-[var(--text-strong)]">{finding.title}</span>
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-[var(--text-subtle)]">
                              <span>{finding.category}</span>
                              {finding.module ? <span className="font-mono">{finding.module}</span> : null}
                              {finding.endpoint ? <span className="truncate font-mono">{finding.endpoint}</span> : null}
                              {finding.cwe ? <span className="font-mono">{finding.cwe}</span> : null}
                              {finding.cvss_score != null ? <span>CVSS {finding.cvss_score}</span> : null}
                            </div>
                          </div>
                          {finding.evidence ? <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-[var(--text-subtle)]" /> : null}
                        </div>

                        {expanded === finding.id ? (
                          <div className="mt-3 space-y-2 border-t border-[var(--border-light)] pt-3">
                            {finding.evidence ? (
                              <pre className="overflow-x-auto rounded-lg bg-[var(--surface-tertiary)] p-3 font-mono text-[11px] leading-relaxed text-[var(--text-default)]">
                                {finding.evidence}
                              </pre>
                            ) : null}
                            {finding.impact ? (
                              <p className="text-[11px] text-[var(--text-muted)]">
                                <span className="font-semibold">Impact:</span> {finding.impact}
                              </p>
                            ) : null}
                            {(finding.recommendation || finding.recommended_fix) ? (
                              <p className="text-[11px] text-[var(--text-muted)]">
                                <span className="font-semibold">Fix:</span> {finding.recommendation || finding.recommended_fix}
                              </p>
                            ) : null}
                            {finding.cve_id ? (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--brand)] hover:underline"
                              >
                                {finding.cve_id} <ExternalLink className="h-3 w-3" />
                              </a>
                            ) : null}
                          </div>
                        ) : null}
                      </button>
                    ))}
                  </div>
                </div>
              </Panel>
            ) : null}
          </>
        )}
      </div>
    </Page>
  );
}