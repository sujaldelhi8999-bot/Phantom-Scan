import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  ArrowLeft,
  ArrowRight,
  Check,
  FileCode,
  GitBranch,
  Globe,
  Layers3,
  Loader2,
  Play,
  ShieldAlert,
  Trash2,
  X,
} from 'lucide-react';

import {
  Button,
  EmptyState,
  Input,
  Page,
  PageHeader,
  Panel,
  SectionHeader,
  SeverityBadge,
  StatusBadge,
} from '../../components/ui/Primitives';
import {
  apiErrorMessage,
  getMultiSourceHistory,
  getMultiSourceStatus,
  listGitHubRepos,
  startMultiSourceScan,
  stopMultiSourceScan,
} from '../../services/api';
import type {
  GitHubRepo,
  MultiSourceScanHistoryItem,
  MultiSourceScanResponse,
  MultiSourceSourceType,
} from '../../types';
import { formatDateTime, relativeTime } from '../../utils/derived';

type SourceDraft = {
  id: string;
  type: MultiSourceSourceType;
  enabled: boolean;
  config: Record<string, unknown>;
  label: string;
};

const SOURCE_TYPES: Array<{ type: MultiSourceSourceType; label: string; description: string; icon: typeof Globe }> = [
  { type: 'github', label: 'GitHub Repo', description: 'Clone and scan a repository', icon: GitBranch },
  { type: 'local', label: 'Local Codebase', description: 'Scan a local directory', icon: FileCode },
  { type: 'live', label: 'Live Target', description: 'Active security testing of a URL', icon: Globe },
];

const STEPS = ['Sources', 'Configuration', 'Correlation', 'Review & Launch'];

export default function MultiSourceScanPage() {
  const [step, setStep] = useState(0);
  const [sources, setSources] = useState<SourceDraft[]>([]);
  const [scanName, setScanName] = useState('');
  const [intensity, setIntensity] = useState<'low' | 'medium' | 'high'>('medium');
  const [correlate, setCorrelate] = useState(true);
  const [dataFlow, setDataFlow] = useState(true);
  const [sarif, setSarif] = useState(true);
  const [maxDuration, setMaxDuration] = useState(120);
  const [submitting, setSubmitting] = useState(false);
  const [history, setHistory] = useState<MultiSourceScanHistoryItem[]>([]);
  const [activeScan, setActiveScan] = useState<MultiSourceScanResponse | null>(null);

  // Source editor state
  const [selectedType, setSelectedType] = useState<MultiSourceSourceType>('github');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [localPath, setLocalPath] = useState('');
  const [liveUrl, setLiveUrl] = useState('');
  const [liveModules, setLiveModules] = useState<string[]>([]);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [githubConnected, setGithubConnected] = useState<boolean | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const historyResult = await getMultiSourceHistory();
      setHistory(historyResult);
      const running = historyResult.find((item) => item.overall_status === 'running' || item.overall_status === 'queued');
      if (running) {
        const status = await getMultiSourceStatus(running.scan_id);
        setActiveScan(status);
      }
    } catch {
      // history may be empty on first run
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const loadRepos = useCallback(async () => {
    try {
      const repoResult = await listGitHubRepos();
      setGithubConnected(repoResult.connected);
      setRepos(repoResult.repos);
    } catch {
      setGithubConnected(false);
    }
  }, []);

  useEffect(() => {
    if (selectedType === 'github') void loadRepos();
  }, [selectedType, loadRepos]);

  useEffect(() => {
    if (!activeScan) return;
    const interval = setInterval(async () => {
      try {
        const status = await getMultiSourceStatus(activeScan.scan_id);
        setActiveScan(status);
        if (['complete', 'error', 'cancelled'].includes(status.overall_status)) {
          clearInterval(interval);
          await load();
        }
      } catch {
        clearInterval(interval);
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [activeScan?.scan_id, load]);

  const nextId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

  const addSource = () => {
    let config: Record<string, unknown> = {};
    let label = '';
    if (selectedType === 'github') {
      const repo = repos.find((r) => r.full_name === repoUrl || r.clone_url === repoUrl);
      config = {
        type: 'github',
        repo_url: repo?.clone_url || repoUrl,
        branch,
        auth_type: 'oauth_user',
        scan_mode: 'full',
        base_branch: 'main',
        include_workflows: true,
        include_dependabot: true,
      };
      label = repo?.full_name || repoUrl;
    } else if (selectedType === 'local') {
      config = { type: 'local', path: localPath, exclude_patterns: [] };
      label = localPath;
    } else if (selectedType === 'live') {
      config = {
        type: 'live',
        target_url: liveUrl,
        authorization_confirmed: false,
        intensity,
        selected_modules: liveModules,
      };
      label = liveUrl;
    }
    if (!label) {
      toast.error('Please fill in the source details.');
      return;
    }
    if (editingId) {
      setSources((prev) => prev.map((s) => (s.id === editingId ? { ...s, type: selectedType, config, label } : s)));
      setEditingId(null);
    } else {
      setSources((prev) => [...prev, { id: nextId(), type: selectedType, enabled: true, config, label }]);
    }
    setRepoUrl(''); setLocalPath(''); setLiveUrl('');
  };

  const removeSource = (id: string) => setSources((prev) => prev.filter((s) => s.id !== id));

  const canProceed = sources.length > 0 && sources.every((s) => s.enabled);

  const launch = async () => {
    if (!canProceed || submitting) return;
    setSubmitting(true);
    try {
      const result = await startMultiSourceScan({
        name: scanName || `Multi-source scan (${sources.length} sources)`,
        mode: 'multi_agent',
        intensity,
        sources: sources.map((s) => ({ ...s.config, enabled: true, priority: 1 })),
        correlate_findings: correlate,
        data_flow_tracing: dataFlow,
        generate_sarif: sarif,
        generate_pdf: false,
        max_duration_minutes: maxDuration,
      });
      toast.success(`Multi-source scan #${result.scan_id} started`);
      setActiveScan(result);
      setStep(0);
      setSources([]);
      await load();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not start the multi-source scan.'));
    } finally {
      setSubmitting(false);
    }
  };

  const stopActive = async () => {
    if (!activeScan) return;
    try {
      await stopMultiSourceScan(activeScan.scan_id);
      toast.success('Stop requested');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not stop the scan.'));
    }
  };

  const sourceCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const s of sources) counts[s.type] = (counts[s.type] || 0) + 1;
    return counts;
  }, [sources]);

  return (
    <Page>
      <PageHeader
        title="Multi-Source Scan"
        description="Coordinate SAST, SCA, secrets, IaC and live DAST testing across codebases, repositories and targets."
      />

      {/* Active scan banner */}
      {activeScan && !['complete', 'error', 'cancelled'].includes(activeScan.overall_status) ? (
        <Panel className="mb-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[var(--brand-soft)]">
              <Loader2 className="h-4 w-4 animate-spin text-[var(--brand)]" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-xs font-semibold text-[var(--text-strong)]">
                Scan #{activeScan.scan_id} · {activeScan.overall_status}
              </div>
              <div className="mt-1 h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-[var(--surface-tertiary)]">
                <div className="h-full rounded-full bg-[var(--brand)] transition-all" style={{ width: `${activeScan.overall_progress}%` }} />
              </div>
            </div>
            <div className="text-[11px] text-[var(--text-muted)]">{activeScan.overall_progress}%</div>
            <Button variant="secondary" onClick={() => { void stopActive(); }}>
              <X className="h-3.5 w-3.5" />Stop
            </Button>
          </div>
        </Panel>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* Wizard */}
        <div>
          <Panel>
            {/* Stepper */}
            <div className="mb-5 flex items-center gap-2">
              {STEPS.map((label, index) => (
                <div key={label} className="flex flex-1 items-center gap-2">
                  <div
                    className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${
                      index < step
                        ? 'bg-[var(--brand)] text-white'
                        : index === step
                          ? 'bg-[var(--brand-soft)] text-[var(--brand)]'
                          : 'bg-[var(--surface-tertiary)] text-[var(--text-subtle)]'
                    }`}
                  >
                    {index < step ? <Check className="h-3 w-3" /> : index + 1}
                  </div>
                  <span className={`hidden text-[11px] font-medium sm:block ${index === step ? 'text-[var(--text-strong)]' : 'text-[var(--text-subtle)]'}`}>
                    {label}
                  </span>
                  {index < STEPS.length - 1 ? <div className="h-px flex-1 bg-[var(--border-light)]" /> : null}
                </div>
              ))}
            </div>

            {step === 0 ? (
              <div className="space-y-4">
                <SectionHeader title="Add scan sources" />
                <div className="grid gap-3 sm:grid-cols-3">
                  {SOURCE_TYPES.map((sourceType) => {
                    const Icon = sourceType.icon;
                    const active = selectedType === sourceType.type;
                    return (
                      <button
                        key={sourceType.type}
                        onClick={() => setSelectedType(sourceType.type)}
                        className={`rounded-xl border p-3.5 text-left transition-colors ${
                          active
                            ? 'border-[var(--brand)] bg-[var(--brand-soft)]/40'
                            : 'border-[var(--border-light)] bg-[var(--surface-secondary)] hover:border-[var(--border-default)]'
                        }`}
                      >
                        <Icon className={`h-4 w-4 ${active ? 'text-[var(--brand)]' : 'text-[var(--text-subtle)]'}`} />
                        <div className="mt-2 text-xs font-semibold text-[var(--text-strong)]">{sourceType.label}</div>
                        <div className="mt-0.5 text-[10px] leading-relaxed text-[var(--text-muted)]">{sourceType.description}</div>
                        {sourceCounts[sourceType.type] ? (
                          <span className="mt-2 inline-block rounded bg-[var(--brand-soft)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--brand)]">
                            {sourceCounts[sourceType.type]} added
                          </span>
                        ) : null}
                      </button>
                    );
                  })}
                </div>

                <div className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-4">
                  {selectedType === 'github' ? (
                    <div className="space-y-3">
                      {githubConnected === false ? (
                        <p className="text-xs text-[var(--text-muted)]">
                          GitHub is not connected.{' '}
                          <Link to="/github" className="font-medium text-[var(--brand)] hover:underline">Connect GitHub</Link> to browse repositories.
                        </p>
                      ) : null}
                      <div>
                        <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Repository</label>
                        {repos.length ? (
                          <select
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                            className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--surface-primary)] px-3 py-2 text-xs text-[var(--text-default)] outline-none focus:border-[var(--brand)]"
                          >
                            <option value="">Select a repository...</option>
                            {repos.map((repo) => (
                              <option key={repo.id} value={repo.clone_url}>{repo.full_name} ({repo.language || 'unknown'})</option>
                            ))}
                          </select>
                        ) : (
                          <Input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repo" />
                        )}
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Branch</label>
                        <Input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
                      </div>
                    </div>
                  ) : selectedType === 'local' ? (
                    <div>
                      <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Absolute path to codebase</label>
                      <Input value={localPath} onChange={(e) => setLocalPath(e.target.value)} placeholder="C:\work\my-app or /home/dev/project" />
                      <p className="mt-1.5 text-[10px] text-[var(--text-subtle)]">
                        Runs Semgrep, truffleHog, gitleaks, pip-audit and npm audit inside the sandbox.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div>
                        <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Target URL</label>
                        <Input value={liveUrl} onChange={(e) => setLiveUrl(e.target.value)} placeholder="https://app.example.com" />
                        <p className="mt-1.5 text-[10px] text-[var(--text-subtle)]">
                          Requires authorization verification before active testing starts.
                        </p>
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Modules (optional)</label>
                        <Input
                          value={liveModules.join(',')}
                          onChange={(e) => setLiveModules(e.target.value.split(',').map((m) => m.trim()).filter(Boolean))}
                          placeholder="sqli,xss,ssrf,jwt,cors"
                        />
                      </div>
                    </div>
                  )}
                  <div className="mt-3">
                    <Button onClick={addSource} disabled={!selectedType}>
                      {editingId ? 'Update Source' : 'Add Source'}
                    </Button>
                  </div>
                </div>

                {sources.length ? (
                  <div className="space-y-2">
                    <SectionHeader title={`Configured sources (${sources.length})`} />
                    {sources.map((source) => (
                      <div key={source.id} className="flex items-center gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3">
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--surface-tertiary)]">
                          <Layers3 className="h-4 w-4 text-[var(--brand)]" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-xs font-medium text-[var(--text-strong)]">{source.label}</div>
                          <div className="text-[10px] text-[var(--text-subtle)]">{source.type}</div>
                        </div>
                        <StatusBadge status={source.enabled ? 'Enabled' : 'Disabled'} />
                        <Button variant="secondary" className="!px-2" onClick={() => removeSource(source.id)}>
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : null}

                <div className="flex justify-end">
                  <Button onClick={() => setStep(1)} disabled={!canProceed}>
                    Next <ArrowRight className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ) : step === 1 ? (
              <div className="space-y-4">
                <SectionHeader title="Scan configuration" />
                <div>
                  <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Scan name</label>
                  <Input value={scanName} onChange={(e) => setScanName(e.target.value)} placeholder="Q3 security sweep" />
                </div>
                <div>
                  <label className="mb-1.5 block text-[10px] font-semibold text-[var(--text-subtle)]">Intensity</label>
                  <div className="grid grid-cols-3 gap-2">
                    {(['low', 'medium', 'high'] as const).map((value) => (
                      <button
                        key={value}
                        onClick={() => setIntensity(value)}
                        className={`rounded-lg border px-3 py-2 text-xs font-medium capitalize transition-colors ${
                          intensity === value
                            ? 'border-[var(--brand)] bg-[var(--brand-soft)] text-[var(--brand)]'
                            : 'border-[var(--border-light)] text-[var(--text-muted)] hover:bg-[var(--surface-hover)]'
                        }`}
                      >
                        {value}
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Max duration (minutes)</label>
                  <Input value={maxDuration} onChange={(e) => setMaxDuration(Number(e.target.value) || 120)} type="number" min={5} max={1440} />
                </div>
                <div className="flex justify-between">
                  <Button variant="secondary" onClick={() => setStep(0)}>
                    <ArrowLeft className="h-3.5 w-3.5" />Back
                  </Button>
                  <Button onClick={() => setStep(2)}>Next <ArrowRight className="h-3.5 w-3.5" /></Button>
                </div>
              </div>
            ) : step === 2 ? (
              <div className="space-y-4">
                <SectionHeader title="Correlation & analysis" />
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3.5">
                  <input type="checkbox" checked={correlate} onChange={(e) => setCorrelate(e.target.checked)} className="mt-0.5 accent-[var(--brand)]" />
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-strong)]">Cross-source correlation</div>
                    <div className="mt-0.5 text-[10px] leading-relaxed text-[var(--text-muted)]">
                      Link findings across code, live and dependency sources into unified vulnerability stories.
                    </div>
                  </div>
                </label>
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3.5">
                  <input type="checkbox" checked={dataFlow} onChange={(e) => setDataFlow(e.target.checked)} className="mt-0.5 accent-[var(--brand)]" />
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-strong)]">Data flow tracing</div>
                    <div className="mt-0.5 text-[10px] leading-relaxed text-[var(--text-muted)]">
                      Trace tainted data from inputs to sinks across source boundaries.
                    </div>
                  </div>
                </label>
                <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3.5">
                  <input type="checkbox" checked={sarif} onChange={(e) => setSarif(e.target.checked)} className="mt-0.5 accent-[var(--brand)]" />
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-strong)]">SARIF export</div>
                    <div className="mt-0.5 text-[10px] leading-relaxed text-[var(--text-muted)]">
                      Generate SARIF 2.1.0 output for GitHub Code Scanning.
                    </div>
                  </div>
                </label>
                <div className="flex justify-between">
                  <Button variant="secondary" onClick={() => setStep(1)}>
                    <ArrowLeft className="h-3.5 w-3.5" />Back
                  </Button>
                  <Button onClick={() => setStep(3)}>Next <ArrowRight className="h-3.5 w-3.5" /></Button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <SectionHeader title="Review & launch" />
                <div className="rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-4">
                  <div className="mb-3 text-xs font-semibold text-[var(--text-strong)]">{scanName || 'Untitled scan'}</div>
                  <div className="space-y-2">
                    {sources.map((source) => (
                      <div key={source.id} className="flex items-center justify-between text-xs">
                        <span className="text-[var(--text-default)]">{source.label}</span>
                        <span className="text-[10px] uppercase text-[var(--text-subtle)]">{source.type}</span>
                      </div>
                    ))}
                    <div className="flex items-center justify-between border-t border-[var(--border-light)] pt-2 text-[11px]">
                      <span className="text-[var(--text-muted)]">Intensity</span>
                      <span className="capitalize text-[var(--text-strong)]">{intensity}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-[var(--text-muted)]">Correlation</span>
                      <span className="text-[var(--text-strong)]">{correlate ? 'On' : 'Off'}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-[var(--text-muted)]">Data flow tracing</span>
                      <span className="text-[var(--text-strong)]">{dataFlow ? 'On' : 'Off'}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-[var(--text-muted)]">SARIF export</span>
                      <span className="text-[var(--text-strong)]">{sarif ? 'On' : 'Off'}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-[var(--text-muted)]">Max duration</span>
                      <span className="text-[var(--text-strong)]">{maxDuration} min</span>
                    </div>
                  </div>
                </div>
                <div className="flex justify-between">
                  <Button variant="secondary" onClick={() => setStep(2)}>
                    <ArrowLeft className="h-3.5 w-3.5" />Back
                  </Button>
                  <Button onClick={() => { void launch(); }} disabled={submitting}>
                    {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}Launch Scan
                  </Button>
                </div>
              </div>
            )}
          </Panel>
        </div>

        {/* History sidebar */}
        <div>
          <Panel>
            <SectionHeader title="Recent multi-source scans" />
            {history.length ? (
              <div className="space-y-2">
                {history.slice(0, 8).map((item) => (
                  <Link
                    key={item.scan_id}
                    to={`/multi-source/${item.scan_id}`}
                    className="block rounded-xl border border-[var(--border-light)] bg-[var(--surface-secondary)] p-3 transition-colors hover:border-[var(--border-default)]"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-xs font-medium text-[var(--text-strong)]">
                        {item.name}
                      </span>
                      <StatusBadge status={item.overall_status} />
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {item.sources.map((source) => (
                        <span key={source} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase text-[var(--text-subtle)]">
                          {source}
                        </span>
                      ))}
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px] text-[var(--text-subtle)]">
                      <span>{item.total_findings} findings · {item.correlated_findings} correlations</span>
                      <span>{relativeTime(item.created_at)}</span>
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={<ShieldAlert className="h-6 w-6 text-[var(--text-subtle)]" />}
                title="No multi-source scans yet"
                description="Launch your first coordinated scan to get started."
              />
            )}
          </Panel>
        </div>
      </div>
    </Page>
  );
}
