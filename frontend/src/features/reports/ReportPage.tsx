import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Download, GitCompareArrows, RotateCcw, Sparkles } from 'lucide-react';

import { Button, Drawer, EmptyState, ErrorState, GlassPanel, MetricCard, RemediationChecklist, SectionHeader, SecurityScore, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { apiErrorMessage, getAIAnalysis, getScan, getScanArtifacts, startScan } from '../../services/api';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AISecurityAnalystOutput, BrowserSecurityOutput, ScanArtifactsResponse, ScanResponse } from '../../types';
import { countBySeverity, previousScanForTarget, scanDuration, securityScore, targetName } from '../../utils/derived';

type ObservabilityTab = 'Overview' | 'Attack Surface' | 'Browser' | 'Network' | 'Console' | 'APIs' | 'Authentication' | 'Storage' | 'WebSockets' | 'Technologies' | 'Findings';
const observabilityTabs: ObservabilityTab[] = ['Overview', 'Attack Surface', 'Browser', 'Network', 'Console', 'APIs', 'Authentication', 'Storage', 'WebSockets', 'Technologies', 'Findings'];
const networkFilters = ['All', 'API', 'Auth', 'GraphQL', 'WebSocket', 'Scripts', 'Third Party', 'Errors'];

function asArray(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null) : [];
}

function text(value: unknown, fallback = ''): string {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'string') return value;
  return String(value);
}

function JsonBlock({ value }: { value: unknown }) {
  return <pre className="max-h-[360px] overflow-auto whitespace-pre-wrap rounded-2xl bg-slate-950/70 p-4 font-mono text-xs text-slate-300">{JSON.stringify(value ?? {}, null, 2)}</pre>;
}

function displayValue(value: unknown): string {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean).join(', ') || 'None';
  if (value && typeof value === 'object') return JSON.stringify(value);
  return text(value, 'None');
}

function AnalystReport({ analysis }: { analysis: AISecurityAnalystOutput | null | undefined }) {
  if (!analysis) {
    return <Surface className="p-6"><EmptyState title="No AI Security Analyst artifact" description="Open or refresh this report after a completed scan to generate grounded analyst output." /></Surface>;
  }
  const summary = analysis.security_summary ?? {};
  const priorities = analysis.priorities ?? [];
  const executive = Object.entries(analysis.executive_report ?? {});
  const developer = analysis.developer_report ?? [];
  return (
    <Surface className="p-6">
      <SectionHeader title="AI Security Analyst" description="Evidence-grounded executive and developer analysis. The analyst cannot start active tests." />
      <div className="mb-5 flex flex-wrap gap-2"><StatusBadge status={analysis.ai_status ?? 'Deterministic analysis'} /><StatusBadge status={analysis.safety?.can_start_active_test === false ? 'Active tests disabled' : 'Active tests unavailable'} /></div>
      {analysis.ai_narrative ? <div className="mb-5 rounded-2xl bg-violet-500/[0.08] p-4 text-sm leading-6 text-violet-100/90">{analysis.ai_narrative}</div> : null}
      <div className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl bg-white/[0.035] p-4"><div className="mb-2 flex items-center gap-2 text-sm text-violet-200"><Sparkles className="h-4 w-4" />Posture</div><div className="text-lg font-semibold text-slate-50">{displayValue(summary.overall_security_posture)}</div></div>
        <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Analyst Score</div><div className="mt-2 text-3xl font-semibold text-slate-50">{analysis.score_explanation?.score ?? '--'}</div></div>
        <div className="rounded-2xl bg-white/[0.035] p-4 md:col-span-2"><div className="text-sm text-slate-500">Recommended Next Action</div><div className="mt-2 text-sm leading-6 text-slate-200">{displayValue(summary.recommended_next_action)}</div></div>
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <div>
          <h3 className="mb-3 font-semibold text-slate-100">Top Priorities</h3>
          <div className="space-y-2">{priorities.length ? priorities.slice(0, 5).map((item) => <div key={`${item.priority}-${item.finding_id}`} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge status={`Priority ${item.priority}`} /><StatusBadge status={text(item.severity, 'INFO')} /><span className="font-medium text-slate-100">{text(item.title)}</span></div><p className="mt-2 text-sm leading-6 text-slate-400">{text(item.recommended_action, 'Review evidence and remediate.')}</p></div>) : <EmptyState title="No active priorities" description="Resolved, accepted-risk, and false-positive findings are excluded from this list." />}</div>
        </div>
        <div>
          <h3 className="mb-3 font-semibold text-slate-100">Executive Report</h3>
          <div className="space-y-2">{executive.map(([label, value]) => <div key={label} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">{label}</div><div className="mt-2 text-sm leading-6 text-slate-300">{displayValue(value)}</div></div>)}</div>
        </div>
      </div>
      {developer.length ? <div className="mt-5"><h3 className="mb-3 font-semibold text-slate-100">Developer Analysis</h3><div className="grid gap-3 lg:grid-cols-2">{developer.slice(0, 6).map((item) => <div key={String(item.finding_id)} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge status={`Finding ${text(item.finding_id)}`} /><StatusBadge status={text(item.severity, 'INFO')} /></div><div className="mt-2 break-all font-mono text-xs text-slate-500">{text(item.affected_endpoint)}</div><p className="mt-2 text-sm leading-6 text-slate-400">{text(item.remediation, 'No remediation text available.')}</p></div>)}</div></div> : null}
    </Surface>
  );
}

function networkMatchesFilter(entry: Record<string, unknown>, filter: string) {
  const classification = text(entry.classification).toUpperCase();
  const status = Number(entry.status ?? 0);
  if (filter === 'All') return true;
  if (filter === 'API') return classification === 'API';
  if (filter === 'Auth') return classification === 'AUTH';
  if (filter === 'GraphQL') return classification === 'GRAPHQL';
  if (filter === 'WebSocket') return classification === 'WEBSOCKET';
  if (filter === 'Scripts') return classification === 'SCRIPT';
  if (filter === 'Third Party') return classification === 'THIRD_PARTY';
  if (filter === 'Errors') return status >= 400;
  return true;
}

function ObservabilityTabs({ browserOutput }: { browserOutput: BrowserSecurityOutput | null | undefined }) {
  const [tab, setTab] = useState<ObservabilityTab>('Overview');
  const [networkFilter, setNetworkFilter] = useState('All');
  const [selectedNetwork, setSelectedNetwork] = useState<Record<string, unknown> | null>(null);
  const pages = asArray(browserOutput?.pages);
  const routes = asArray(browserOutput?.routes);
  const dom = asArray(browserOutput?.dom);
  const network = asArray(browserOutput?.network_events);
  const consoleEvents = asArray(browserOutput?.console_events);
  const apis = asArray(browserOutput?.api_inventory);
  const cookies = asArray(browserOutput?.cookies);
  const websockets = asArray(browserOutput?.websockets);
  const technologies = asArray(browserOutput?.third_party);
  const browserFindings = asArray(browserOutput?.findings);
  const filteredNetwork = network.filter((entry) => networkMatchesFilter(entry, networkFilter));

  if (!browserOutput) {
    return <Surface className="p-6"><EmptyState title="No browser observability artifact" description="Run a new scan to collect Browser, Network, DOM, API, Storage, and WebSocket evidence." /></Surface>;
  }

  return (
    <Surface className="p-6">
      <SectionHeader title="Advanced Observability" description="Browser, Network, DOM, JavaScript, API, Authentication, Storage, WebSocket, and correlation evidence from this scan." />
      <div className="mb-5 flex flex-wrap gap-2">
        {observabilityTabs.map((item) => <button key={item} onClick={() => setTab(item)} className={`rounded-2xl px-3 py-2 text-sm font-semibold ${tab === item ? 'bg-violet-500/15 text-violet-100 ring-1 ring-violet-400/25' : 'bg-white/[0.04] text-slate-400 hover:text-slate-200'}`}>{item}</button>)}
      </div>

      {tab === 'Overview' ? <div className="grid gap-3 md:grid-cols-4"><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Engine</div><div className="mt-2 text-slate-100">{text(browserOutput.browser_engine, 'unknown')}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Pages</div><div className="mt-2 text-2xl font-semibold text-slate-50">{pages.length}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Network Events</div><div className="mt-2 text-2xl font-semibold text-slate-50">{network.length}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">APIs</div><div className="mt-2 text-2xl font-semibold text-slate-50">{apis.length}</div></div><div className="rounded-2xl bg-white/[0.035] p-4 md:col-span-4"><div className="mb-2 text-sm text-slate-500">Correlation</div><JsonBlock value={browserOutput.correlation} /></div></div> : null}

      {tab === 'Attack Surface' ? <div className="grid gap-3 md:grid-cols-2">{routes.map((route, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="break-all font-mono text-sm text-slate-100">{text(route.route)}</div><div className="mt-2 text-xs uppercase tracking-[0.18em] text-slate-600">{text(route.source, 'observed')}</div></div>)}</div> : null}

      {tab === 'Browser' ? <div className="grid gap-4 lg:grid-cols-2"><div><h3 className="mb-3 font-semibold text-slate-100">Pages Visited</h3><div className="space-y-2">{pages.map((page, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-3"><div className="break-all font-mono text-sm text-slate-200">{text(page.url)}</div><div className="mt-1 text-xs text-slate-500">{text(page.title)} {text(page.status)}</div></div>)}</div></div><div><h3 className="mb-3 font-semibold text-slate-100">DOM Summary</h3><div className="space-y-2">{dom.map((page, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-3"><div className="break-all font-mono text-sm text-slate-200">{text(page.page)}</div><div className="mt-2 grid gap-2 text-xs text-slate-500 sm:grid-cols-3"><span>Forms {asArray(page.forms).length}</span><span>Inputs {asArray(page.inputs).length}</span><span>CSP Events {asArray(browserOutput.csp_violations).length}</span></div></div>)}</div></div></div> : null}

      {tab === 'Network' ? <div className="space-y-4"><div className="flex flex-wrap gap-2">{networkFilters.map((item) => <button key={item} onClick={() => setNetworkFilter(item)} className={`rounded-2xl px-3 py-2 text-sm ${networkFilter === item ? 'bg-violet-500/15 text-violet-100' : 'bg-white/[0.04] text-slate-400'}`}>{item}</button>)}</div><div className="hidden overflow-hidden rounded-2xl border border-white/[0.06] md:block"><div className="grid grid-cols-[90px_1.6fr_120px_90px_110px_130px] gap-3 border-b border-white/[0.06] px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-600"><span>Method</span><span>Endpoint</span><span>Type</span><span>Status</span><span>Duration</span><span>Initiator</span></div>{filteredNetwork.map((entry, index) => <button key={index} onClick={() => setSelectedNetwork(entry)} className="grid w-full grid-cols-[90px_1.6fr_120px_90px_110px_130px] gap-3 border-b border-white/[0.04] px-4 py-3 text-left last:border-b-0 hover:bg-white/[0.04]"><span className="font-mono text-sm text-slate-200">{text(entry.method)}</span><span className="truncate font-mono text-sm text-slate-400">{text(entry.url)}</span><span><StatusBadge status={text(entry.classification, 'UNKNOWN')} /></span><span className="text-sm text-slate-300">{text(entry.status, '--')}</span><span className="text-sm text-slate-400">{text(entry.duration_ms, '--')} ms</span><span className="truncate text-sm text-slate-500">{text(entry.initiator)}</span></button>)}</div><div className="space-y-2 md:hidden">{filteredNetwork.map((entry, index) => <button key={index} onClick={() => setSelectedNetwork(entry)} className="w-full rounded-2xl bg-white/[0.035] p-4 text-left"><div className="flex justify-between gap-3"><span className="font-mono text-sm text-slate-100">{text(entry.method)}</span><StatusBadge status={text(entry.classification, 'UNKNOWN')} /></div><div className="mt-2 break-all font-mono text-xs text-slate-500">{text(entry.url)}</div></button>)}</div></div> : null}

      {tab === 'Console' ? <div className="space-y-2">{consoleEvents.length ? consoleEvents.map((event, index) => <div key={index} className="grid gap-3 rounded-2xl bg-white/[0.035] p-4 md:grid-cols-[120px_120px_1fr_160px]"><span className="text-sm text-slate-500">{text(event.timestamp)}</span><StatusBadge status={text(event.type, 'log')} /><span className="text-sm text-slate-300">{text(event.message)}</span><span className="truncate text-xs text-slate-500">{text(event.source)}</span></div>) : <EmptyState title="No console events" description="No browser console messages were captured for this scan." />}</div> : null}

      {tab === 'APIs' ? <div className="grid gap-3 md:grid-cols-2">{apis.map((api, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex items-center gap-2"><span className="font-mono text-sm text-slate-100">{text(api.method)}</span><StatusBadge status={text(api.classification, 'API')} /></div><div className="mt-2 break-all font-mono text-sm text-slate-400">{text(api.endpoint)}</div><div className="mt-3 text-xs text-slate-500">Status: {JSON.stringify(api.status_codes)} | Auth: {text(api.authentication, 'unknown')}</div><JsonBlock value={{ parameters: api.observed_parameters, response_fields: api.response_fields }} /></div>)}</div> : null}

      {tab === 'Authentication' ? <JsonBlock value={browserOutput.auth_flow} /> : null}

      {tab === 'Storage' ? <div className="grid gap-4 lg:grid-cols-2"><div><h3 className="mb-3 font-semibold text-slate-100">Cookies</h3><div className="space-y-2">{cookies.map((cookie, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="font-mono text-sm text-slate-100">{text(cookie.name)}</div><div className="mt-2 flex flex-wrap gap-2"><StatusBadge status={`Secure ${text(cookie.secure)}`} /><StatusBadge status={`HttpOnly ${text(cookie.httponly)}`} /><StatusBadge status={`SameSite ${text(cookie.samesite, 'none')}`} /></div><div className="mt-2 text-xs text-slate-500">{text(cookie.domain)} {text(cookie.path)} {text(cookie.expires)}</div></div>)}</div></div><div><h3 className="mb-3 font-semibold text-slate-100">Browser Storage Metadata</h3><JsonBlock value={browserOutput.storage} /></div></div> : null}

      {tab === 'WebSockets' ? <div className="space-y-2">{websockets.length ? websockets.map((socket, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="break-all font-mono text-sm text-slate-100">{text(socket.url)}</div><div className="mt-2 flex flex-wrap gap-2"><StatusBadge status={text(socket.authentication_state, 'unknown')} /><StatusBadge status={text(socket.disconnect_behavior, 'not connected')} /></div><JsonBlock value={socket.message_schema ?? socket.messages} /></div>) : <EmptyState title="No WebSockets observed" description="No browser-visible WebSocket endpoints were captured." />}</div> : null}

      {tab === 'Technologies' ? <div className="grid gap-3 md:grid-cols-2">{technologies.map((item, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="font-mono text-sm text-slate-100">{text(item.domain)}</div><div className="mt-2 text-sm text-slate-400">{text(item.purpose, 'unknown')}</div><div className="mt-2 break-all text-xs text-slate-500">{text(item.resource)}</div><div className="mt-2 flex gap-2"><StatusBadge status={`SRI ${text(item.integrity, 'unknown')}`} /><StatusBadge status={text(item.crossorigin, 'crossorigin not set')} /></div></div>)}</div> : null}

      {tab === 'Findings' ? <div className="space-y-3">{browserFindings.length ? browserFindings.map((finding, index) => <div key={index} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex flex-wrap items-center gap-2"><StatusBadge status={text(finding.severity, 'INFO')} /><StatusBadge status={text(finding.confidence, 'POTENTIAL')} /><span className="font-medium text-slate-100">{text(finding.title)}</span></div><p className="mt-3 text-sm leading-6 text-slate-400">{text(finding.evidence)}</p></div>) : <EmptyState title="No browser-derived findings" description="The browser observation artifact did not produce additional findings." />}</div> : null}

      <Drawer title="Request Details" open={Boolean(selectedNetwork)} onClose={() => setSelectedNetwork(null)}>
        {selectedNetwork ? <div className="space-y-5"><section><h3 className="mb-2 font-semibold text-slate-100">General</h3><JsonBlock value={{ method: selectedNetwork.method, url: selectedNetwork.url, status: selectedNetwork.status, type: selectedNetwork.classification, auth: selectedNetwork.authentication_state }} /></section><section><h3 className="mb-2 font-semibold text-slate-100">Headers</h3><JsonBlock value={{ request: selectedNetwork.request_headers_summary, response: selectedNetwork.response_headers_summary }} /></section><section><h3 className="mb-2 font-semibold text-slate-100">Schema</h3><JsonBlock value={selectedNetwork.response_schema} /></section><section><h3 className="mb-2 font-semibold text-slate-100">Timing / Initiator</h3><JsonBlock value={{ duration_ms: selectedNetwork.duration_ms, initiator: selectedNetwork.initiator, redirect_chain: selectedNetwork.redirect_chain }} /></section></div> : null}
      </Drawer>
    </Surface>
  );
}

export default function ReportPage() {
  const { scan_id } = useParams();
  const { scans, findings, refresh } = usePhantomData();
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [artifacts, setArtifacts] = useState<ScanArtifactsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [compareOpen, setCompareOpen] = useState(false);
  const previous = scan ? previousScanForTarget(scans, scan) : undefined;
  const previousFindings = previous ? findings.filter((finding) => finding.scan_id === previous.id) : [];

  useEffect(() => {
    if (!scan_id) return;
    let active = true;
    const load = async () => {
      try {
        const [nextScan, nextArtifacts] = await Promise.all([getScan(scan_id), getScanArtifacts(scan_id)]);
        let hydratedArtifacts = nextArtifacts;
        if (!nextArtifacts.ai_analyst_output && nextScan.status === 'complete') {
          try {
            const analysis = await getAIAnalysis(scan_id);
            hydratedArtifacts = { ...nextArtifacts, ai_analyst_output: analysis };
          } catch {
            hydratedArtifacts = nextArtifacts;
          }
        }
        if (!active) return;
        setScan(nextScan);
        setArtifacts(hydratedArtifacts);
        setError(null);
      } catch (err) {
        if (active) setError(apiErrorMessage(err, 'Unable to load report.'));
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 6000);
    return () => { active = false; window.clearInterval(timer); };
  }, [scan_id]);

  const counts = useMemo(() => countBySeverity(scan?.findings ?? []), [scan]);
  const score = securityScore(scan?.findings ?? []);
  const activeOutput = artifacts?.active_security_output;
  const previousCounts = countBySeverity(previousFindings);
  const previousScore = securityScore(previousFindings);

  const exportJson = () => {
    if (!scan) return;
    const blob = new Blob([JSON.stringify({ scan, artifacts }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `phantomscan-report-${scan.scan_id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const rescan = async () => {
    if (!scan) return;
    try {
      const next = await startScan({ target_url: scan.target_url, mode: 'defend', intensity: scan.intensity });
      toast.success('Rescan started');
      await refresh();
      window.location.href = `/report/${next.scan_id}`;
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to start rescan.'));
    }
  };

  if (error) return <ErrorState title="Unable to load report" description="PhantomScan could not retrieve this assessment." detail={error} action={<Button onClick={() => window.location.reload()}>Retry</Button>} />;
  if (!scan) return <Surface className="p-6"><EmptyState title="Loading report" description="Retrieving scan evidence from the backend." /></Surface>;

  return (
    <div className="space-y-6">
      <GlassPanel className="p-6"><div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between"><div><div className="mb-3 flex flex-wrap gap-2"><StatusBadge status={scan.status} /><StatusBadge status={scan.mode === 'pentest' ? 'Authorized Testing' : 'Defend'} /></div><h1 className="text-2xl font-semibold text-slate-50">Security Assessment</h1><div className="mt-2 font-mono text-sm text-slate-400">{targetName(scan.target_url)}</div></div><div className="flex flex-wrap gap-3"><Button variant="secondary" onClick={exportJson}><Download className="h-4 w-4" />Export JSON</Button><Button variant="secondary" onClick={rescan}><RotateCcw className="h-4 w-4" />Rescan</Button><Button variant="secondary" onClick={() => setCompareOpen((value) => !value)} disabled={!previous}><GitCompareArrows className="h-4 w-4" />Compare</Button></div></div></GlassPanel>
      <div className="grid gap-4 md:grid-cols-5"><MetricCard label="Security Score" value={score} /><MetricCard label="Critical" value={counts.CRITICAL} tone={counts.CRITICAL ? 'red' : 'green'} /><MetricCard label="High" value={counts.HIGH} tone={counts.HIGH ? 'amber' : 'green'} /><MetricCard label="Medium" value={counts.MEDIUM} tone="amber" /><MetricCard label="Low" value={counts.LOW} tone="purple" /></div>
      <Surface className="p-6"><div className="grid gap-8 lg:grid-cols-[220px_1fr]"><SecurityScore score={score} /><div className="grid gap-3 sm:grid-cols-2"><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Started</div><div className="mt-1 text-slate-100">{new Date(scan.created_at).toLocaleString()}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Duration</div><div className="mt-1 text-slate-100">{scanDuration(scan)}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Requests</div><div className="mt-1 text-slate-100">{scan.request_count}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Sandbox</div><div className="mt-1 text-slate-100">{scan.sandbox_id ?? 'Not used'}</div></div></div></div></Surface>
      {compareOpen && previous ? <Surface className="p-6"><SectionHeader title="Scan Comparison" description={`Previous scan ${previous.id} vs current scan ${scan.scan_id}`} /><div className="grid gap-3 md:grid-cols-5">{[['Security Score', previousScore, score], ['Critical', previousCounts.CRITICAL, counts.CRITICAL], ['High', previousCounts.HIGH, counts.HIGH], ['Resolved', previousFindings.length, Math.max(0, previousFindings.length - scan.findings.length)], ['New', 0, Math.max(0, scan.findings.length - previousFindings.length)]].map(([label, before, after]) => <div key={String(label)} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">{label}</div><div className="mt-2 text-xl font-semibold text-slate-50">{before} → {after}</div></div>)}</div></Surface> : null}
      <AnalystReport analysis={artifacts?.ai_analyst_output} />
      {activeOutput ? <Surface className="p-6"><SectionHeader title="Active Security Evidence" description="Structured active-test output persisted by the backend sandbox run." /><div className="grid gap-3 md:grid-cols-4"><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Active Score</div><div className="mt-1 text-2xl font-semibold text-slate-50">{activeOutput.score?.score ?? '--'}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Plan Modules</div><div className="mt-1 text-2xl font-semibold text-slate-50">{activeOutput.test_plan?.modules?.length ?? 0}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Events</div><div className="mt-1 text-2xl font-semibold text-slate-50">{activeOutput.events?.length ?? 0}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Sandbox</div><div className="mt-1 break-all text-sm text-slate-100">{activeOutput.sandbox_id ?? 'Not provided'}</div></div></div>{activeOutput.evidence?.length ? <div className="mt-5 space-y-3">{activeOutput.evidence.slice(0, 8).map((item, index) => <div key={index} className="rounded-2xl bg-slate-950/60 p-4"><div className="font-medium text-slate-100">{String(item.title ?? `Evidence ${index + 1}`)}</div><div className="mt-2 break-all font-mono text-xs text-slate-500">{String(item.endpoint ?? '')}</div><p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">{String(item.evidence ?? '')}</p></div>)}</div> : <EmptyState title="No active evidence artifact" description="The active engine completed without finding-specific evidence records." />}</Surface> : null}
      <ObservabilityTabs browserOutput={artifacts?.browser_security_output} />
      <Surface className="p-6"><SectionHeader title="Findings" description="Persisted findings for this assessment." />{scan.findings.length ? <div className="space-y-3">{scan.findings.map((finding) => <div key={finding.id} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex flex-wrap items-center gap-3"><SeverityBadge severity={finding.severity} /><div className="font-medium text-slate-100">{finding.title}</div></div><p className="mt-3 text-sm leading-6 text-slate-400">{finding.evidence || finding.description}</p><div className="mt-4"><RemediationChecklist items={(finding.recommendation || finding.fix || 'Rerun after remediation.').split(/\n|\.\s+/).map((item) => item.trim()).filter(Boolean).slice(0, 5)} /></div></div>)}</div> : <EmptyState title="No findings" description="Your latest scan found no actionable issues." />}</Surface>
      <Surface className="p-6"><SectionHeader title="Report Artifacts" description="Generated backend artifacts retained with the scan." />{artifacts?.markdown_report ? <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap rounded-2xl bg-slate-950/70 p-4 text-sm text-slate-300">{artifacts.markdown_report}</pre> : <EmptyState title="No markdown report" description="The backend did not persist a remediation report for this scan." />}</Surface>
      <Surface className="p-6"><SectionHeader title="Hindi Explanations" description="Hindi AI output persisted by the backend when configured." />{artifacts?.hindi_findings?.length ? <div className="space-y-3">{artifacts.hindi_findings.map((item, index) => <div key={`${String(item.title)}-${index}`} className="rounded-2xl bg-white/[0.035] p-4"><div className="font-medium text-slate-100">{String(item.title ?? `Finding ${index + 1}`)}</div><p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">{[item.how_exploited, item.fix, item.recommendation].filter(Boolean).map(String).join('\n\n') || 'No Hindi text persisted.'}</p></div>)}</div> : <EmptyState title="No Hindi explanations" description="Hindi output is available when the backend AI explainer has a configured provider and returns results." />}</Surface>
      <div className="text-sm text-slate-500"><Link to="/history" className="text-violet-300 hover:text-violet-200">Back to Scan History</Link></div>
    </div>
  );
}
