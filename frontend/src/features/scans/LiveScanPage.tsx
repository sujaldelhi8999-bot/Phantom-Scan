import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Check, Loader2, RotateCcw, ShieldCheck, Square } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import { useScanTelemetry } from '../../hooks/useScanTelemetry';
import { apiErrorMessage, startScan, stopScan } from '../../services/api';
import type { ScanIntensity, ScanResponse } from '../../types';
import { DEFEND_CHECKS } from '../../types';
import { ActivityTimeline, AgentRow, Button, EmptyState, ErrorState, GlassPanel, ProgressBar, SectionHeader, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { countBySeverity, targetName } from '../../utils/derived';

const profiles: Array<{ id: ScanIntensity; label: string; description: string }> = [
  { id: 'low', label: 'Quick', description: 'Baseline checks and fast posture signal.' },
  { id: 'medium', label: 'Standard', description: 'Balanced passive security assessment.' },
  { id: 'high', label: 'Deep', description: 'Full passive analysis and intelligence enrichment.' }
];

export default function LiveScanPage() {
  const navigate = useNavigate();
  const { refresh, scans } = usePhantomData();
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<ScanIntensity>('medium');
  const [activeScan, setActiveScan] = useState<ScanResponse | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const telemetry = useScanTelemetry(activeScan?.scan_id ?? null);
  const displayFindings = telemetry.findings.length ? telemetry.findings : activeScan?.findings ?? [];
  const counts = countBySeverity(displayFindings);
  const terminal = telemetry.scanStatus ? ['complete', 'error', 'cancelled'].includes(telemetry.scanStatus) : false;

  useEffect(() => {
    const stored = localStorage.getItem('phantomscan:active-defend-scan');
    if (stored) {
      try {
        setActiveScan(JSON.parse(stored) as ScanResponse);
      } catch {
        localStorage.removeItem('phantomscan:active-defend-scan');
      }
    }
  }, []);

  useEffect(() => {
    if (activeScan) localStorage.setItem('phantomscan:active-defend-scan', JSON.stringify(activeScan));
  }, [activeScan]);

  const latestDefend = useMemo(() => scans.find((scan) => scan.mode === 'defend'), [scans]);

  const runScan = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const scan = await startScan({ target_url: target, mode: 'defend', intensity: profile });
      setActiveScan(scan);
      toast.success('Scan started');
      await refresh();
    } catch (err) {
      const message = apiErrorMessage(err, 'PhantomScan could not start this assessment.');
      setError(message);
      toast.error('Unable to start scan');
    } finally {
      setSubmitting(false);
    }
  };

  const stopActiveScan = async () => {
    if (!activeScan) return;
    try {
      await stopScan(activeScan.scan_id);
      toast.success('Cancellation requested');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to cancel scan.'));
    }
  };

  const resetScan = () => {
    setActiveScan(null);
    localStorage.removeItem('phantomscan:active-defend-scan');
  };

  return (
    <div className="space-y-6">
      <GlassPanel className="p-6">
        <SectionHeader title="Scan Configuration" description="Defend mode runs passive security assessment modules only. Authorized Testing controls are intentionally not exposed here." />
        <div className="grid gap-6 xl:grid-cols-[1fr_380px]">
          <div className="space-y-5">
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-300">Target</span>
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="https://example.com"
                className="h-14 w-full rounded-2xl border border-white/[0.08] bg-slate-950/55 px-4 font-mono text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-violet-400/50 focus:bg-slate-950/80"
              />
            </label>
            <div>
              <div className="mb-2 text-sm font-medium text-slate-300">Profile</div>
              <div className="grid gap-3 sm:grid-cols-3">
                {profiles.map((item) => (
                  <button key={item.id} onClick={() => setProfile(item.id)} className={`rounded-2xl border p-4 text-left transition ${profile === item.id ? 'border-violet-400/50 bg-violet-500/12' : 'border-white/[0.08] bg-white/[0.035] hover:bg-white/[0.06]'}`}>
                    <div className="font-semibold text-slate-100">{item.label}</div>
                    <div className="mt-1 text-sm text-slate-500">{item.description}</div>
                  </button>
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-3 border-t border-white/[0.06] pt-5 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-sm text-slate-500">Latest Defend baseline: {latestDefend ? `${targetName(latestDefend.target_url)} · ${latestDefend.status}` : 'No scans yet'}</div>
              <div className="flex gap-3">
                {activeScan ? <Button variant="secondary" onClick={resetScan}><RotateCcw className="h-4 w-4" />New Target</Button> : null}
                <Button variant="primary" onClick={runScan} disabled={submitting || !target.trim() || Boolean(activeScan && !terminal)}>
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                  Run Security Scan
                </Button>
              </div>
            </div>
            {error ? <ErrorState title="Unable to start scan" description="PhantomScan could not start this assessment." detail={error} action={<Button onClick={runScan} variant="secondary">Retry</Button>} /> : null}
          </div>
          <Surface className="p-5">
            <div className="mb-4 text-sm font-semibold text-slate-200">Included Defend Checks</div>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
              {DEFEND_CHECKS.map((check) => (
                <div key={check} className="flex items-center gap-3 rounded-2xl bg-white/[0.035] px-3 py-2.5 text-sm text-slate-300">
                  <Check className="h-4 w-4 text-violet-300" />
                  {check}
                </div>
              ))}
            </div>
          </Surface>
        </div>
      </GlassPanel>

      <div className="grid gap-6 xl:grid-cols-[1fr_420px]">
        <Surface className="p-6">
          <SectionHeader
            title="Scan Activity"
            description={activeScan ? `Assessing ${targetName(activeScan.target_url)}` : 'Live timeline appears after a scan starts.'}
            action={activeScan && !terminal ? <Button variant="danger" onClick={stopActiveScan}><Square className="h-4 w-4" />Cancel Scan</Button> : activeScan && terminal ? <Button variant="secondary" onClick={() => navigate(`/report/${activeScan.scan_id}`)}>Open Report</Button> : null}
          />
          {activeScan ? (
            <div className="space-y-6">
              <div className="rounded-3xl border border-white/[0.06] bg-white/[0.035] p-5">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <div>
                    <div className="font-semibold text-slate-100">Security Assessment</div>
                    <div className="mt-1 text-sm text-slate-500">{telemetry.events[telemetry.events.length - 1]?.title ?? 'Initializing assessment'}</div>
                  </div>
                  <StatusBadge status={telemetry.scanStatus ?? activeScan.status} />
                </div>
                <ProgressBar value={telemetry.progress || activeScan.progress} />
                <div className="mt-3 flex flex-wrap gap-4 text-sm text-slate-500">
                  <span>{telemetry.progress || activeScan.progress}% complete</span>
                  <span>{telemetry.requestCount || activeScan.request_count} requests</span>
                  <span>Realtime: {telemetry.connectionState}</span>
                </div>
              </div>
              {telemetry.error ? <ErrorState title="Realtime connection issue" description="The scan remains available through backend polling." detail={telemetry.error} /> : null}
              <ActivityTimeline events={telemetry.events} />
            </div>
          ) : <EmptyState title="No active scan" description="Configure a target and run a security assessment to stream live progress." />}
        </Surface>

        <Surface className="p-6">
          <SectionHeader title="Agent Status" description="Compact operational state for this scan." />
          {activeScan ? (
            <div className="space-y-2">
              {(telemetry.agents.length ? telemetry.agents : []).map((agent) => <AgentRow key={agent.name} agent={agent} />)}
              {!telemetry.agents.length ? <EmptyState title="Waiting for agents" description="Agent telemetry will appear when backend audit events arrive." /> : null}
            </div>
          ) : <EmptyState title="No agent activity" description="Agents are assigned after a scan is created." />}
        </Surface>
      </div>

      <Surface className="p-6">
        <SectionHeader title="Findings" description="Live finding records streamed by the backend." />
        {displayFindings.length ? (
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-5">
              {Object.entries(counts).map(([severity, count]) => <div key={severity} className="rounded-2xl bg-white/[0.035] p-3"><SeverityBadge severity={severity as keyof typeof counts} /><div className="mt-2 text-xl font-semibold text-slate-50">{count}</div></div>)}
            </div>
            {displayFindings.slice(-8).reverse().map((finding) => (
              <div key={finding.id} className="grid gap-3 rounded-2xl bg-white/[0.035] p-4 sm:grid-cols-[110px_1fr_150px] sm:items-center">
                <SeverityBadge severity={finding.severity} />
                <div className="min-w-0"><div className="truncate font-medium text-slate-100">{finding.title}</div><div className="truncate text-sm text-slate-500">{finding.category}</div></div>
                <StatusBadge status="Open" />
              </div>
            ))}
          </div>
        ) : <EmptyState title="No findings" description="Your latest scan found no actionable issues." />}
      </Surface>
    </div>
  );
}
