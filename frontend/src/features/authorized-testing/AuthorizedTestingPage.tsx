import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { CheckCircle2, Loader2, LockKeyhole, ShieldCheck, Square } from 'lucide-react';

import {
  ActivityTimeline,
  Button,
  EmptyState,
  ErrorState,
  GlassPanel,
  ProgressBar,
  SectionHeader,
  SecurityScore,
  SeverityBadge,
  StatusBadge,
  Surface
} from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { useScanTelemetry } from '../../hooks/useScanTelemetry';
import {
  API_BASE_URL,
  activeMap,
  apiErrorMessage,
  createAuthorizationChallenge,
  getAuthorizationStatus,
  getLabStatus,
  revokeAuthorization,
  setLabScenario,
  startScan,
  stopScan,
  verifyAuthorization
} from '../../services/api';
import type {
  ActiveMapResponse,
  AuthorizationChallengeResponse,
  AuthorizationStatusResponse,
  LabStatusResponse,
  ScanIntensity,
  ScanResponse,
  TestModule,
  VerificationMethod
} from '../../types';
import { TEST_MODULES } from '../../types';
import { targetName } from '../../utils/derived';

const labTarget = `${API_BASE_URL}/lab/phantombank`;
const defaultModules: TestModule[] = [
  'input_security',
  'xss',
  'auth_session',
  'access_control',
  'csrf',
  'file_upload',
  'api_security',
  'websocket',
  'redirect',
  'security_headers',
  'cors',
  'sensitive_exposure'
];
const terminalStatuses = ['complete', 'error', 'cancelled'];

function formatLimit(seconds: number | undefined) {
  if (!seconds) return 'Backend default';
  if (seconds >= 60) return `${Math.round(seconds / 60)} minutes`;
  return `${seconds} seconds`;
}

function gateLabel(status: string | undefined) {
  if (status === 'TRAINING') return 'LAB VERIFIED';
  if (status === 'ALLOWLIST') return 'LOCAL DEV ALLOWLIST';
  if (status === 'VERIFIED') return 'OWNERSHIP VERIFIED';
  if (status === 'BLOCKED') return 'BLOCKED';
  return 'NOT MAPPED';
}

export default function AuthorizedTestingPage() {
  const { refresh } = usePhantomData();
  const [target, setTarget] = useState(labTarget);
  const [method, setMethod] = useState<VerificationMethod>('dns');
  const [challenge, setChallenge] = useState<AuthorizationChallengeResponse | null>(null);
  const [authorization, setAuthorization] = useState<AuthorizationStatusResponse | null>(null);
  const [selectedTests, setSelectedTests] = useState<TestModule[]>(defaultModules);
  const [profile, setProfile] = useState<ScanIntensity>('medium');
  const [confirmation, setConfirmation] = useState(true);
  const [activeScan, setActiveScan] = useState<ScanResponse | null>(null);
  const [mapResult, setMapResult] = useState<ActiveMapResponse | null>(null);
  const [labStatus, setLabStatus] = useState<LabStatusResponse | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const telemetry = useScanTelemetry(activeScan?.scan_id ?? null);

  const modulesByGroup = useMemo(() => {
    const grouped: Record<string, typeof TEST_MODULES> = {};
    for (const module of TEST_MODULES) grouped[module.group] = [...(grouped[module.group] ?? []), module];
    return grouped;
  }, []);
  const planModules = mapResult?.plan.modules ?? [];
  const plannedModuleIds = new Set(planModules.map((item) => item.module));
  const findings = telemetry.findings.length ? telemetry.findings : activeScan?.findings ?? [];
  const scanStatus = telemetry.scanStatus ?? activeScan?.status ?? null;
  const isRunning = Boolean(scanStatus && !terminalStatuses.includes(scanStatus));
  const gateStatus = mapResult?.gate.authorization_status;
  const isLab = mapResult?.gate.authorization_status === 'TRAINING' || target.includes('/lab/phantombank');
  const canExecute = Boolean(
    mapResult?.gate.allowed
    && selectedTests.length
    && (gateStatus !== 'VERIFIED' || confirmation)
  );

  const loadLabStatus = async () => {
    try {
      setLabStatus(await getLabStatus());
    } catch {
      setLabStatus(null);
    }
  };

  useEffect(() => {
    void loadLabStatus();
    const stored = window.localStorage.getItem('phantomscan.activeTest');
    if (stored) {
      try {
        const scan = JSON.parse(stored) as ScanResponse;
        setActiveScan(scan);
        setTarget(scan.target_url);
      } catch {
        window.localStorage.removeItem('phantomscan.activeTest');
      }
    }
  }, []);

  useEffect(() => {
    if (activeScan) window.localStorage.setItem('phantomscan.activeTest', JSON.stringify(activeScan));
  }, [activeScan]);

  const usePhantomBankLab = () => {
    setTarget(labTarget);
    setAuthorization(null);
    setChallenge(null);
    setConfirmation(true);
    setMapResult(null);
    toast.success('PhantomBank Lab selected');
  };

  const loadStatus = async () => {
    if (!target.trim()) return;
    setLoadingAction('status');
    setError(null);
    try {
      setAuthorization(await getAuthorizationStatus(target));
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to load authorization status.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const createChallenge = async () => {
    setLoadingAction('challenge');
    setError(null);
    try {
      const next = await createAuthorizationChallenge({ target_url: target, verification_method: method });
      setChallenge(next);
      setAuthorization({
        id: next.id,
        domain: next.domain,
        target_origin: next.target_origin,
        verification_method: next.verification_method,
        verified_at: null,
        expires_at: null,
        status: next.status,
        message: 'Target verification pending.'
      });
      toast.success('Verification challenge created');
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to create verification challenge.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const verify = async () => {
    const id = challenge?.id ?? authorization?.id;
    if (!id) return;
    setLoadingAction('verify');
    setError(null);
    try {
      const next = await verifyAuthorization(id);
      setAuthorization(next);
      toast.success('Target verified');
    } catch (err) {
      setError(apiErrorMessage(err, 'Verification token was not found.'));
      toast.error('Verification required');
    } finally {
      setLoadingAction(null);
    }
  };

  const revoke = async () => {
    if (!authorization?.id) return;
    setLoadingAction('revoke');
    try {
      setAuthorization(await revokeAuthorization(authorization.id));
      setMapResult(null);
      toast.success('Authorization revoked');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to revoke authorization.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const mapAttackSurface = async () => {
    setLoadingAction('map');
    setError(null);
    try {
      const mapped = await activeMap({
        target_url: target,
        selected_modules: selectedTests,
        authorization_id: authorization?.id ?? null,
        authorization_confirmed: confirmation
      });
      setMapResult(mapped);
      if (mapped.gate.authorization_status === 'TRAINING' || mapped.gate.authorization_status === 'ALLOWLIST') {
        setConfirmation(true);
      }
      toast.success(`Mapped ${mapped.surfaces.length} surfaces`);
    } catch (err) {
      setMapResult(null);
      setError(apiErrorMessage(err, 'Active target gate blocked mapping.'));
      toast.error('Mapping blocked');
    } finally {
      setLoadingAction(null);
    }
  };

  const execute = async () => {
    if (!mapResult) return;
    setLoadingAction('execute');
    setError(null);
    try {
      const verifiedExternal = mapResult.gate.authorization_status === 'VERIFIED';
      const scan = await startScan({
        target_url: target,
        mode: 'pentest',
        intensity: profile,
        selected_tests: selectedTests,
        authorization_id: verifiedExternal ? mapResult.gate.authorization_id ?? authorization?.id ?? null : null,
        authorization_confirmed: verifiedExternal ? confirmation : false
      });
      setActiveScan(scan);
      toast.success('Authorized test started');
      await refresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Unable to start authorized test.'));
      toast.error('Unable to start test');
    } finally {
      setLoadingAction(null);
    }
  };

  const stopTest = async () => {
    if (!activeScan) return;
    setLoadingAction('stop');
    try {
      await stopScan(activeScan.scan_id);
      setActiveScan({ ...activeScan, status: 'cancelling' });
      toast.success('Stop requested');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to stop test.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const switchScenario = async (state: 'VULNERABLE' | 'PATCHED', scenario?: string) => {
    setLoadingAction(`${scenario ?? 'all'}-${state}`);
    try {
      const response = await setLabScenario({ state, scenario: scenario ?? 'all' });
      setLabStatus((current) => current ? { ...current, scenario_state: response.scenario_state } : current);
      setMapResult(null);
      toast.success(`${scenario ?? 'All scenarios'} set to ${state}`);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to update lab scenario.'));
    } finally {
      setLoadingAction(null);
    }
  };

  const toggleModule = (module: TestModule) => {
    setSelectedTests((current) => current.includes(module) ? current.filter((item) => item !== module) : [...current, module]);
    setMapResult(null);
  };

  return (
    <div className="space-y-6 authorized-theme">
      <GlassPanel className="p-6 amber-glass">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <div className="mb-3 flex flex-wrap gap-2">
              <Link to="/scan" className="rounded-full bg-violet-500/12 px-3 py-1 text-xs font-semibold text-violet-200 ring-1 ring-violet-400/25">DEFEND</Link>
              <span className="rounded-full bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-100 ring-1 ring-amber-400/30">AUTHORIZED TEST</span>
              <span className="rounded-full bg-emerald-500/12 px-3 py-1 text-xs font-semibold text-emerald-200 ring-1 ring-emerald-400/25">SECURITY LAB</span>
            </div>
            <h1 className="text-2xl font-semibold text-slate-50">Active Security Testing Workspace</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Active verification is enforced by the backend target gate. Lab, localhost, allowlisted, or ownership-verified targets can run controlled modules.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3 xl:w-[520px]">
            <div className="rounded-2xl bg-white/[0.04] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-600">Authorization</div>
              <div className="mt-2"><StatusBadge status={gateLabel(mapResult?.gate.authorization_status)} /></div>
            </div>
            <div className="rounded-2xl bg-white/[0.04] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-600">Mapped Surfaces</div>
              <div className="mt-2 text-2xl font-semibold text-slate-50">{mapResult?.surfaces.length ?? 0}</div>
            </div>
            <div className="rounded-2xl bg-white/[0.04] p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-600">Selected Modules</div>
              <div className="mt-2 text-2xl font-semibold text-slate-50">{selectedTests.length}</div>
            </div>
          </div>
        </div>
      </GlassPanel>

      {error ? <ErrorState title="Active testing issue" description="PhantomScan could not complete the current action." detail={error} /> : null}

      <div className="grid gap-6 xl:grid-cols-[1fr_430px]">
        <Surface className="p-6">
          <SectionHeader title="Target Gate" description="Frontend controls are advisory; the backend gate makes the final active-test decision." />
          <div className="grid gap-4 lg:grid-cols-[1fr_220px]">
            <label className="block">
              <span className="mb-2 block text-sm text-slate-300">Target</span>
              <input
                value={target}
                onChange={(event) => { setTarget(event.target.value); setMapResult(null); }}
                placeholder="https://staging.example.com"
                className="h-14 w-full rounded-2xl border border-white/[0.08] bg-slate-950/55 px-4 font-mono text-sm text-slate-100 outline-none focus:border-amber-400/50"
              />
            </label>
            <div className="grid gap-3">
              <Button variant="amber" onClick={usePhantomBankLab}>Use PhantomBank Lab</Button>
              <Button variant="secondary" onClick={loadStatus} disabled={!target.trim() || loadingAction === 'status'}>
                {loadingAction === 'status' ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Check Ownership
              </Button>
            </div>
          </div>
          <div className="mt-5 grid gap-4 lg:grid-cols-2">
            <div className="rounded-3xl bg-white/[0.035] p-5">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <div className="font-semibold text-slate-100">Ownership Verification</div>
                  <div className="mt-1 text-sm text-slate-500">Required for external non-allowlisted targets.</div>
                </div>
                <StatusBadge status={authorization?.status ?? (isLab ? 'LAB VERIFIED' : 'PENDING')} />
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_1fr]">
                <button onClick={() => setMethod('dns')} className={`rounded-2xl px-4 py-3 text-sm ${method === 'dns' ? 'bg-amber-500/15 text-amber-100' : 'bg-white/[0.04] text-slate-400'}`}>DNS TXT</button>
                <button onClick={() => setMethod('http')} className={`rounded-2xl px-4 py-3 text-sm ${method === 'http' ? 'bg-amber-500/15 text-amber-100' : 'bg-white/[0.04] text-slate-400'}`}>HTTP File</button>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <Button variant="secondary" onClick={createChallenge} disabled={isLab || !target.trim() || loadingAction === 'challenge'}>
                  <LockKeyhole className="h-4 w-4" />Challenge
                </Button>
                <Button variant="secondary" onClick={verify} disabled={(!challenge?.id && !authorization?.id) || loadingAction === 'verify'}>
                  <CheckCircle2 className="h-4 w-4" />Verify
                </Button>
                <Button variant="secondary" onClick={revoke} disabled={!authorization?.id || loadingAction === 'revoke'}>Revoke</Button>
              </div>
              {challenge ? (
                <div className="mt-4 rounded-2xl bg-slate-950/70 p-3 font-mono text-xs text-amber-100">
                  {method === 'dns' ? challenge.dns_record : challenge.http_url}
                </div>
              ) : null}
            </div>
            <div className="rounded-3xl bg-white/[0.035] p-5">
              <div className="font-semibold text-slate-100">Attack Surface Mapper</div>
              <p className="mt-1 text-sm leading-6 text-slate-500">Mapping consumes the lab manifest or conservatively parses the approved target root page.</p>
              <Button variant="amber" className="mt-5 w-full" onClick={mapAttackSurface} disabled={!target.trim() || loadingAction === 'map'}>
                {loadingAction === 'map' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                Map Attack Surface
              </Button>
              <div className="mt-4 grid gap-2 text-sm">
                <div className="flex justify-between rounded-2xl bg-white/[0.04] px-4 py-3"><span className="text-slate-500">Plan modules</span><span className="text-slate-100">{planModules.length}</span></div>
                <div className="flex justify-between rounded-2xl bg-white/[0.04] px-4 py-3"><span className="text-slate-500">Plan score</span><span className="text-slate-100">{mapResult?.score.score ?? '--'}</span></div>
              </div>
            </div>
          </div>
        </Surface>

        <Surface className="p-6">
          <SectionHeader title="PhantomBank Lab" description="Fake users and fake data only. Switch vulnerable to patched, then verify fixes." />
          {labStatus ? (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <Button variant="danger" onClick={() => void switchScenario('VULNERABLE')} disabled={loadingAction === 'all-VULNERABLE'}>Switch All Vulnerable</Button>
                <Button variant="secondary" onClick={() => void switchScenario('PATCHED')} disabled={loadingAction === 'all-PATCHED'}>Switch All Patched</Button>
              </div>
              <div className="max-h-[430px] space-y-2 overflow-auto pr-1">
                {Object.entries(labStatus.scenarios).map(([scenario, modules]) => {
                  const state = labStatus.scenario_state[scenario] ?? 'VULNERABLE';
                  return (
                    <div key={scenario} className="rounded-2xl bg-white/[0.035] p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate font-mono text-sm text-slate-200">{scenario.replace(/_/g, ' ')}</div>
                          <div className="mt-1 text-xs text-slate-500">{modules.join(', ')}</div>
                        </div>
                        <StatusBadge status={state} />
                      </div>
                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        <button onClick={() => void switchScenario('VULNERABLE', scenario)} className="rounded-xl bg-red-500/10 px-3 py-2 text-xs font-semibold text-red-200">Vulnerable</button>
                        <button onClick={() => void switchScenario('PATCHED', scenario)} className="rounded-xl bg-emerald-500/10 px-3 py-2 text-xs font-semibold text-emerald-200">Patched</button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : <EmptyState title="Lab status unavailable" description="Start the backend and refresh to use PhantomBank Lab scenarios." />}
        </Surface>
      </div>

      <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)_360px]">
        <Surface className="p-6">
          <SectionHeader title="Test Plan" description="Only modules relevant to mapped surfaces are planned by the backend." />
          <div className="space-y-3 text-sm">
            {[
              ['Target', isLab ? 'PhantomBank Lab' : targetName(target)],
              ['Authorization', gateLabel(mapResult?.gate.authorization_status)],
              ['Mapped Surfaces', String(mapResult?.surfaces.length ?? 0)],
              ['Selected Modules', String(selectedTests.length)],
              ['Request Limit', String(mapResult?.limits.max_requests ?? 'Backend default')],
              ['Timeout', formatLimit(mapResult?.limits.timeout_seconds)]
            ].map(([label, value]) => (
              <div key={label} className="flex items-center justify-between gap-4 rounded-2xl bg-white/[0.04] px-4 py-3">
                <span className="text-slate-500">{label}</span>
                <span className="break-all text-right text-slate-100">{value}</span>
              </div>
            ))}
          </div>
          <div className="mt-5 grid gap-3">
            {(['low', 'medium', 'high'] as ScanIntensity[]).map((item) => (
              <button key={item} onClick={() => setProfile(item)} className={`rounded-2xl p-3 text-left capitalize ${profile === item ? 'bg-amber-500/15 text-amber-100 ring-1 ring-amber-400/30' : 'bg-white/[0.035] text-slate-300'}`}>
                {item} intensity
              </button>
            ))}
          </div>
          <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-2xl bg-white/[0.035] p-4">
            <input type="checkbox" checked={confirmation} onChange={(event) => setConfirmation(event.target.checked)} className="mt-1 accent-amber-400" />
            <span className="text-sm leading-6 text-slate-400">I have explicit authorization. Lab and localhost runs are still gated by the backend.</span>
          </label>
          <Button variant="amber" className="mt-5 w-full py-3" onClick={execute} disabled={!canExecute || loadingAction === 'execute'}>
            {loadingAction === 'execute' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            RUN AUTHORIZED TEST
          </Button>
          <div className="mt-5 space-y-4">
            {Object.entries(modulesByGroup).map(([group, modules]) => (
              <div key={group} className="rounded-2xl bg-white/[0.025] p-3">
                <div className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-600">{group}</div>
                <div className="space-y-2">
                  {modules.map((module) => {
                    const planned = plannedModuleIds.has(String(module.id));
                    return (
                      <label key={module.id} className="flex cursor-pointer items-start gap-3 rounded-xl px-2 py-2 hover:bg-white/[0.04]">
                        <input type="checkbox" checked={selectedTests.includes(module.id)} onChange={() => toggleModule(module.id)} className="mt-1 accent-amber-400" />
                        <span>
                          <span className="block text-sm font-medium text-slate-200">{module.label}</span>
                          <span className="block text-xs text-slate-500">{planned ? 'Planned on mapped surface' : module.description}</span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </Surface>

        <Surface className="p-6">
          <SectionHeader
            title="Live Activity"
            description={activeScan ? `Scan ${activeScan.scan_id} against ${targetName(activeScan.target_url)}` : 'Map a target and run an authorized test.'}
            action={isRunning ? (
              <Button variant="danger" onClick={stopTest} disabled={loadingAction === 'stop'}>
                {loadingAction === 'stop' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
                STOP TEST
              </Button>
            ) : activeScan ? <Link className="text-sm font-semibold text-amber-200 hover:text-amber-100" to={`/report/${activeScan.scan_id}`}>Open report</Link> : null}
          />
          {activeScan ? (
            <div className="space-y-5">
              <ProgressBar value={telemetry.progress || activeScan.progress} amber />
              <div className="grid gap-3 sm:grid-cols-4">
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Progress</div><div className="mt-1 text-2xl font-semibold text-slate-50">{telemetry.progress || activeScan.progress}%</div></div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Requests</div><div className="mt-1 text-2xl font-semibold text-slate-50">{telemetry.requestCount || activeScan.request_count}</div></div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Findings</div><div className="mt-1 text-2xl font-semibold text-slate-50">{findings.length}</div></div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Status</div><div className="mt-2"><StatusBadge status={scanStatus ?? activeScan.status} /></div></div>
              </div>
              {telemetry.error ? <ErrorState title="Realtime connection issue" description="The scan remains available through backend polling." detail={telemetry.error} /> : null}
              <ActivityTimeline events={telemetry.events} />
            </div>
          ) : (
            <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
              <SecurityScore score={mapResult?.score.score ?? 100} />
              <EmptyState title="No active test running" description="Run mapping, review planned modules, then launch an authorized test to stream real WebSocket activity here." />
            </div>
          )}
        </Surface>

        <Surface className="p-6">
          <SectionHeader title="Findings" description="New active-test findings appear from persisted backend scan data." />
          {findings.length ? (
            <div className="space-y-3">
              {findings.map((finding) => (
                <div key={finding.id} className="rounded-2xl bg-white/[0.035] p-4">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <StatusBadge status={finding.confidence} />
                  </div>
                  <div className="font-medium text-slate-100">{finding.title}</div>
                  <div className="mt-2 break-all font-mono text-xs text-slate-500">{finding.endpoint || finding.target}</div>
                  <p className="mt-3 line-clamp-4 text-sm leading-6 text-slate-400">{finding.evidence || finding.description}</p>
                </div>
              ))}
            </div>
          ) : <EmptyState title="No active findings yet" description="The lab vulnerable state should produce findings. Patched scenarios should pass without findings." />}
        </Surface>
      </div>
    </div>
  );
}
