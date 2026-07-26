import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Loader2, Search, ShieldCheck, Sparkles } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import type { AISecurityAnalystOutput, Finding, RiskStatus, Severity } from '../../types';
import { Button, Drawer, EmptyState, RemediationChecklist, SectionHeader, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { apiErrorMessage, updateFindingRemediation, updateFindingRiskStatus, verifyFindingFix } from '../../services/api';
import { formatDateTime, relativeTime, severityOrder, targetName } from '../../utils/derived';

function checklist(finding: Finding) {
  const fix = finding.recommended_fix || finding.recommendation || finding.fix || 'Review and remediate this finding.';
  return fix
    .split(/\n|\.\s+/)
    .map((item) => item.trim().replace(/^[-*\d.)\s]+/, ''))
    .filter(Boolean)
    .slice(0, 6);
}

function text(value: unknown, fallback = 'Not available'): string {
  if (value === null || value === undefined || value === '') return fallback;
  return typeof value === 'string' ? value : String(value);
}

function sameId(value: unknown, id: number): boolean {
  return String(value ?? '') === String(id);
}

function relatedChainsFor(analyst: AISecurityAnalystOutput | null | undefined, id: number) {
  return (analyst?.related_security_chains ?? []).filter((chain) => {
    const primary = chain.primary as Record<string, unknown> | undefined;
    const related = Array.isArray(chain.related) ? chain.related as Array<Record<string, unknown>> : [];
    return sameId(primary?.id, id) || related.some((item) => sameId(item.id, id));
  });
}

function remediationPlanFor(analyst: AISecurityAnalystOutput | null | undefined, id: number) {
  return Object.entries(analyst?.remediation_plan ?? {}).flatMap(([bucket, items]) =>
    (items ?? [])
      .filter((item) => sameId(item.finding_id, id))
      .map((item) => ({ bucket, item }))
  );
}

function FindingDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const { artifactsByScanId, refresh } = usePhantomData();
  const [language, setLanguage] = useState<'en' | 'hi'>('en');
  const [action, setAction] = useState<string | null>(null);
  const analyst = finding ? artifactsByScanId[finding.scan_id]?.ai_analyst_output : null;
  const priority = finding ? analyst?.priorities?.find((item) => sameId(item.finding_id, finding.id)) : undefined;
  const developerAnalysis = finding ? analyst?.developer_report?.find((item) => sameId(item.finding_id, finding.id)) : undefined;
  const relatedChains = finding ? relatedChainsFor(analyst, finding.id) : [];
  const planItems = finding ? remediationPlanFor(analyst, finding.id) : [];
  const hindiRecord = finding
    ? artifactsByScanId[finding.scan_id]?.hindi_findings?.find((item) => String(item.title ?? '') === finding.title)
    : null;
  const hindiText = hindiRecord
    ? [hindiRecord.how_exploited, hindiRecord.fix, hindiRecord.recommendation].filter(Boolean).join('\n\n')
    : '';

  const markInProgress = async () => {
    if (!finding) return;
    setAction('progress');
    try {
      await updateFindingRemediation(finding.id, 'IN_PROGRESS');
      toast.success('Finding marked in progress');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to update remediation status.'));
    } finally {
      setAction(null);
    }
  };

  const verifyFix = async () => {
    if (!finding) return;
    setAction('verify');
    try {
      const result = await verifyFindingFix(finding.id);
      toast.success(result.status === 'FIX_VERIFIED' ? 'Fix verified' : 'Issue still present');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to verify fix.'));
    } finally {
      setAction(null);
    }
  };

  const updateRisk = async (riskStatus: RiskStatus) => {
    if (!finding) return;
    setAction(riskStatus);
    try {
      await updateFindingRiskStatus(finding.id, riskStatus);
      toast.success(riskStatus === 'ACTIVE' ? 'Finding reactivated' : 'Finding excluded from active priority');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to update risk status.'));
    } finally {
      setAction(null);
    }
  };

  return (
    <Drawer title={finding?.title ?? 'Finding'} open={Boolean(finding)} onClose={onClose}>
      {finding ? (
        <div className="space-y-6">
          <div className="flex flex-wrap gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.remediation_status ?? 'OPEN'} />
            <StatusBadge status={finding.verification_status ?? 'NOT_VERIFIED'} />
            <StatusBadge status={finding.risk_status ?? 'ACTIVE'} />
            <StatusBadge status={finding.confidence} />
          </div>
          <section>
            <h3 className="mb-2 font-semibold text-slate-100">Overview</h3>
            <p className="text-sm leading-6 text-slate-400">{finding.description || finding.evidence || 'No overview was persisted for this finding.'}</p>
          </section>
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              ['Asset', targetName(finding.target)],
              ['Endpoint', finding.endpoint || finding.target],
              ['Category', finding.category],
              ['Confidence', finding.confidence],
              ['Module', finding.module || 'Not mapped'],
              ['Parameter', finding.parameter || 'Not applicable'],
              ['Detected by', finding.agent],
              ['First detected', formatDateTime(finding.timestamp)]
            ].map(([label, value]) => <div key={label} className="rounded-2xl bg-white/[0.035] p-3"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">{label}</div><div className="mt-2 break-words text-sm text-slate-200">{value}</div></div>)}
          </div>
          <section><h3 className="mb-2 font-semibold text-slate-100">Evidence</h3><pre className="whitespace-pre-wrap rounded-2xl bg-slate-950/60 p-4 font-mono text-xs text-slate-300">{finding.evidence || finding.description || 'No evidence text persisted.'}</pre></section>
          <section><h3 className="mb-2 font-semibold text-slate-100">Impact</h3><p className="text-sm leading-6 text-slate-400">{finding.impact || finding.how_exploited || 'Impact was not persisted for this finding.'}</p></section>
          <section>
            <div className="mb-3 flex items-center justify-between gap-3"><h3 className="font-semibold text-slate-100">AI Explanation</h3><div className="rounded-2xl bg-white/[0.04] p-1"><button onClick={() => setLanguage('en')} className={`rounded-xl px-3 py-1.5 text-xs ${language === 'en' ? 'bg-violet-500/20 text-violet-100' : 'text-slate-500'}`}>English</button><button onClick={() => setLanguage('hi')} className={`rounded-xl px-3 py-1.5 text-xs ${language === 'hi' ? 'bg-violet-500/20 text-violet-100' : 'text-slate-500'}`}>Hindi</button></div></div>
            <p className="whitespace-pre-wrap text-sm leading-6 text-slate-400">{language === 'en' ? finding.how_exploited || finding.impact || 'English AI explanation was not persisted.' : hindiText || 'Hindi explanation was not persisted for this finding. Configure the backend AI explainer and rerun the scan.'}</p>
          </section>
          <section>
            <h3 className="mb-3 flex items-center gap-2 font-semibold text-slate-100"><Sparkles className="h-4 w-4 text-violet-300" />AI Security Analyst</h3>
            {analyst ? (
              <div className="space-y-3">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="rounded-2xl bg-white/[0.035] p-3"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">Priority</div><div className="mt-2 text-lg font-semibold text-slate-50">{priority ? `#${priority.priority}` : 'Not active'}</div></div>
                  <div className="rounded-2xl bg-white/[0.035] p-3"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">Analyst Score</div><div className="mt-2 text-lg font-semibold text-slate-50">{priority?.score ?? '--'}</div></div>
                  <div className="rounded-2xl bg-white/[0.035] p-3"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">AI Active Tests</div><div className="mt-2 text-sm text-slate-200">{analyst.safety?.can_start_active_test === false ? 'Disabled' : 'Not available'}</div></div>
                </div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="mb-1 text-sm font-semibold text-slate-100">Recommended Action</div><p className="text-sm leading-6 text-slate-400">{priority?.recommended_action || developerAnalysis?.remediation || finding.recommendation || 'Review evidence and remediate.'}</p></div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="mb-1 text-sm font-semibold text-slate-100">Why {finding.confidence === 'CONFIRMED' ? 'Confirmed' : 'Potential'}</div><p className="text-sm leading-6 text-slate-400">{finding.confidence === 'CONFIRMED' ? 'The persisted finding is marked CONFIRMED by the scanner evidence. PhantomScan cites the finding record rather than inventing additional proof.' : 'The scanner observed a suspicious signal, but the record is not CONFIRMED. Treat it as needing repeatable browser or active verification before calling it proven.'}</p>{priority?.factors?.length ? <div className="mt-3 flex flex-wrap gap-2">{priority.factors.map((factor) => <StatusBadge key={factor} status={factor} />)}</div> : null}</div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="mb-2 text-sm font-semibold text-slate-100">Related Findings</div>{relatedChains.length ? <div className="space-y-2">{relatedChains.map((chain, index) => <div key={index} className="text-sm leading-6 text-slate-400"><span className="font-medium text-slate-200">{text(chain.title, `Chain ${index + 1}`)}:</span> {text(chain.explanation, 'Evidence-related chain.')}</div>)}</div> : <div className="text-sm text-slate-500">No related chain was identified for this finding.</div>}</div>
                <div className="rounded-2xl bg-white/[0.035] p-4"><div className="mb-2 text-sm font-semibold text-slate-100">Remediation Plan</div>{planItems.length ? <div className="space-y-2">{planItems.map(({ bucket, item }) => <div key={`${bucket}-${text(item.finding_id)}`} className="text-sm leading-6 text-slate-400"><StatusBadge status={bucket} /> <span className="ml-2">{text(item.action)}</span></div>)}</div> : <div className="text-sm text-slate-500">This finding is not in the active analyst priority plan.</div>}</div>
              </div>
            ) : <div className="rounded-2xl bg-white/[0.035] p-4 text-sm text-slate-500">No AI Security Analyst artifact is available for this scan yet.</div>}
          </section>
          <section><h3 className="mb-3 font-semibold text-slate-100">Recommended Fix</h3><RemediationChecklist items={checklist(finding)} /></section>
          <section><h3 className="mb-2 font-semibold text-slate-100">Verification</h3><p className="text-sm leading-6 text-slate-400">{finding.verification || 'Rerun the relevant PhantomScan check after remediation.'}</p></section>
          <section>
            <h3 className="mb-3 font-semibold text-slate-100">Remediation Actions</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <Button onClick={markInProgress} disabled={action === 'progress' || finding.remediation_status === 'RESOLVED'}>
                {action === 'progress' ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Mark In Progress
              </Button>
              <Button variant="amber" onClick={verifyFix} disabled={action === 'verify'}>
                {action === 'verify' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                Verify Fix
              </Button>
            </div>
            <div className="mt-3 grid gap-3 sm:grid-cols-3">
              <Button variant="secondary" onClick={() => updateRisk('ACTIVE')} disabled={action === 'ACTIVE' || (finding.risk_status ?? 'ACTIVE') === 'ACTIVE'}>
                {action === 'ACTIVE' ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Active Risk
              </Button>
              <Button variant="secondary" onClick={() => updateRisk('FALSE_POSITIVE')} disabled={action === 'FALSE_POSITIVE' || finding.risk_status === 'FALSE_POSITIVE'}>
                {action === 'FALSE_POSITIVE' ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                False Positive
              </Button>
              <Button variant="secondary" onClick={() => updateRisk('ACCEPTED_RISK')} disabled={action === 'ACCEPTED_RISK' || finding.risk_status === 'ACCEPTED_RISK'}>
                {action === 'ACCEPTED_RISK' ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Accept Risk
              </Button>
            </div>
          </section>
          <section><h3 className="mb-2 font-semibold text-slate-100">History</h3><div className="rounded-2xl bg-white/[0.035] p-4 text-sm text-slate-400">Detected {formatDateTime(finding.timestamp)} by {finding.agent}. Current status: {finding.remediation_status ?? 'OPEN'} / {finding.verification_status ?? 'NOT_VERIFIED'} / {finding.risk_status ?? 'ACTIVE'}.</div></section>
        </div>
      ) : null}
    </Drawer>
  );
}

export default function FindingsPage() {
  const { findings } = usePhantomData();
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const [selected, setSelected] = useState<Finding | null>(null);
  const categories = useMemo(() => ['All', ...Array.from(new Set(findings.map((finding) => finding.category))).sort()], [findings]);
  const filtered = findings.filter((finding) => {
    const matchesSeverity = severity === 'ALL' || finding.severity === severity;
    const matchesCategory = category === 'All' || finding.category === category;
    const haystack = `${finding.title} ${finding.target} ${finding.endpoint} ${finding.category} ${finding.agent} ${finding.cve_id ?? ''}`.toLowerCase();
    return matchesSeverity && matchesCategory && haystack.includes(query.toLowerCase());
  });

  return (
    <div className="space-y-6">
      <Surface className="p-6">
        <SectionHeader title="Findings" description={`${findings.length} total persisted findings.`} />
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap gap-2">
            <button onClick={() => setSeverity('ALL')} className={`rounded-2xl px-3 py-2 text-sm ${severity === 'ALL' ? 'bg-violet-500/15 text-violet-100' : 'bg-white/[0.04] text-slate-400'}`}>All</button>
            {severityOrder.map((item) => <button key={item} onClick={() => setSeverity(item)} className={`rounded-2xl px-3 py-2 text-sm ${severity === item ? 'bg-violet-500/15 text-violet-100' : 'bg-white/[0.04] text-slate-400'}`}>{item}</button>)}
          </div>
          <div className="grid gap-3 sm:grid-cols-[180px_1fr] lg:w-[520px]">
            <select value={category} onChange={(event) => setCategory(event.target.value)} className="h-11 rounded-2xl border border-white/[0.08] bg-slate-950/60 px-3 text-sm text-slate-200 outline-none">{categories.map((item) => <option key={item}>{item}</option>)}</select>
            <div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings..." className="h-11 w-full rounded-2xl border border-white/[0.08] bg-slate-950/60 pl-10 pr-3 text-sm text-slate-200 outline-none" /></div>
          </div>
        </div>
      </Surface>

      <Surface className="overflow-hidden">
        {filtered.length ? (
          <div className="hidden md:block">
            <div className="grid grid-cols-[120px_1.4fr_1fr_150px_120px_120px_120px] gap-4 border-b border-white/[0.06] px-5 py-3 text-xs uppercase tracking-[0.18em] text-slate-600">
              <span>Severity</span><span>Finding</span><span>Asset</span><span>Category</span><span>Confidence</span><span>Status</span><span>Found</span>
            </div>
            {filtered.map((finding) => (
              <button key={finding.id} onClick={() => setSelected(finding)} className="grid w-full grid-cols-[120px_1.4fr_1fr_150px_120px_120px_120px] gap-4 border-b border-white/[0.04] px-5 py-4 text-left transition last:border-b-0 hover:bg-white/[0.04]">
                <SeverityBadge severity={finding.severity} />
                <span className="truncate font-medium text-slate-100">{finding.title}</span>
                <span className="truncate font-mono text-sm text-slate-400">{targetName(finding.target)}</span>
                <span className="truncate text-sm text-slate-400">{finding.category}</span>
                <span className="text-sm text-slate-400">{finding.confidence}</span>
                <span className="flex flex-col items-start gap-1"><StatusBadge status={finding.remediation_status ?? 'OPEN'} /><StatusBadge status={finding.risk_status ?? 'ACTIVE'} /></span>
                <span className="text-sm text-slate-500">{relativeTime(finding.timestamp)}</span>
              </button>
            ))}
          </div>
        ) : <EmptyState title="No findings" description="Your latest scan found no actionable issues." />}
        {filtered.length ? (
          <div className="space-y-3 p-4 md:hidden">
            {filtered.map((finding) => <button key={finding.id} onClick={() => setSelected(finding)} className="w-full rounded-2xl bg-white/[0.035] p-4 text-left"><div className="mb-3 flex items-center justify-between gap-3"><SeverityBadge severity={finding.severity} /><span className="flex flex-wrap justify-end gap-1"><StatusBadge status={finding.remediation_status ?? 'OPEN'} /><StatusBadge status={finding.risk_status ?? 'ACTIVE'} /></span></div><div className="font-medium text-slate-100">{finding.title}</div><div className="mt-2 font-mono text-sm text-slate-500">{targetName(finding.target)}</div><div className="mt-2 text-xs text-slate-500">{relativeTime(finding.timestamp)}</div></button>)}
          </div>
        ) : null}
      </Surface>
      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
