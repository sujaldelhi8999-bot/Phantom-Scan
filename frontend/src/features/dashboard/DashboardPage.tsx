import { Link } from 'react-router-dom';
import { ArrowUpRight, Sparkles } from 'lucide-react';

import { usePhantomData } from '../../hooks/usePhantomData';
import { ActivityTimeline, EmptyState, GlassPanel, MetricCard, SectionHeader, SecurityScore, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { agentSummary, countBySeverity, deriveAssets, formatDateTime, latestCompletedScan, relativeTime, securityScore, targetName } from '../../utils/derived';

export default function DashboardPage() {
  const { scans, findings, agents, logs, health, loading, artifactsByScanId } = usePhantomData();
  const latestScan = latestCompletedScan(scans);
  const latestFindings = latestScan ? findings.filter((finding) => finding.scan_id === latestScan.id) : findings;
  const analyst = latestScan ? artifactsByScanId[latestScan.id]?.ai_analyst_output : null;
  const analystSummary = analyst?.security_summary;
  const topPriority = analyst?.priorities?.[0];
  const score = securityScore(latestFindings);
  const counts = countBySeverity(latestFindings);
  const assets = deriveAssets(scans, findings);
  const summary = agentSummary(agents);
  const timeline = logs.slice(-8).map((log) => ({
    id: `dashboard-log-${log.id}`,
    timestamp: new Date(log.timestamp).toLocaleTimeString('en-GB', { hour12: false }),
    title: log.action.replace(/_/g, ' '),
    detail: log.details,
    agent: log.agent_name,
    tone: /error|failed|cancel/i.test(log.action) ? 'red' as const : /complete|delivered/i.test(log.action) ? 'green' as const : 'purple' as const
  }));

  if (loading) {
    return <div className="grid gap-4 md:grid-cols-4"><MetricCard label="Security Score" value="--" detail="Loading" /><MetricCard label="Critical Findings" value="--" detail="Loading" /><MetricCard label="Assets" value="--" detail="Loading" /><MetricCard label="Last Scan" value="--" detail="Loading" /></div>;
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Security Score" value={latestScan ? score : 'No baseline'} detail={latestScan ? `Based on scan ${latestScan.id}` : 'Run a scan to establish posture'} tone={score >= 80 ? 'green' : score >= 50 ? 'amber' : 'red'} />
        <MetricCard label="Critical Findings" value={counts.CRITICAL} detail={`${counts.HIGH} high-priority findings`} tone={counts.CRITICAL ? 'red' : counts.HIGH ? 'amber' : 'green'} />
        <MetricCard label="Assets" value={assets.length} detail="Targets from scan history" tone="blue" />
        <MetricCard label="Last Scan" value={latestScan ? relativeTime(latestScan.created_at) : 'No scans'} detail={latestScan ? targetName(latestScan.target_url) : 'No baseline yet'} tone="purple" />
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <GlassPanel className="p-6 xl:col-span-8">
          <SectionHeader title="Security Posture" description="Latest completed assessment score derived from persisted findings." />
          {latestScan ? (
            <div className="grid gap-8 lg:grid-cols-[220px_1fr] lg:items-center">
              <SecurityScore score={score} />
              <div className="space-y-4">
                <p className="max-w-2xl text-lg text-slate-200">{counts.CRITICAL + counts.HIGH > 0 ? `${counts.CRITICAL + counts.HIGH} high-priority findings require attention.` : 'No high-priority findings are present in the latest completed scan.'}</p>
                <div className="grid gap-3 sm:grid-cols-5">
                  {Object.entries(counts).map(([severity, count]) => (
                    <div key={severity} className="rounded-2xl bg-white/[0.035] p-3">
                      <SeverityBadge severity={severity as keyof typeof counts} />
                      <div className="mt-3 text-2xl font-semibold text-slate-50">{count}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : <EmptyState title="No scans yet" description="Run your first security assessment to establish a baseline." action={<Link className="rounded-2xl bg-violet-500 px-4 py-2.5 text-sm font-semibold text-white shadow-violet" to="/scan">Run First Scan</Link>} />}
        </GlassPanel>

        <Surface className="p-6 xl:col-span-4">
          <SectionHeader title="Threat Summary" description="Current severity distribution." />
          <div className="space-y-3">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((severity) => (
              <div key={severity} className="flex items-center justify-between rounded-2xl bg-white/[0.035] px-4 py-3">
                <SeverityBadge severity={severity} />
                <span className="text-lg font-semibold text-slate-50">{counts[severity]}</span>
              </div>
            ))}
          </div>
        </Surface>
      </section>

      {latestScan ? (
        <GlassPanel className="p-6">
          <SectionHeader
            title="AI Security Analyst"
            description="Final evidence-grounded prioritization from scanner, browser, and active-test artifacts. It cannot start active tests."
            action={<Link to={`/report/${latestScan.id}`} className="text-sm font-semibold text-violet-300 hover:text-violet-200">Open Report</Link>}
          />
          {analyst ? (
            <div className="grid gap-3 md:grid-cols-4">
              <div className="rounded-2xl bg-white/[0.035] p-4">
                <div className="mb-2 flex items-center gap-2 text-sm text-violet-200"><Sparkles className="h-4 w-4" />Posture</div>
                <div className="text-lg font-semibold text-slate-50">{String(analystSummary?.overall_security_posture ?? 'Unknown')}</div>
                <div className="mt-2 text-xs text-slate-500">{analyst.ai_status ?? 'Deterministic analysis available'}</div>
              </div>
              <div className="rounded-2xl bg-white/[0.035] p-4 md:col-span-2">
                <div className="text-sm text-slate-500">Recommended Next Action</div>
                <div className="mt-2 text-sm leading-6 text-slate-200">{String(analystSummary?.recommended_next_action ?? topPriority?.recommended_action ?? 'No analyst recommendation yet.')}</div>
              </div>
              <div className="rounded-2xl bg-white/[0.035] p-4">
                <div className="text-sm text-slate-500">Active Priorities</div>
                <div className="mt-2 text-3xl font-semibold text-slate-50">{analyst.priorities?.length ?? 0}</div>
                <div className="mt-2 text-xs text-slate-500">Active test launch: {analyst.safety?.can_start_active_test === false ? 'disabled' : 'not available'}</div>
              </div>
            </div>
          ) : <EmptyState title="AI analysis pending" description="The next completed scan or report refresh will generate the analyst artifact." />}
        </GlassPanel>
      ) : null}

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Surface className="p-6 xl:col-span-7">
          <SectionHeader title="Recent Findings" description="Latest security issues detected." action={<Link to="/findings" className="text-sm font-semibold text-violet-300 hover:text-violet-200">View All</Link>} />
          {findings.length ? (
            <div className="space-y-2">
              {findings.slice(-6).reverse().map((finding) => (
                <Link key={finding.id} to="/findings" className="grid gap-3 rounded-2xl bg-white/[0.035] p-4 transition hover:bg-white/[0.06] sm:grid-cols-[110px_1fr_auto] sm:items-center">
                  <SeverityBadge severity={finding.severity} />
                  <div className="min-w-0">
                    <div className="truncate font-medium text-slate-100">{finding.title}</div>
                    <div className="truncate text-sm text-slate-500">{targetName(finding.target)}</div>
                  </div>
                  <div className="text-sm text-slate-500">{relativeTime(finding.timestamp)}</div>
                </Link>
              ))}
            </div>
          ) : <EmptyState title="No findings" description="Your latest scan found no actionable issues." />}
        </Surface>

        <Surface className="p-6 xl:col-span-5">
          <SectionHeader title="Agent Activity" description="Backend-derived latest agent state." action={<Link to="/agents" className="text-sm font-semibold text-violet-300 hover:text-violet-200">Open Agents</Link>} />
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-2xl bg-violet-500/10 p-4"><div className="text-sm text-violet-200">Active</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.active}</div></div>
            <div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-400">Waiting</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.waiting}</div></div>
            <div className="rounded-2xl bg-emerald-500/10 p-4"><div className="text-sm text-emerald-200">Complete</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.completed}</div></div>
          </div>
          <div className="mt-4 space-y-2">
            {agents.slice(0, 6).map((agent) => <div key={agent.name} className="flex items-center justify-between rounded-2xl bg-white/[0.035] px-4 py-3 text-sm"><span className="text-slate-200">{agent.name}</span><StatusBadge status={agent.status} /></div>)}
          </div>
        </Surface>
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <Surface className="p-6 xl:col-span-8">
          <SectionHeader title="Scan Activity" description="Recent append-only backend audit events." action={<Link to="/audit-logs" className="text-sm font-semibold text-violet-300 hover:text-violet-200">Audit Logs</Link>} />
          <ActivityTimeline events={timeline} />
        </Surface>
        <GlassPanel className="p-6 xl:col-span-4">
          <SectionHeader title="System Health" description="Truthful backend status." action={<Link to="/system-health" className="text-sm font-semibold text-violet-300 hover:text-violet-200"><ArrowUpRight className="inline h-4 w-4" /></Link>} />
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-2xl bg-white/[0.04] p-4"><span className="text-slate-400">Backend API</span><StatusBadge status={health ? 'Connected' : 'Unavailable'} /></div>
            <div className="flex items-center justify-between rounded-2xl bg-white/[0.04] p-4"><span className="text-slate-400">Database</span><StatusBadge status={health?.database === 'available' ? 'Healthy' : 'Unavailable'} /></div>
            <div className="flex items-center justify-between rounded-2xl bg-white/[0.04] p-4"><span className="text-slate-400">Agents</span><StatusBadge status={health?.agents ?? 'unavailable'} /></div>
            <div className="flex items-center justify-between rounded-2xl bg-white/[0.04] p-4"><span className="text-slate-400">Scheduler</span><StatusBadge status={health?.scheduler ?? 'unavailable'} /></div>
          </div>
          <div className="mt-4 text-xs text-slate-500">Last scan: {latestScan ? formatDateTime(latestScan.created_at) : 'No scans yet'}</div>
        </GlassPanel>
      </section>
    </div>
  );
}
