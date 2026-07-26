import { useMemo, useState } from 'react';
import { AgentRow, Drawer, EmptyState, SectionHeader, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AgentStatus } from '../../types';
import { agentSummary, formatDateTime } from '../../utils/derived';

export default function AgentsPage() {
  const { agents, logs } = usePhantomData();
  const [selected, setSelected] = useState<AgentStatus | null>(null);
  const summary = agentSummary(agents);
  const selectedLogs = useMemo(() => selected ? logs.filter((log) => log.agent_name === selected.name).slice(-20).reverse() : [], [logs, selected]);
  return (
    <div className="space-y-6">
      <Surface className="p-6"><SectionHeader title="Agent Operations" description="Backend-derived state from live jobs and persisted audit logs." /><div className="grid gap-3 sm:grid-cols-4"><div className="rounded-2xl bg-violet-500/10 p-4"><div className="text-sm text-violet-200">Active</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.active}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-400">Waiting</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.waiting}</div></div><div className="rounded-2xl bg-emerald-500/10 p-4"><div className="text-sm text-emerald-200">Completed</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.completed}</div></div><div className="rounded-2xl bg-red-500/10 p-4"><div className="text-sm text-red-200">Failed</div><div className="mt-2 text-2xl font-semibold text-slate-50">{summary.failed}</div></div></div></Surface>
      <Surface className="p-4">{agents.length ? <div className="grid gap-1 md:grid-cols-2 xl:grid-cols-3">{agents.map((agent) => <AgentRow key={agent.name} agent={agent} onClick={() => setSelected(agent)} />)}</div> : <EmptyState title="No agent data" description="Agent status appears after the backend responds." />}</Surface>
      <Drawer title={selected?.name ?? 'Agent'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? <div className="space-y-5"><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Status</div><div className="mt-2"><StatusBadge status={selected.status} /></div></div><section><h3 className="mb-3 font-semibold text-slate-100">Activity</h3>{selectedLogs.length ? <div className="space-y-2">{selectedLogs.map((log) => <div key={log.id} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex items-center justify-between gap-3"><div className="font-medium text-slate-100">{log.action.replace(/_/g, ' ')}</div><div className="text-xs text-slate-500">{formatDateTime(log.timestamp)}</div></div><div className="mt-2 text-sm text-slate-400">{log.details}</div></div>)}</div> : <EmptyState title="No activity" description="No persisted audit entries exist for this agent yet." />}</section></div> : null}
      </Drawer>
    </div>
  );
}
