import { usePhantomData } from '../../hooks/usePhantomData';
import { Button, SectionHeader, StatusBadge, Surface } from '../../components/ui/Primitives';

export default function SystemHealthPage() {
  const { health, realtimeState, realtimeHealthy, refresh, refreshing } = usePhantomData();
  const rows = [['Backend API', health ? 'Connected' : 'Unavailable'], ['WebSocket', realtimeState], ['Database', health?.database ?? 'unavailable'], ['Agents', health?.agents ?? 'unavailable'], ['Scheduler', health?.scheduler ?? 'unavailable']];

  const aiRows: [string, string][] = [];
  if (health) {
    aiRows.push(['AI Provider', health.ai_provider]);
    aiRows.push(['AI Model', health.ai_model]);
    aiRows.push(['AI Status', health.ai_status === 'connected' ? 'Connected' : 'Offline']);
  }

  return <div className="space-y-6">
    <Surface className="p-6">
      <SectionHeader title="System Health" description="Truthful connectivity state from REST health and realtime status." action={<Button onClick={() => void refresh()} disabled={refreshing}>{refreshing ? 'Refreshing' : 'Refresh'}</Button>} />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {rows.map(([label, value]) => <div key={label} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">{label}</div><div className="mt-3"><StatusBadge status={value} /></div></div>)}
      </div>
    </Surface>
    <Surface className="p-6">
      <SectionHeader title="AI Integration" description="AI analysis is powered by OpenRouter with configurable models." />
      <div className="grid gap-3 md:grid-cols-3">
        {aiRows.map(([label, value]) => <div key={label} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">{label}</div><div className="mt-3"><StatusBadge status={value} /></div></div>)}
      </div>
    </Surface>
    <Surface className="p-6">
      <SectionHeader title="Availability" description="Systems Online requires backend health and realtime connection to be healthy." />
      <div className="text-3xl font-semibold text-slate-50">{realtimeHealthy ? 'Systems Online' : 'Connection Issue'}</div>
      <p className="mt-2 text-sm text-slate-500">PhantomScan never displays a green system state unless both REST and WebSocket health are available.</p>
    </Surface>
  </div>;
}
