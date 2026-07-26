import { SectionHeader, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';

export default function SettingsPage() {
  const { health } = usePhantomData();
  const env = ['VITE_API_BASE_URL', 'VITE_WS_BASE_URL', 'DATABASE_URL', 'ACTIVE_TARGET_ALLOWLIST', 'MAX_SCAN_DURATION', 'MAX_REQUESTS_PER_SECOND', 'MAX_TOTAL_REQUESTS', 'MAX_CONCURRENT_SCANS', 'MAX_REDIRECT_DEPTH', 'MAX_RESPONSE_SIZE', 'BROWSER_PAGE_LIMIT', 'NVD_API_KEY', 'OPENROUTER_API_KEY', 'OPENROUTER_MODEL', 'PHANTOMSCAN_WEBHOOK_URL'];
  return <div className="space-y-6"><Surface className="p-6"><SectionHeader title="Settings" description="Read-only runtime status and supported integration variables." /><div className="grid gap-3 md:grid-cols-3">{[['API', health ? 'Connected' : 'Unavailable'], ['Database', health?.database ?? 'unavailable'], ['Agents', health?.agents ?? 'unavailable']].map(([label, value]) => <div key={label} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">{label}</div><div className="mt-3"><StatusBadge status={value} /></div></div>)}</div></Surface><Surface className="p-6"><SectionHeader title="Configuration Inputs" description="These names are consumed by the existing backend/frontend code. Values are not exposed." /><div className="grid gap-2 md:grid-cols-2">{env.map((name) => <div key={name} className="rounded-2xl bg-white/[0.035] px-4 py-3 font-mono text-sm text-slate-300">{name}</div>)}</div></Surface></div>;
}
