import { useMemo, useState } from 'react';
import { Drawer, EmptyState, SectionHeader, SecurityScore, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { deriveAssets, formatDateTime, relativeTime } from '../../utils/derived';

type Asset = ReturnType<typeof deriveAssets>[number];

export default function AssetsPage() {
  const { scans, findings, artifactsByScanId } = usePhantomData();
  const assets = useMemo(() => deriveAssets(scans, findings), [scans, findings]);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [tab, setTab] = useState('Overview');
  const technologies = Object.values(artifactsByScanId).flatMap((artifact) => {
    const stack = artifact.scanner_output?.tech_stack;
    if (!stack || typeof stack !== 'object') return [];
    const record = stack as Record<string, unknown>;
    return [record.server, record.x_powered_by, ...(Array.isArray(record.technologies) ? record.technologies : [])].filter((item): item is string => typeof item === 'string' && Boolean(item.trim()));
  });

  return (
    <div className="space-y-6">
      <Surface className="p-6"><SectionHeader title="Assets" description="Monitored targets derived from real scan history and finding records." /></Surface>
      {assets.length ? <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{assets.map((asset) => (
        <button key={asset.name} onClick={() => { setSelected(asset); setTab('Overview'); }} className="rounded-3xl border border-white/[0.06] bg-slate-950/45 p-5 text-left transition hover:border-violet-400/30 hover:bg-white/[0.045]">
          <div className="flex items-start justify-between gap-4"><div><div className="font-mono text-sm text-slate-100">{asset.name}</div><div className="mt-1 text-sm text-slate-500">Last scan {relativeTime(asset.last_scan)}</div></div><StatusBadge status={asset.status} /></div>
          <div className="mt-6 grid grid-cols-3 gap-3"><div><div className="text-xs text-slate-500">Score</div><div className="mt-1 text-2xl font-semibold text-slate-50">{asset.score}</div></div><div><div className="text-xs text-slate-500">Findings</div><div className="mt-1 text-2xl font-semibold text-slate-50">{asset.findings.length}</div></div><div><div className="text-xs text-slate-500">Scans</div><div className="mt-1 text-2xl font-semibold text-slate-50">{asset.scans.length}</div></div></div>
        </button>
      ))}</div> : <EmptyState title="No assets monitored yet." description="Assets appear after real scan history or findings are available." />}
      <Drawer title={selected?.name ?? 'Asset'} open={Boolean(selected)} onClose={() => setSelected(null)}>
        {selected ? <div className="space-y-5">
          <div className="flex flex-wrap gap-2">{['Overview', 'Findings', 'Technologies', 'Endpoints', 'Scans', 'Activity'].map((item) => <button key={item} onClick={() => setTab(item)} className={`rounded-2xl px-3 py-2 text-sm ${tab === item ? 'bg-violet-500/15 text-violet-100' : 'bg-white/[0.04] text-slate-400'}`}>{item}</button>)}</div>
          {tab === 'Overview' ? <div className="grid gap-4 sm:grid-cols-[140px_1fr]"><SecurityScore score={selected.score} size="sm" /><div className="space-y-3"><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Target</div><div className="mt-1 break-all font-mono text-sm text-slate-100">{selected.target_url}</div></div><div className="rounded-2xl bg-white/[0.035] p-4"><div className="text-sm text-slate-500">Last Scan</div><div className="mt-1 text-slate-100">{formatDateTime(selected.last_scan)}</div></div></div></div> : null}
          {tab === 'Findings' ? <div className="space-y-3">{selected.findings.length ? selected.findings.map((finding) => <div key={finding.id} className="rounded-2xl bg-white/[0.035] p-4"><div className="flex items-center gap-3"><SeverityBadge severity={finding.severity} /><div className="font-medium text-slate-100">{finding.title}</div></div><div className="mt-2 text-sm text-slate-500">{finding.category}</div></div>) : <EmptyState title="No findings" description="No findings are associated with this asset." />}</div> : null}
          {tab === 'Technologies' ? <div className="space-y-2">{technologies.length ? Array.from(new Set(technologies)).map((technology) => <div key={technology} className="rounded-2xl bg-white/[0.035] px-4 py-3 font-mono text-sm text-slate-200">{technology}</div>) : <EmptyState title="No technologies" description="Technology data appears when scanner artifacts are persisted." />}</div> : null}
          {tab === 'Endpoints' ? <div className="space-y-2">{Array.from(new Set(selected.findings.map((finding) => finding.endpoint).filter(Boolean))).map((endpoint) => <div key={endpoint} className="rounded-2xl bg-white/[0.035] px-4 py-3 font-mono text-xs text-slate-300">{endpoint}</div>)}</div> : null}
          {tab === 'Scans' ? <div className="space-y-2">{selected.scans.map((scan) => <div key={scan.id} className="flex items-center justify-between rounded-2xl bg-white/[0.035] px-4 py-3"><div><div className="text-sm text-slate-100">Scan {scan.id}</div><div className="text-xs text-slate-500">{formatDateTime(scan.created_at)}</div></div><StatusBadge status={scan.status} /></div>)}</div> : null}
          {tab === 'Activity' ? <div className="rounded-2xl bg-white/[0.035] p-4 text-sm text-slate-400">Activity is represented by scan history and audit logs. Open Audit Logs for append-only records.</div> : null}
        </div> : null}
      </Drawer>
    </div>
  );
}
