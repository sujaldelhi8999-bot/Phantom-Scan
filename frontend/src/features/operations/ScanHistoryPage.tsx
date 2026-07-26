import { Link } from 'react-router-dom';
import { EmptyState, ModeBadge, SectionHeader, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { countBySeverity, formatDateTime, scanDuration, targetName } from '../../utils/derived';

export default function ScanHistoryPage() {
  const { scans, findings } = usePhantomData();
  return (
    <Surface className="overflow-hidden">
      <div className="p-6"><SectionHeader title="Scan History" description="Stored assessments from SQLite persistence." /></div>
      {scans.length ? <div className="hidden md:block"><div className="grid grid-cols-[1.3fr_110px_150px_130px_120px_120px] gap-4 border-y border-white/[0.06] px-5 py-3 text-xs uppercase tracking-[0.18em] text-slate-600"><span>Target</span><span>Mode</span><span>Started</span><span>Duration</span><span>Findings</span><span>Status</span></div>{scans.map((scan) => { const scanFindings = findings.filter((finding) => finding.scan_id === scan.id); const counts = countBySeverity(scanFindings); return <Link key={scan.id} to={`/report/${scan.id}`} className="grid grid-cols-[1.3fr_110px_150px_130px_120px_120px] gap-4 border-b border-white/[0.04] px-5 py-4 last:border-b-0 hover:bg-white/[0.04]"><span className="truncate font-mono text-sm text-slate-100">{targetName(scan.target_url)}</span><ModeBadge mode={scan.mode} /><span className="text-sm text-slate-400">{formatDateTime(scan.created_at)}</span><span className="text-sm text-slate-400">{scanDuration(scan)}</span><span className="text-sm text-slate-400">{scanFindings.length} ({counts.CRITICAL}/{counts.HIGH})</span><StatusBadge status={scan.status} /></Link>; })}</div> : <div className="p-6"><EmptyState title="No scans yet" description="Run your first security assessment to establish a baseline." action={<Link className="rounded-2xl bg-violet-500 px-4 py-2.5 text-sm font-semibold text-white" to="/scan">Run First Scan</Link>} /></div>}
    </Surface>
  );
}
