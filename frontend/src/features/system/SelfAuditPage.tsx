import { Link } from 'react-router-dom';
import { EmptyState, MetricCard, SectionHeader, SecurityScore, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { countBySeverity, formatDateTime, securityScore } from '../../utils/derived';

const categories = ['API', 'Dependencies', 'Secrets', 'Docker', 'Authentication', 'Database', 'Headers', 'TLS', 'Configuration'];

export default function SelfAuditPage() {
  const { selfAudit, findings } = usePhantomData();
  const auditFindings = selfAudit?.scan_id ? findings.filter((finding) => finding.scan_id === selfAudit.scan_id) : [];
  const counts = countBySeverity(auditFindings);
  const score = securityScore(auditFindings);
  return (
    <div className="space-y-6"><Surface className="p-6"><SectionHeader title="Guardian Self-Audit" description="PhantomScan continuously evaluates its own security posture." /></Surface>{selfAudit && selfAudit.status !== 'never_run' ? <><div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5"><MetricCard label="System Health" value={`${score} / 100`} detail="Derived from self-audit findings" tone={score >= 80 ? 'green' : 'amber'} /><MetricCard label="Last Audit" value={formatDateTime(selfAudit.completed_at ?? selfAudit.created_at)} detail={`Scan ${selfAudit.scan_id}`} /><MetricCard label="Critical" value={counts.CRITICAL} tone={counts.CRITICAL ? 'red' : 'green'} /><MetricCard label="High" value={counts.HIGH} tone={counts.HIGH ? 'amber' : 'green'} /><MetricCard label="Medium" value={counts.MEDIUM} tone={counts.MEDIUM ? 'amber' : 'green'} /></div><Surface className="p-6"><div className="grid gap-8 lg:grid-cols-[220px_1fr]"><SecurityScore score={score} /><div><SectionHeader title="Self-Audit Categories" description="Status is derived from finding categories where available." /><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{categories.map((category) => { const affected = auditFindings.some((finding) => finding.category.toLowerCase().includes(category.toLowerCase())); return <div key={category} className="flex items-center justify-between rounded-2xl bg-white/[0.035] p-4"><span className="text-sm text-slate-200">{category}</span><StatusBadge status={affected ? 'Attention Required' : 'Healthy'} /></div>; })}</div></div></div></Surface><Surface className="p-6"><SectionHeader title="Self-Audit Findings" description="Findings persisted by the latest self-audit scan." />{auditFindings.length ? <div className="space-y-3">{auditFindings.map((finding) => <div key={finding.id} className="rounded-2xl bg-white/[0.035] p-4"><div className="font-medium text-slate-100">{finding.title}</div><div className="mt-2 text-sm text-slate-500">{finding.category}</div></div>)}</div> : <EmptyState title="No self-audit findings" description="The latest self-audit found no actionable issues." />}</Surface></> : <EmptyState title="Self-audit has not run yet" description="The backend schedules self-audit daily at 02:00 UTC." action={<Link className="rounded-2xl bg-violet-500 px-4 py-2.5 text-sm font-semibold text-white" to="/system-health">View System Health</Link>} />}</div>
  );
}
