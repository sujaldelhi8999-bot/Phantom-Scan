import { useState } from 'react';
import { Drawer, EmptyState, SectionHeader, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import type { AuditLog } from '../../types';
import { formatDateTime, targetName } from '../../utils/derived';

export default function AuditLogsPage() {
  const { logs } = usePhantomData();
  const [selected, setSelected] = useState<AuditLog | null>(null);
  return (
    <div className="space-y-6"><Surface className="p-6"><SectionHeader title="Audit Logs" description="Append-only records for scans, agents, authorization, and system events." /></Surface><Surface className="overflow-hidden">{logs.length ? <div className="hidden md:block"><div className="grid grid-cols-[160px_180px_1fr_170px_120px_1fr] gap-4 border-b border-white/[0.06] px-5 py-3 text-xs uppercase tracking-[0.18em] text-slate-600"><span>Time</span><span>User</span><span>Target</span><span>Action</span><span>Mode</span><span>Result</span></div>{logs.slice().reverse().map((log) => <button key={log.id} onClick={() => setSelected(log)} className="grid w-full grid-cols-[160px_180px_1fr_170px_120px_1fr] gap-4 border-b border-white/[0.04] px-5 py-4 text-left last:border-b-0 hover:bg-white/[0.04]"><span className="text-sm text-slate-400">{formatDateTime(log.timestamp)}</span><span className="truncate text-sm text-slate-400">{log.user_id ?? 'local-user'}</span><span className="truncate font-mono text-sm text-slate-300">{log.target ? targetName(log.target) : `Scan ${log.scan_id}`}</span><span className="truncate text-sm text-slate-100">{log.action.replace(/_/g, ' ')}</span><span className="text-sm text-slate-500">{log.authorization_status ?? 'System'}</span><span className="truncate text-sm text-slate-400">{log.result ?? log.details}</span></button>)}</div> : <div className="p-6"><EmptyState title="No audit logs" description="Backend audit rows appear here after scans or system events." /></div>}</Surface><Drawer title="Audit Record" open={Boolean(selected)} onClose={() => setSelected(null)}>{selected ? <div className="space-y-3">{Object.entries(selected).map(([key, value]) => <div key={key} className="rounded-2xl bg-white/[0.035] p-4"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">{key.replace(/_/g, ' ')}</div><div className="mt-2 break-words text-sm text-slate-200">{value ?? 'Not set'}</div></div>)}</div> : null}</Drawer></div>
  );
}
