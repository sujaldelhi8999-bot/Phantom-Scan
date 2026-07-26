import { SectionHeader, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { deriveNotifications, relativeTime } from '../../utils/derived';

export default function NotificationsPage() {
  const { findings, logs } = usePhantomData();
  const notices = deriveNotifications(findings, logs);
  return <Surface className="p-6"><SectionHeader title="Notifications" description="Notification state derived from backend findings and audit logs." />{notices.length ? <div className="grid gap-3 md:grid-cols-2">{notices.map((notice) => <div key={notice.id} className="rounded-2xl border border-white/[0.06] bg-white/[0.035] p-4"><div className="flex items-center justify-between"><div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-600">{notice.type}</div><div className="text-xs text-slate-500">{relativeTime(notice.timestamp)}</div></div><div className="mt-2 font-medium text-slate-100">{notice.title}</div><div className="mt-1 text-sm text-slate-400">{notice.detail}</div></div>)}</div> : <div className="text-sm text-slate-500">No notifications have been derived from backend activity yet.</div>}</Surface>;
}
