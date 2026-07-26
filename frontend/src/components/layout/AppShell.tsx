import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  Bell,
  Bug,
  ChevronLeft,
  ClipboardList,
  Command,
  FileClock,
  FileText,
  HeartPulse,
  History,
  Home,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Sparkles,
  Stethoscope,
  UserCircle,
  Wrench,
  X
} from 'lucide-react';
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';

import { usePhantomData } from '../../hooks/usePhantomData';
import { apiErrorMessage, askPhantomScan } from '../../services/api';
import { deriveAssets, deriveNotifications, deriveTechnologies, latestCompletedScan, relativeTime, targetName } from '../../utils/derived';
import { Button, Drawer, StatusBadge, cx } from '../ui/Primitives';

interface NavItem {
  label: string;
  path: string;
  icon: typeof Home;
  amber?: boolean;
}

const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Overview',
    items: [
      { label: 'Dashboard', path: '/', icon: Home },
      { label: 'Live Scan', path: '/scan', icon: Activity }
    ]
  },
  {
    label: 'Security',
    items: [
      { label: 'Findings', path: '/findings', icon: ShieldAlert },
      { label: 'Assets', path: '/assets', icon: Layers3 },
      { label: 'CVE Intelligence', path: '/cve', icon: Bug },
      { label: 'Remediation', path: '/remediation', icon: Wrench }
    ]
  },
  {
    label: 'Operations',
    items: [
      { label: 'Agents', path: '/agents', icon: Network },
      { label: 'Scan History', path: '/history', icon: History },
      { label: 'Audit Logs', path: '/audit-logs', icon: ClipboardList }
    ]
  },
  {
    label: 'System',
    items: [
      { label: 'Self Audit', path: '/self-audit', icon: Stethoscope },
      { label: 'Notifications', path: '/notifications', icon: Bell },
      { label: 'System Health', path: '/system-health', icon: HeartPulse },
      { label: 'Settings', path: '/settings', icon: Settings }
    ]
  },
  {
    label: 'Authorized',
    items: [{ label: 'Testing Workspace', path: '/authorized-testing', icon: LockKeyhole, amber: true }]
  }
];

const routeDetails: Record<string, { title: string; description: string }> = {
  '/': { title: 'Security Overview', description: 'Monitor posture, findings, and system activity.' },
  '/scan': { title: 'Security Scan', description: 'Assess the current security posture of a target.' },
  '/findings': { title: 'Findings', description: 'Triage vulnerabilities detected by PhantomScan agents.' },
  '/assets': { title: 'Assets', description: 'Review monitored targets derived from scan history.' },
  '/cve': { title: 'CVE Intelligence', description: 'Correlate detected technologies with CVE findings.' },
  '/remediation': { title: 'Remediation', description: 'Prioritize fixes from confirmed security evidence.' },
  '/agents': { title: 'Agents', description: 'Observe live and historical agent operations.' },
  '/history': { title: 'Scan History', description: 'Browse stored assessments and reports.' },
  '/audit-logs': { title: 'Audit Logs', description: 'Append-only operational evidence from scans and agents.' },
  '/self-audit': { title: 'Guardian Self-Audit', description: 'PhantomScan continuously evaluates its own security posture.' },
  '/notifications': { title: 'Notifications', description: 'Events derived from findings, scans, agents, and system activity.' },
  '/system-health': { title: 'System Health', description: 'Verify backend, realtime, database, and agent availability.' },
  '/settings': { title: 'Settings', description: 'Runtime configuration and integration status.' },
  '/authorized-testing': { title: 'Authorized Testing', description: 'Controlled security testing for approved targets.' }
};

function currentRoute(pathname: string) {
  if (pathname.startsWith('/report/')) return { title: 'Security Assessment', description: 'Review completed scan evidence and remediation guidance.' };
  return routeDetails[pathname] ?? routeDetails['/'];
}

function Sidebar({ collapsed, mobileOpen, onCloseMobile, onToggleCollapse }: { collapsed: boolean; mobileOpen: boolean; onCloseMobile: () => void; onToggleCollapse: () => void }) {
  const content = (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between px-4 py-5">
        <Link to="/" className="min-w-0" onClick={onCloseMobile}>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-violet-500/15 ring-1 ring-violet-400/25">
              <Shield className="h-5 w-5 text-violet-200" />
            </div>
            {!collapsed ? (
              <div className="leading-tight">
                <div className="text-sm font-bold tracking-[0.2em] text-slate-50">PHANTOMSCAN</div>
                <div className="text-xs text-slate-500">Guardian Console</div>
              </div>
            ) : null}
          </div>
        </Link>
        <button className="rounded-xl p-2 text-slate-500 hover:bg-white/[0.06] hover:text-slate-200 lg:hidden" onClick={onCloseMobile} aria-label="Close navigation">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto px-3 pb-4">
        {navGroups.map((group) => (
          <div key={group.label}>
            {!collapsed ? <div className={cx('mb-2 px-3 text-[11px] font-semibold uppercase tracking-[0.24em]', group.label === 'Authorized' ? 'text-amber-300/80' : 'text-slate-600')}>{group.label}</div> : null}
            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    onClick={onCloseMobile}
                    className={({ isActive }) =>
                      cx(
                        'group relative flex items-center gap-3 rounded-2xl px-3 py-2.5 text-sm font-medium transition',
                        isActive
                          ? item.amber
                            ? 'bg-amber-500/10 text-amber-100 ring-1 ring-amber-400/20'
                            : 'bg-violet-500/10 text-slate-50 ring-1 ring-violet-400/15'
                          : item.amber
                            ? 'text-amber-200/75 hover:bg-amber-500/[0.07] hover:text-amber-100'
                            : 'text-slate-400 hover:bg-white/[0.05] hover:text-slate-100',
                        collapsed && 'justify-center'
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive ? <span className={cx('absolute left-0 h-5 w-1 rounded-r-full', item.amber ? 'bg-amber-400' : 'bg-violet-400')} /> : null}
                        <Icon className="h-4 w-4 shrink-0" />
                        {!collapsed ? <span className="truncate">{item.label}</span> : null}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="hidden border-t border-white/[0.06] p-3 lg:block">
        <Button variant="ghost" onClick={onToggleCollapse} className="w-full justify-center">
          <ChevronLeft className={cx('h-4 w-4 transition', collapsed && 'rotate-180')} />
          {!collapsed ? 'Collapse' : null}
        </Button>
      </div>
    </div>
  );

  return (
    <>
      <aside className={cx('fixed inset-y-0 left-0 z-30 hidden border-r border-white/[0.06] bg-[#070A12]/80 backdrop-blur-xl transition-all duration-200 lg:block', collapsed ? 'w-[86px]' : 'w-[236px]')}>{content}</aside>
      <AnimatePresence>
        {mobileOpen ? (
          <>
            <motion.div className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm lg:hidden" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onCloseMobile} />
            <motion.aside className="fixed inset-y-0 left-0 z-50 w-[280px] border-r border-white/[0.08] bg-[#070A12] lg:hidden" initial={{ x: -300 }} animate={{ x: 0 }} exit={{ x: -300 }} transition={{ duration: 0.2 }}>
              {content}
            </motion.aside>
          </>
        ) : null}
      </AnimatePresence>
    </>
  );
}

function SystemStatusPopover({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { health, realtimeState, realtimeHealthy } = usePhantomData();
  if (!open) return null;
  const rows = [
    ['Backend API', health ? 'Connected' : 'Unavailable'],
    ['WebSocket', realtimeState === 'open' ? 'Connected' : realtimeState],
    ['Database', health?.database === 'available' ? 'Healthy' : 'Unavailable'],
    ['Agents', health?.agents === 'available' ? 'Available' : 'Unavailable'],
    ['Scheduler', health?.scheduler ?? 'unavailable']
  ];
  return (
    <div className="absolute right-0 top-12 z-30 w-80 rounded-3xl border border-white/[0.08] bg-[#0B1020]/95 p-4 shadow-2xl backdrop-blur-xl">
      <div className="mb-3 flex items-center justify-between">
        <div className="font-semibold text-slate-100">System Status</div>
        <button onClick={onClose} className="rounded-lg p-1 text-slate-500 hover:bg-white/[0.06] hover:text-slate-200"><X className="h-4 w-4" /></button>
      </div>
      <div className="space-y-2">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-center justify-between rounded-2xl bg-white/[0.035] px-3 py-2 text-sm">
            <span className="text-slate-400">{label}</span>
            <StatusBadge status={value} />
          </div>
        ))}
      </div>
      <div className="mt-3 text-xs text-slate-500">Overall state: {realtimeHealthy ? 'Systems Online' : 'Connection Issue'}</div>
    </div>
  );
}

function GlobalSearch() {
  const navigate = useNavigate();
  const { scans, findings, agents, artifactsByScanId } = usePhantomData();
  const [query, setQuery] = useState('');
  const assets = useMemo(() => deriveAssets(scans, findings), [scans, findings]);
  const technologies = useMemo(() => deriveTechnologies(artifactsByScanId), [artifactsByScanId]);
  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    return [
      ...findings.filter((item) => `${item.title} ${item.category} ${item.target} ${item.cve_id ?? ''}`.toLowerCase().includes(needle)).slice(0, 4).map((finding) => ({ label: finding.title, detail: finding.target, path: '/findings', icon: ShieldAlert })),
      ...assets.filter((asset) => `${asset.name} ${asset.target_url}`.toLowerCase().includes(needle)).slice(0, 3).map((asset) => ({ label: asset.name, detail: `${asset.findings.length} findings`, path: '/assets', icon: Layers3 })),
      ...scans.filter((scan) => `${scan.target_url} ${scan.mode} ${scan.status}`.toLowerCase().includes(needle)).slice(0, 3).map((scan) => ({ label: targetName(scan.target_url), detail: `Scan ${scan.id} · ${scan.status}`, path: `/report/${scan.id}`, icon: FileText })),
      ...technologies.filter((tech) => tech.name.toLowerCase().includes(needle)).slice(0, 3).map((tech) => ({ label: tech.name, detail: 'Detected technology', path: '/cve', icon: Bug })),
      ...agents.filter((agent) => agent.name.toLowerCase().includes(needle)).slice(0, 3).map((agent) => ({ label: agent.name, detail: agent.status, path: '/agents', icon: Network }))
    ];
  }, [agents, assets, findings, query, scans, technologies]);

  return (
    <div className="relative hidden w-[min(420px,32vw)] md:block">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
      <input
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Search PhantomScan..."
        className="h-11 w-full rounded-2xl border border-white/[0.08] bg-white/[0.04] pl-10 pr-4 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-violet-400/50 focus:bg-white/[0.07]"
      />
      {query ? (
        <div className="absolute right-0 top-13 z-30 w-full overflow-hidden rounded-3xl border border-white/[0.08] bg-[#0B1020]/95 p-2 shadow-2xl backdrop-blur-xl">
          {results.length ? results.map((result) => {
            const Icon = result.icon;
            return (
              <button key={`${result.path}-${result.label}-${result.detail}`} onClick={() => { navigate(result.path); setQuery(''); }} className="flex w-full items-center gap-3 rounded-2xl px-3 py-2.5 text-left hover:bg-white/[0.06]">
                <Icon className="h-4 w-4 text-violet-300" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-slate-100">{result.label}</span>
                  <span className="block truncate text-xs text-slate-500">{result.detail}</span>
                </span>
              </button>
            );
          }) : <div className="px-4 py-6 text-center text-sm text-slate-500">No matching records.</div>}
        </div>
      ) : null}
    </div>
  );
}

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { scans } = usePhantomData();
  const [query, setQuery] = useState('');
  const lastScan = scans[0];
  const actions = [
    { label: 'Open Dashboard', path: '/', icon: Home },
    { label: 'Start Defend Scan', path: '/scan', icon: Activity },
    { label: 'Open Findings', path: '/findings', icon: ShieldAlert },
    { label: 'Open Agents', path: '/agents', icon: Network },
    { label: 'Open Self Audit', path: '/self-audit', icon: Stethoscope },
    { label: 'Search Asset', path: '/assets', icon: Layers3 },
    { label: 'View Last Scan', path: lastScan ? `/report/${lastScan.id}` : '/history', icon: FileClock },
    { label: 'Open Authorized Testing', path: '/authorized-testing', icon: LockKeyhole }
  ];
  const filtered = actions.filter((action) => action.label.toLowerCase().includes(query.toLowerCase()));
  return (
    <AnimatePresence>
      {open ? (
        <motion.div className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/70 px-4 pt-[12vh] backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
          <motion.div className="w-full max-w-2xl overflow-hidden rounded-[2rem] border border-white/[0.08] bg-[#0B1020]/95 shadow-2xl" initial={{ y: 20, scale: 0.98 }} animate={{ y: 0, scale: 1 }} exit={{ y: 20, scale: 0.98 }} transition={{ duration: 0.18 }} onClick={(event) => event.stopPropagation()}>
            <div className="flex items-center gap-3 border-b border-white/[0.06] px-5 py-4">
              <Command className="h-5 w-5 text-violet-300" />
              <input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Open a safe PhantomScan action..." className="flex-1 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-600" />
            </div>
            <div className="max-h-[420px] overflow-y-auto p-2">
              {filtered.map((action) => {
                const Icon = action.icon;
                return (
                  <button key={action.label} onClick={() => { navigate(action.path); onClose(); }} className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left hover:bg-white/[0.06]">
                    <Icon className="h-4 w-4 text-violet-300" />
                    <span className="text-sm font-medium text-slate-100">{action.label}</span>
                  </button>
                );
              })}
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

function NotificationDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { findings, logs } = usePhantomData();
  const notices = useMemo(() => deriveNotifications(findings, logs), [findings, logs]);
  return (
    <Drawer title="Notifications" open={open} onClose={onClose}>
      <div className="space-y-3">
        {notices.length ? notices.map((notice) => (
          <div key={notice.id} className="rounded-2xl border border-white/[0.06] bg-white/[0.035] p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{notice.type}</div>
              <div className="text-xs text-slate-500">{relativeTime(notice.timestamp)}</div>
            </div>
            <div className="mt-2 font-medium text-slate-100">{notice.title}</div>
            <div className="mt-1 line-clamp-2 text-sm text-slate-400">{notice.detail}</div>
          </div>
        )) : <div className="rounded-2xl border border-white/[0.06] bg-white/[0.035] p-6 text-sm text-slate-500">No notifications have been derived from backend activity yet.</div>}
      </div>
    </Drawer>
  );
}

function AskPhantomScanDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { scans, artifactsByScanId } = usePhantomData();
  const latestScan = latestCompletedScan(scans);
  const prompts = latestScan ? artifactsByScanId[latestScan.id]?.ai_analyst_output?.suggested_prompts ?? [] : [];
  const [question, setQuestion] = useState('What should I fix first?');
  const [answer, setAnswer] = useState<string | null>(null);
  const [citations, setCitations] = useState<Array<{ label?: string; title?: string; endpoint?: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!latestScan || !question.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const response = await askPhantomScan(latestScan.id, question.trim());
      setAnswer(response.answer);
      setCitations(response.citations.map((item) => ({ label: item.label, title: item.title, endpoint: item.endpoint })));
    } catch (err) {
      setError(apiErrorMessage(err, 'Ask PhantomScan could not answer from current evidence.'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Drawer title="Ask PhantomScan" open={open} onClose={onClose}>
      {latestScan ? (
        <div className="space-y-5">
          <div className="rounded-2xl bg-white/[0.035] p-4 text-sm text-slate-400">Answers are grounded in scan {latestScan.id} for {targetName(latestScan.target_url)}. This assistant cannot start active tests.</div>
          <form onSubmit={submit} className="space-y-3">
            <textarea value={question} onChange={(event) => setQuestion(event.target.value)} className="min-h-28 w-full rounded-2xl border border-white/[0.08] bg-slate-950/60 p-4 text-sm text-slate-100 outline-none placeholder:text-slate-600" placeholder="Ask about priorities, score, authentication, APIs, changes, or remediation..." />
            <Button type="submit" disabled={loading || !question.trim()}>{loading ? 'Thinking...' : 'Ask'}</Button>
          </form>
          {prompts.length ? <div className="space-y-2"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">Suggested Prompts</div><div className="flex flex-wrap gap-2">{prompts.slice(0, 8).map((prompt) => <button key={prompt} onClick={() => setQuestion(prompt)} className="rounded-2xl bg-white/[0.04] px-3 py-2 text-xs text-slate-300 hover:bg-white/[0.08]">{prompt}</button>)}</div></div> : null}
          {error ? <div className="rounded-2xl border border-red-400/20 bg-red-500/[0.06] p-4 text-sm text-red-100/80">{error}</div> : null}
          {answer ? <div className="rounded-2xl bg-violet-500/[0.08] p-4 text-sm leading-6 text-violet-50/90">{answer}</div> : null}
          {citations.length ? <div className="space-y-2"><div className="text-xs uppercase tracking-[0.18em] text-slate-600">Citations</div>{citations.map((citation, index) => <div key={`${citation.label}-${index}`} className="rounded-2xl bg-white/[0.035] p-3 text-sm text-slate-400"><div className="font-medium text-slate-200">{citation.label ?? `Citation ${index + 1}`}</div><div>{citation.title}</div><div className="break-all font-mono text-xs text-slate-500">{citation.endpoint}</div></div>)}</div> : null}
        </div>
      ) : <div className="rounded-2xl border border-white/[0.06] bg-white/[0.035] p-6 text-sm text-slate-500">Run a scan before asking evidence-grounded questions.</div>}
    </Drawer>
  );
}

export default function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { health, realtimeHealthy, realtimeState, refresh, refreshing } = usePhantomData();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('phantomscan:sidebar') === 'collapsed');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [askOpen, setAskOpen] = useState(false);
  const details = currentRoute(location.pathname);

  useEffect(() => {
    localStorage.setItem('phantomscan:sidebar', collapsed ? 'collapsed' : 'expanded');
  }, [collapsed]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen(true);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="min-h-screen bg-app text-slate-100">
      <div className="pointer-events-none fixed inset-0 bg-grid opacity-80" />
      <div className="pointer-events-none fixed left-1/3 top-0 h-96 w-96 rounded-full bg-violet-500/15 blur-3xl" />
      {location.pathname.startsWith('/authorized-testing') ? <div className="pointer-events-none fixed right-0 top-1/3 h-96 w-96 rounded-full bg-amber-500/10 blur-3xl" /> : null}
      <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} onToggleCollapse={() => setCollapsed((value) => !value)} />
      <div className={cx('relative min-h-screen transition-all duration-200', collapsed ? 'lg:pl-[86px]' : 'lg:pl-[236px]')}>
        <header className="sticky top-0 z-20 border-b border-white/[0.06] bg-[#070A12]/70 backdrop-blur-xl">
          <div className="mx-auto flex h-[76px] max-w-[1600px] items-center gap-4 px-4 sm:px-6 lg:px-8">
            <button className="rounded-2xl border border-white/[0.08] bg-white/[0.04] p-2.5 text-slate-300 lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open navigation">
              <Menu className="h-5 w-5" />
            </button>
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-xl font-semibold tracking-tight text-slate-50">{details.title}</h1>
              <p className="mt-0.5 hidden truncate text-sm text-slate-500 sm:block">{details.description}</p>
            </div>
            <GlobalSearch />
            <Button variant="ghost" onClick={() => setCommandOpen(true)} className="hidden px-3 md:inline-flex"><Command className="h-4 w-4" />K</Button>
            <Button variant="ghost" onClick={() => setAskOpen(true)} className="px-3"><Sparkles className="h-4 w-4" /><span className="hidden sm:inline">Ask</span></Button>
            <Button variant="ghost" onClick={() => setNotificationsOpen(true)} className="h-11 w-11 p-0" aria-label="Notifications"><Bell className="h-4 w-4" /></Button>
            <div className="relative">
              <button onClick={() => setStatusOpen((value) => !value)} className="flex items-center gap-2 rounded-2xl border border-white/[0.08] bg-white/[0.04] px-3 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-white/[0.08]">
                <span className={cx('h-2.5 w-2.5 rounded-full', realtimeHealthy ? 'bg-emerald-400' : 'bg-amber-400')} />
                <span className="hidden sm:inline">{realtimeHealthy ? 'Systems Online' : 'Connection Issue'}</span>
              </button>
              <SystemStatusPopover open={statusOpen} onClose={() => setStatusOpen(false)} />
            </div>
            <Button variant="ghost" onClick={() => void refresh()} className="hidden px-3 xl:inline-flex" disabled={refreshing}>
              <Sparkles className={cx('h-4 w-4', refreshing && 'animate-spin')} />
              Refresh
            </Button>
            <div className="hidden h-11 items-center gap-2 rounded-2xl border border-white/[0.08] bg-white/[0.04] px-3 md:flex">
              <UserCircle className="h-5 w-5 text-slate-500" />
              <span className="text-sm text-slate-300">Local</span>
            </div>
          </div>
        </header>
        <main className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          {health?.status === 'degraded' || realtimeState === 'error' ? (
            <div className="mb-6 rounded-3xl border border-amber-400/20 bg-amber-500/[0.06] px-5 py-4 text-sm text-amber-100/80">
              Backend telemetry is degraded. Visible status and metrics are based on the latest reachable data.
            </div>
          ) : null}
          {children}
        </main>
      </div>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />
      <NotificationDrawer open={notificationsOpen} onClose={() => setNotificationsOpen(false)} />
      <AskPhantomScanDrawer open={askOpen} onClose={() => setAskOpen(false)} />
    </div>
  );
}
