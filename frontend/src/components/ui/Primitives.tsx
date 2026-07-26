import { AnimatePresence, motion } from 'framer-motion';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Info,
  Loader2,
  ShieldCheck,
  X,
  XCircle
} from 'lucide-react';

import type { AgentState, ScanStatus, Severity, TimelineEvent } from '../../types';
import { scoreLabel } from '../../utils/derived';

export function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(' ');
}

export function GlassPanel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={cx('glass-panel', className)}>{children}</div>;
}

export function Surface({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={cx('rounded-3xl border border-white/[0.06] bg-slate-950/45 shadow-soft', className)}>{children}</div>;
}

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'amber';

export function Button({
  children,
  variant = 'secondary',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      {...props}
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-2xl px-4 py-2.5 text-sm font-semibold transition duration-200 focus:outline-none focus:ring-2 focus:ring-violet-400/70 disabled:cursor-not-allowed disabled:opacity-50',
        variant === 'primary' && 'bg-violet-500 text-white shadow-violet hover:bg-violet-400',
        variant === 'secondary' && 'border border-white/[0.08] bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]',
        variant === 'ghost' && 'text-slate-300 hover:bg-white/[0.06] hover:text-white',
        variant === 'danger' && 'bg-red-500/15 text-red-200 ring-1 ring-red-400/25 hover:bg-red-500/25',
        variant === 'amber' && 'bg-amber-500/15 text-amber-100 ring-1 ring-amber-400/30 hover:bg-amber-500/25',
        className
      )}
    >
      {children}
    </button>
  );
}

export function SectionHeader({
  title,
  description,
  action
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h2 className="text-lg font-semibold text-slate-50">{title}</h2>
        {description ? <p className="mt-1 text-sm text-slate-400">{description}</p> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function MetricCard({ label, value, detail, tone = 'purple' }: { label: string; value: ReactNode; detail?: string; tone?: 'purple' | 'green' | 'amber' | 'red' | 'blue' }) {
  const toneClass = {
    purple: 'from-violet-400/20 to-violet-500/5 text-violet-200',
    green: 'from-emerald-400/20 to-emerald-500/5 text-emerald-200',
    amber: 'from-amber-400/20 to-amber-500/5 text-amber-200',
    red: 'from-red-400/20 to-red-500/5 text-red-200',
    blue: 'from-sky-400/20 to-sky-500/5 text-sky-200'
  }[tone];
  return (
    <Surface className="overflow-hidden p-5">
      <div className={cx('mb-5 h-1.5 w-16 rounded-full bg-gradient-to-r', toneClass)} />
      <div className="text-sm text-slate-400">{label}</div>
      <div className="mt-2 text-3xl font-semibold tracking-tight text-slate-50">{value}</div>
      {detail ? <div className="mt-2 text-sm text-slate-500">{detail}</div> : null}
    </Surface>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const classes: Record<Severity, string> = {
    CRITICAL: 'bg-red-500/15 text-red-200 ring-red-400/30',
    HIGH: 'bg-orange-500/15 text-orange-200 ring-orange-400/30',
    MEDIUM: 'bg-amber-500/15 text-amber-200 ring-amber-400/30',
    LOW: 'bg-violet-500/15 text-violet-200 ring-violet-400/30',
    INFO: 'bg-sky-500/15 text-sky-200 ring-sky-400/30'
  };
  return <span className={cx('inline-flex rounded-full px-2.5 py-1 text-xs font-bold ring-1', classes[severity])}>{severity}</span>;
}

export function StatusBadge({ status }: { status: ScanStatus | AgentState | string }) {
  const normalized = status.toLowerCase();
  const classes = normalized.includes('complete') || normalized.includes('verified') || normalized.includes('healthy')
    ? 'bg-emerald-500/12 text-emerald-200 ring-emerald-400/25'
    : normalized.includes('running') || normalized.includes('active') || normalized.includes('queued') || normalized.includes('progress')
      ? 'bg-violet-500/12 text-violet-200 ring-violet-400/25'
      : normalized.includes('cancel') || normalized.includes('error') || normalized.includes('critical') || normalized.includes('failed')
        ? 'bg-red-500/12 text-red-200 ring-red-400/25'
        : normalized.includes('pending') || normalized.includes('attention') || normalized.includes('degraded')
          ? 'bg-amber-500/12 text-amber-200 ring-amber-400/25'
          : 'bg-slate-500/12 text-slate-300 ring-white/10';
  return <span className={cx('inline-flex rounded-full px-2.5 py-1 text-xs font-semibold capitalize ring-1', classes)}>{status.replace(/_/g, ' ')}</span>;
}

export function ModeBadge({ mode }: { mode: 'defend' | 'pentest' }) {
  return (
    <span
      className={cx(
        'inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ring-1',
        mode === 'defend' ? 'bg-violet-500/12 text-violet-200 ring-violet-400/25' : 'bg-amber-500/12 text-amber-200 ring-amber-400/30'
      )}
    >
      {mode === 'defend' ? 'Defend' : 'Authorized Testing'}
    </span>
  );
}

export function SecurityScore({ score, size = 'lg' }: { score: number; size?: 'sm' | 'lg' }) {
  const color = score >= 90 ? '#22C55E' : score >= 70 ? '#8B5CF6' : score >= 50 ? '#F59E0B' : '#EF4444';
  const radius = size === 'lg' ? 64 : 38;
  const stroke = size === 'lg' ? 12 : 8;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const dimension = size === 'lg' ? 160 : 100;
  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className="relative" style={{ width: dimension, height: dimension }}>
        <svg viewBox={`0 0 ${dimension} ${dimension}`} className="-rotate-90">
          <circle cx={dimension / 2} cy={dimension / 2} r={radius} stroke="rgba(255,255,255,0.08)" strokeWidth={stroke} fill="none" />
          <circle
            cx={dimension / 2}
            cy={dimension / 2}
            r={radius}
            stroke={color}
            strokeWidth={stroke}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className={cx('font-semibold text-slate-50', size === 'lg' ? 'text-5xl' : 'text-3xl')}>{score}</div>
          <div className="text-xs uppercase tracking-[0.24em] text-slate-500">Score</div>
        </div>
      </div>
      <div className="text-sm font-semibold text-slate-200">{scoreLabel(score)}</div>
    </div>
  );
}

export function ProgressBar({ value, amber = false }: { value: number; amber?: boolean }) {
  return (
    <div className="h-2.5 overflow-hidden rounded-full bg-white/[0.06]">
      <motion.div
        className={cx('h-full rounded-full', amber ? 'bg-amber-400' : 'bg-violet-400')}
        initial={false}
        animate={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        transition={{ duration: 0.2 }}
      />
    </div>
  );
}

export function AgentRow({ agent, onClick }: { agent: { name: string; status: AgentState }; onClick?: () => void }) {
  const Icon = agent.status === 'complete' ? CheckCircle2 : agent.status === 'error' ? XCircle : agent.status === 'active' ? Loader2 : Circle;
  return (
    <button onClick={onClick} className="flex w-full items-center gap-3 rounded-2xl px-3 py-3 text-left transition hover:bg-white/[0.04]">
      <Icon className={cx('h-4 w-4', agent.status === 'active' && 'animate-spin text-violet-300', agent.status === 'complete' && 'text-emerald-300', agent.status === 'error' && 'text-red-300', agent.status === 'idle' && 'text-slate-500')} />
      <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{agent.name}</span>
      <StatusBadge status={agent.status} />
    </button>
  );
}

export function ActivityTimeline({ events }: { events: TimelineEvent[] }) {
  if (!events.length) return <EmptyState title="No activity yet" description="Realtime scan activity appears here when an assessment starts." />;
  return (
    <div className="space-y-3">
      <AnimatePresence initial={false}>
        {events.slice(-80).map((event) => (
          <motion.div
            key={event.id}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="grid grid-cols-[70px_1fr] gap-4 rounded-2xl border border-white/[0.05] bg-slate-950/35 p-3"
          >
            <div className="font-mono text-xs text-slate-500">{event.timestamp}</div>
            <div>
              <div className="text-sm font-medium capitalize text-slate-100">{event.title}</div>
              {event.detail ? <div className="mt-1 line-clamp-2 text-sm text-slate-400">{event.detail}</div> : null}
              {event.agent ? <div className="mt-2 text-xs text-slate-600">{event.agent}</div> : null}
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="flex min-h-[180px] flex-col items-center justify-center rounded-3xl border border-dashed border-white/[0.08] bg-white/[0.025] p-8 text-center">
      <ShieldCheck className="mb-4 h-8 w-8 text-slate-500" />
      <h3 className="text-base font-semibold text-slate-100">{title}</h3>
      <p className="mt-2 max-w-md text-sm text-slate-500">{description}</p>
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ title, description, detail, action }: { title: string; description: string; detail?: string; action?: ReactNode }) {
  return (
    <div className="rounded-3xl border border-red-400/20 bg-red-500/[0.06] p-6">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 text-red-300" />
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold text-red-100">{title}</h3>
          <p className="mt-1 text-sm text-red-100/70">{description}</p>
          {detail ? <details className="mt-3 text-xs text-red-100/60"><summary>View details</summary><pre className="mt-2 whitespace-pre-wrap font-mono">{detail}</pre></details> : null}
          {action ? <div className="mt-4">{action}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={cx('animate-pulse rounded-2xl bg-white/[0.06]', className)} />;
}

export function Drawer({ title, open, onClose, children, accent = 'purple' }: { title: string; open: boolean; onClose: () => void; children: ReactNode; accent?: 'purple' | 'amber' }) {
  return (
    <AnimatePresence>
      {open ? (
        <>
          <motion.div className="fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside
            initial={{ x: 420, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 420, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed right-0 top-0 z-50 h-full w-full max-w-xl overflow-y-auto border-l border-white/[0.08] bg-[#0B1020]/95 p-6 shadow-2xl backdrop-blur-xl"
          >
            <div className="mb-6 flex items-start justify-between gap-4">
              <div>
                <div className={cx('mb-2 h-1 w-12 rounded-full', accent === 'amber' ? 'bg-amber-400' : 'bg-violet-400')} />
                <h2 className="text-xl font-semibold text-slate-50">{title}</h2>
              </div>
              <Button variant="ghost" onClick={onClose} className="h-10 w-10 p-0" aria-label="Close drawer">
                <X className="h-4 w-4" />
              </Button>
            </div>
            {children}
          </motion.aside>
        </>
      ) : null}
    </AnimatePresence>
  );
}

export function InfoCallout({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-2xl border border-sky-400/20 bg-sky-500/[0.06] p-4 text-sm text-sky-100/80">
      <div className="mb-1 flex items-center gap-2 font-semibold text-sky-100"><Info className="h-4 w-4" />{title}</div>
      {children}
    </div>
  );
}

export function RemediationChecklist({ items }: { items: string[] }) {
  const normalized = items.length ? items : ['Review the evidence.', 'Apply the recommended fix.', 'Deploy changes.', 'Rerun the relevant PhantomScan check.'];
  return (
    <ol className="space-y-2">
      {normalized.map((item, index) => (
        <li key={`${item}-${index}`} className="flex gap-3 rounded-2xl bg-white/[0.035] p-3 text-sm text-slate-300">
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-xs font-semibold text-violet-200">{index + 1}</span>
          <span className="leading-6">{item}</span>
        </li>
      ))}
    </ol>
  );
}
