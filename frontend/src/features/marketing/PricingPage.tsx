import { Link } from 'react-router-dom';
import { Check, Shield } from 'lucide-react';

import { cx } from '../../components/ui/Primitives';
import { useAuth } from '../../context/AuthContext';

const tiers = [
  {
    name: 'Free',
    price: '₹0',
    purpose: 'Acquisition',
    description: 'For trying PhantomScan and scanning small projects.',
    cta: 'Start free',
    href: '/register',
    features: ['Limited assets', 'Limited scans/month', 'Basic vulnerability findings', 'Basic AI explanations', 'Community support'],
  },
  {
    name: 'Developer / Pro',
    price: '₹999-₹2,499',
    suffix: '/month',
    purpose: 'Individual developers, freelancers, and small teams',
    description: 'More scans, deeper analysis, and workflow integrations.',
    cta: 'Choose Pro',
    href: '/register',
    featured: true,
    features: ['More scans', 'Deeper security analysis', 'Scan history', 'AI remediation', 'Scheduled scanning', 'Exportable reports', 'GitHub integration'],
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    purpose: 'Teams that need control, compliance, and support',
    description: 'Private security workflows with policies and SLAs.',
    cta: 'Contact sales',
    href: '/register',
    features: ['SSO', 'Private deployment', 'Custom scan policies', 'Compliance reporting', 'Audit logs', 'API access', 'SLAs', 'Dedicated support', 'Custom integrations'],
  },
];

export default function PricingPage() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-[var(--app-canvas)] text-[var(--text-default)]">
      <header className="border-b border-[var(--border-light)] bg-white/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-4">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--brand)]">
              <Shield className="h-4 w-4 text-white" />
            </span>
            <span className="text-sm font-bold text-[var(--text-strong)]">PhantomScan</span>
          </Link>
          <nav className="flex items-center gap-2 text-xs font-medium">
            <Link to="/" className="rounded-[var(--radius-control)] px-3 py-2 text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]">Home</Link>
            {user ? (
              <Link to="/dashboard" className="rounded-[var(--radius-control)] bg-[var(--brand)] px-3.5 py-2 text-white hover:bg-[var(--brand-hover)]">Dashboard</Link>
            ) : (
              <>
                <Link to="/login" className="rounded-[var(--radius-control)] px-3 py-2 text-[var(--text-muted)] hover:bg-[var(--surface-hover)] hover:text-[var(--text-default)]">Login</Link>
                <Link to="/register" className="rounded-[var(--radius-control)] bg-[var(--brand)] px-3.5 py-2 text-white hover:bg-[var(--brand-hover)]">Get started</Link>
              </>
            )}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-5 py-14 lg:py-20">
        <div className="mx-auto max-w-2xl text-center">
          <div className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-[var(--brand)]">Pricing</div>
          <h1 className="text-4xl font-semibold tracking-[-0.04em] text-[var(--text-strong)] sm:text-5xl">Pick the workspace that fits your security workflow.</h1>
          <p className="mt-5 text-base leading-7 text-[var(--text-muted)]">Start free, upgrade when scans, history, reports, and integrations become part of your regular release process.</p>
        </div>

        <div className="mt-12 grid gap-4 lg:grid-cols-3">
          {tiers.map((tier) => (
            <section key={tier.name} className={cx('relative rounded-2xl border bg-white p-6 shadow-[var(--shadow-card)]', tier.featured ? 'border-[var(--brand)] shadow-[var(--shadow-float)]' : 'border-[var(--border-light)]')}>
              {tier.featured ? <div className="absolute right-5 top-5 rounded-full bg-[var(--brand-soft)] px-2.5 py-1 text-[10px] font-bold text-[var(--brand)]">Popular</div> : null}
              <div className="text-sm font-semibold text-[var(--text-strong)]">{tier.name}</div>
              <div className="mt-4 flex items-end gap-1">
                <span className="text-3xl font-semibold tracking-[-0.03em] text-[var(--text-strong)]">{tier.price}</span>
                {tier.suffix ? <span className="pb-1 text-xs text-[var(--text-muted)]">{tier.suffix}</span> : null}
              </div>
              <p className="mt-3 min-h-12 text-sm leading-6 text-[var(--text-muted)]">{tier.description}</p>
              <div className="mt-4 rounded-lg bg-[var(--surface-secondary)] px-3 py-2 text-[11px] font-medium text-[var(--text-muted)]">Purpose: {tier.purpose}</div>
              <Link to={tier.href} className={cx('mt-6 inline-flex w-full items-center justify-center rounded-[var(--radius-control)] px-4 py-2.5 text-sm font-semibold', tier.featured ? 'bg-[var(--brand)] text-white hover:bg-[var(--brand-hover)]' : 'border border-[var(--border-default)] text-[var(--text-default)] hover:bg-[var(--surface-hover)]')}>
                {tier.cta}
              </Link>
              <ul className="mt-6 space-y-3">
                {tier.features.map((feature) => (
                  <li key={feature} className="flex gap-2 text-sm text-[var(--text-default)]">
                    <Check className="mt-0.5 h-4 w-4 shrink-0 text-[var(--success)]" />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </main>
    </div>
  );
}
