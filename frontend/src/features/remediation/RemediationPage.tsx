import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Loader2, ShieldCheck } from 'lucide-react';

import { Button, EmptyState, SectionHeader, SeverityBadge, StatusBadge, Surface } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import { apiErrorMessage, updateFindingRemediation, verifyFindingFix } from '../../services/api';
import { relativeTime, targetName } from '../../utils/derived';
import type { Finding } from '../../types';

const queueDefinitions = [
  { label: 'Immediate', match: (finding: Finding) => isActionable(finding) && finding.remediation_status !== 'IN_PROGRESS' && ['CRITICAL', 'HIGH'].includes(finding.severity) },
  { label: 'In Progress', match: (finding: Finding) => isActionable(finding) && finding.remediation_status === 'IN_PROGRESS' },
  { label: 'Planned', match: (finding: Finding) => isActionable(finding) && finding.remediation_status !== 'IN_PROGRESS' && ['MEDIUM', 'LOW', 'INFO'].includes(finding.severity) },
  { label: 'Resolved', match: (finding: Finding) => isResolved(finding) },
  { label: 'Excluded', match: (finding: Finding) => isExcluded(finding) }
];

function isResolved(finding: Finding) {
  return finding.remediation_status === 'RESOLVED' || finding.verification_status === 'FIX_VERIFIED';
}

function isExcluded(finding: Finding) {
  return !isResolved(finding) && (finding.risk_status ?? 'ACTIVE') !== 'ACTIVE';
}

function isActionable(finding: Finding) {
  return !isResolved(finding) && !isExcluded(finding);
}

export default function RemediationPage() {
  const { findings, refresh } = usePhantomData();
  const [action, setAction] = useState<string | null>(null);
  const grouped = useMemo(
    () => queueDefinitions.map((group) => ({ ...group, items: findings.filter(group.match) })),
    [findings]
  );

  const markInProgress = async (finding: Finding) => {
    setAction(`progress-${finding.id}`);
    try {
      await updateFindingRemediation(finding.id, 'IN_PROGRESS');
      toast.success('Finding marked in progress');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to update remediation status.'));
    } finally {
      setAction(null);
    }
  };

  const verifyFix = async (finding: Finding) => {
    setAction(`verify-${finding.id}`);
    try {
      const result = await verifyFindingFix(finding.id);
      toast.success(result.status === 'FIX_VERIFIED' ? 'Fix verified' : 'Issue still present');
      await refresh();
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Unable to verify fix.'));
    } finally {
      setAction(null);
    }
  };

  return (
    <div className="space-y-6">
      <Surface className="p-6">
        <SectionHeader title="Fix Queue" description="Prioritized from real persisted findings with backend-backed remediation and verification actions." />
      </Surface>
      {grouped.map((group) => (
        <Surface key={group.label} className="overflow-hidden">
          <div className="p-5"><SectionHeader title={group.label} description={`${group.items.length} finding${group.items.length === 1 ? '' : 's'}`} /></div>
          {group.items.length ? (
            <div>
              <div className="hidden grid-cols-[130px_1.3fr_1fr_150px_170px] gap-4 border-y border-white/[0.06] px-5 py-3 text-xs uppercase tracking-[0.18em] text-slate-600 md:grid">
                <span>Priority</span><span>Finding</span><span>Asset</span><span>Status</span><span>Actions</span>
              </div>
              {group.items.map((finding) => (
                <div key={finding.id} className="grid gap-4 border-b border-white/[0.04] px-5 py-4 last:border-b-0 md:grid-cols-[130px_1.3fr_1fr_150px_170px] md:items-center">
                  <SeverityBadge severity={finding.severity} />
                  <div>
                    <div className="font-medium text-slate-100">{finding.title}</div>
                    <div className="mt-1 text-xs text-slate-500">Updated {relativeTime(finding.timestamp)}</div>
                  </div>
                  <span className="truncate font-mono text-sm text-slate-400">{targetName(finding.target)}</span>
                  <div className="flex flex-wrap gap-2"><StatusBadge status={finding.remediation_status ?? 'OPEN'} /><StatusBadge status={finding.verification_status ?? 'NOT_VERIFIED'} /><StatusBadge status={finding.risk_status ?? 'ACTIVE'} /></div>
                  <div className="grid gap-2">
                    <Button onClick={() => void markInProgress(finding)} disabled={!isActionable(finding) || action === `progress-${finding.id}`}>
                      {action === `progress-${finding.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                      Mark In Progress
                    </Button>
                    <Button variant="amber" onClick={() => void verifyFix(finding)} disabled={!isActionable(finding) || action === `verify-${finding.id}`}>
                      {action === `verify-${finding.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                      Verify Fix
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : <div className="px-5 pb-5"><EmptyState title="No findings in this queue" description="Queue membership changes as findings are marked in progress or verified." /></div>}
        </Surface>
      ))}
    </div>
  );
}
