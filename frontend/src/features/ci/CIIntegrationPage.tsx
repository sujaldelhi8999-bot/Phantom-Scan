import { useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Check, ClipboardCopy, FileCode, FileDown, Braces, GitPullRequest, Loader2, ShieldCheck } from 'lucide-react';

import { Button, EmptyState, Page, PageHeader, Panel, SectionHeader, Select, StatusBadge } from '../../components/ui/Primitives';
import { usePhantomData } from '../../hooks/usePhantomData';
import {
  apiErrorMessage,
  createComplianceReport,
  getPRCommentPreview,
  getSARIF,
  getWorkflowTemplate,
  listPRComments,
} from '../../services/api';
import type { ComplianceReportResponse } from '../../types';

const FRAMEWORK_VALUES = ['pci_dss', 'soc2', 'iso27001', 'hipaa', 'gdpr', 'nist_csf', 'cis'] as const;
type FrameworkValue = (typeof FRAMEWORK_VALUES)[number];

const FRAMEWORKS = [
  { value: 'pci_dss', label: 'PCI DSS 4.0' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO/IEC 27001' },
  { value: 'hipaa', label: 'HIPAA' },
  { value: 'gdpr', label: 'GDPR' },
  { value: 'nist_csf', label: 'NIST CSF' },
  { value: 'cis', label: 'CIS Controls' },
] as const;

export default function CIIntegrationPage() {
  const { scans } = usePhantomData();
  const [scanId, setScanId] = useState<number | ''>('');
  const [template, setTemplate] = useState<string | null>(null);
  const [templateLoading, setTemplateLoading] = useState(false);
  const [sarifLoading, setSarifLoading] = useState(false);
  const [selectedFrameworks, setSelectedFrameworks] = useState<FrameworkValue[]>(['pci_dss', 'soc2']);
  const [reportFormat, setReportFormat] = useState<'markdown' | 'json' | 'html' | 'pdf'>('markdown');
  const [report, setReport] = useState<ComplianceReportResponse | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [prComment, setPrComment] = useState<string | null>(null);
  const [prComments, setPrComments] = useState<Array<{ id: number; pr_number: number; repo_full_name: string; created_at: string }>>([]);
  const [prLoading, setPrLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const selectedScan = useMemo(() => (scanId === '' ? null : scans.find((s) => s.id === scanId)), [scans, scanId]);

  const loadTemplate = async () => {
    setTemplateLoading(true);
    try {
      const result = await getWorkflowTemplate();
      setTemplate(result);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not load the workflow template.'));
    } finally {
      setTemplateLoading(false);
    }
  };

  const copyTemplate = async () => {
    if (!template) return;
    try {
      await navigator.clipboard.writeText(template);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error('Could not copy to clipboard.');
    }
  };

  const exportSARIF = async () => {
    if (!scanId) {
      toast.error('Select a scan first.');
      return;
    }
    setSarifLoading(true);
    try {
      const sarif = await getSARIF(scanId);
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/sarif+json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `phantomscan-${scanId}.sarif`;
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success('SARIF exported');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'SARIF export failed.'));
    } finally {
      setSarifLoading(false);
    }
  };

  const generateReport = async () => {
    if (!scanId) {
      toast.error('Select a scan first.');
      return;
    }
    if (!selectedFrameworks.length) {
      toast.error('Select at least one framework.');
      return;
    }
    setReportLoading(true);
    try {
      const result = await createComplianceReport({
        scan_id: scanId,
        frameworks: selectedFrameworks,
        format: reportFormat,
      });
      setReport(result);
      toast.success('Compliance report generated');
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not generate the report.'));
    } finally {
      setReportLoading(false);
    }
  };

  const previewPRComment = async () => {
    if (!scanId) {
      toast.error('Select a scan first.');
      return;
    }
    setPrLoading(true);
    try {
      const result = await getPRCommentPreview(scanId);
      setPrComment(result.comment);
      const comments = await listPRComments(scanId);
      setPrComments(comments);
    } catch (err) {
      toast.error(apiErrorMessage(err, 'Could not preview the PR comment.'));
    } finally {
      setPrLoading(false);
    }
  };

  useEffect(() => {
    if (scanId === '') {
      setPrComment(null);
      setPrComments([]);
    }
  }, [scanId]);

  const toggleFramework = (value: FrameworkValue) => {
    setSelectedFrameworks((prev) => (prev.includes(value) ? prev.filter((f) => f !== value) : [...prev, value]));
  };

  return (
    <Page>
      <PageHeader
        title="CI/CD Integration"
        description="GitHub Actions workflows, SARIF exports, PR comment bot and compliance reports."
      />

      {/* Scan selector */}
      <Panel className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[260px] flex-1">
            <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Target scan</label>
            <Select value={scanId} onChange={(e) => setScanId(e.target.value === '' ? '' : Number(e.target.value))}>
              <option value="">Select a scan...</option>
              {scans.slice(0, 30).map((scan) => (
                <option key={scan.id} value={scan.id}>#{scan.id} · {scan.target_url} · {scan.status}</option>
              ))}
            </Select>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => { void exportSARIF(); }} disabled={sarifLoading || scanId === ''}>
              {sarifLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Braces className="h-3.5 w-3.5" />}Export SARIF
            </Button>
            <Button variant="secondary" onClick={() => { void previewPRComment(); }} disabled={prLoading || scanId === ''}>
              {prLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <GitPullRequest className="h-3.5 w-3.5" />}PR Comment
            </Button>
          </div>
        </div>
        {selectedScan ? (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-muted)]">
            <StatusBadge status={selectedScan.status} />
            <span>{selectedScan.target_url}</span>
            <span>· {selectedScan.mode}</span>
          </div>
        ) : null}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* GitHub Actions workflow */}
        <Panel>
          <div className="flex items-center justify-between">
            <SectionHeader title="GitHub Actions workflow" />
            <div className="flex gap-1.5">
              <Button variant="secondary" className="!px-2.5" onClick={() => { void loadTemplate(); }} disabled={templateLoading}>
                {templateLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileCode className="h-3.5 w-3.5" />}Load
              </Button>
              {template ? (
                <Button variant="secondary" className="!px-2.5" onClick={() => { void copyTemplate(); }}>
                  {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <ClipboardCopy className="h-3.5 w-3.5" />}
                </Button>
              ) : null}
            </div>
          </div>
          <p className="mb-3 text-[11px] leading-relaxed text-[var(--text-muted)]">
            Drop this into <span className="font-mono">.github/workflows/phantomscan.yml</span> to run scans on every PR and upload
            SARIF to GitHub Code Scanning.
          </p>
          {template ? (
            <pre className="max-h-96 overflow-auto rounded-xl bg-[var(--surface-tertiary)] p-3.5 font-mono text-[10px] leading-relaxed text-[var(--text-default)]">
              {template}
            </pre>
          ) : (
            <EmptyState
              icon={<FileCode className="h-6 w-6 text-[var(--text-subtle)]" />}
              title="Workflow template"
              description="Click Load to generate the ready-to-use GitHub Actions workflow."
            />
          )}
        </Panel>

        {/* Compliance report */}
        <Panel>
          <SectionHeader title="Compliance report" />
          <div className="mb-3 space-y-3">
            <div>
              <label className="mb-1.5 block text-[10px] font-semibold text-[var(--text-subtle)]">Frameworks</label>
              <div className="flex flex-wrap gap-1.5">
                {FRAMEWORKS.map((framework) => {
                  const active = selectedFrameworks.includes(framework.value);
                  return (
                    <button
                      key={framework.value}
                      onClick={() => toggleFramework(framework.value)}
                      className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                        active
                          ? 'border-[var(--brand)] bg-[var(--brand-soft)] text-[var(--brand)]'
                          : 'border-[var(--border-light)] text-[var(--text-muted)] hover:bg-[var(--surface-hover)]'
                      }`}
                    >
                      {framework.label}
                    </button>
                  );
                })}
              </div>
            </div>
            <div>
              <label className="mb-1 block text-[10px] font-semibold text-[var(--text-subtle)]">Format</label>
              <Select value={reportFormat} onChange={(e) => setReportFormat(e.target.value as typeof reportFormat)} className="w-44">
                <option value="markdown">Markdown</option>
                <option value="json">JSON</option>
                <option value="html">HTML</option>
                <option value="pdf">PDF</option>
              </Select>
            </div>
            <Button onClick={() => { void generateReport(); }} disabled={reportLoading || scanId === ''}>
              {reportLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}Generate Report
            </Button>
          </div>

          {report ? (
            <div className="rounded-xl border border-[var(--brand-soft)] bg-[var(--brand-soft)]/30 p-3.5">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-semibold text-[var(--brand)]">{report.report_id}</span>
                <a
                  href={`${report.download_url}`}
                  download
                  className="flex items-center gap-1 rounded-lg bg-[var(--brand)] px-2.5 py-1 text-[11px] font-medium text-white"
                >
                  <FileDown className="h-3 w-3" />Download
                </a>
              </div>
              <div className="space-y-1 text-[11px] text-[var(--text-muted)]">
                <div>Scan #{report.scan_id} · {report.format}</div>
                <div className="flex flex-wrap gap-1">
                  {report.frameworks.map((framework) => (
                    <span key={framework} className="rounded bg-[var(--surface-tertiary)] px-1.5 py-0.5 text-[9px] uppercase">{framework}</span>
                  ))}
                </div>
              </div>
            </div>
          ) : null}
        </Panel>
      </div>

      {/* PR comment bot */}
      <Panel className="mt-4">
        <SectionHeader title="PR comment bot" />
        {prComment ? (
          <div className="space-y-3">
            <pre className="whitespace-pre-wrap rounded-xl bg-[var(--surface-tertiary)] p-3.5 font-mono text-[10px] leading-relaxed text-[var(--text-default)]">
              {prComment}
            </pre>
            {prComments.length ? (
              <div className="space-y-2">
                <div className="text-[11px] font-semibold text-[var(--text-strong)]">Posted comments</div>
                {prComments.map((comment) => (
                  <div key={comment.id} className="flex items-center justify-between rounded-lg border border-[var(--border-light)] bg-[var(--surface-secondary)] px-3 py-2 text-[11px]">
                    <span className="text-[var(--text-default)]">PR #{comment.pr_number} · {comment.repo_full_name}</span>
                    <span className="text-[var(--text-subtle)]">{comment.created_at}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : (
          <EmptyState
            icon={<GitPullRequest className="h-6 w-6 text-[var(--text-subtle)]" />}
            title="PR comment preview"
            description="Select a scan and click PR Comment to preview what the bot would post on your pull request."
          />
        )}
      </Panel>
    </Page>
  );
}
