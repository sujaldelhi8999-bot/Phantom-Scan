import { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { apiErrorMessage, getDosHistory, getDosStatus, startDos, stopDos } from '../../services/api';

interface DoSJob {
  job_id: string;
  target_url: string;
  intensity: string;
  duration: number;
  status: string;
  requests_sent: number;
  responses_received: number;
  errors: number;
  started_at: string;
  stopped_at: string | null;
  baseline_latency?: number;
  peak_latency?: number;
  avg_latency_during?: number;
  recovery_latency?: number;
  impact_score?: number;
  effective?: boolean;
  website_status?: string;
  health_score?: number;
  p95_latency?: number;
  p99_latency?: number;
  jitter_ms?: number;
  error_rate?: number;
  throughput_mbps?: number;
  total_requests?: number;
  status_2xx?: number;
  status_3xx?: number;
  status_4xx?: number;
  status_5xx?: number;
  total_data_mb?: number;
  avg_dns_ms?: number;
  avg_tcp_ms?: number;
  avg_tls_ms?: number;
  avg_ttfb_ms?: number;
  packet_loss?: number;
  recovery_ratio?: number;
  recovered?: boolean;
}

interface LiveStats {
  requests_sent: number;
  responses_received: number;
  errors: number;
  avg_latency: number;
  error_rate: number;
  jitter: number;
}

const fmt = (value: number | undefined | null, digits = 0): string => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return 'N/A';
  return Number(value).toFixed(digits);
};

const healthColor = (score: number | undefined) => {
  const s = Number(score ?? 100);
  if (s > 80) return { text: 'text-green-600', bg: '#22c55e' };
  if (s > 50) return { text: 'text-orange-500', bg: '#f97316' };
  return { text: 'text-red-600', bg: '#ef4444' };
};

const statusInfo = (status: string | undefined) => {
  const base = (status || 'unknown').split('_')[0];
  const map: Record<string, { label: string; icon: string }> = {
    critical: { label: 'Critical — Website severely impacted', icon: '🔴' },
    significant: { label: 'Significant — Website slowed down', icon: '🟠' },
    moderate: { label: 'Moderate — Some impact detected', icon: '🟡' },
    minor: { label: 'Minor — Barely noticeable', icon: '🟢' },
    stable: { label: 'Stable — No significant impact', icon: '✅' },
    unknown: { label: 'Unknown', icon: '❓' },
  };
  const info = map[base] || map.unknown;
  const recoverySuffix = status?.includes('_failed_recovery')
    ? ' (failed to recover)'
    : status?.includes('_slow_recovery')
      ? ' (slow recovery)'
      : '';
  return { ...info, label: info.label + recoverySuffix };
};

export default function DoSPanel() {
  const { user } = useAuth();
  const [target, setTarget] = useState('');
  const [intensity, setIntensity] = useState('low');
  const [duration, setDuration] = useState(30);
  const [running, setRunning] = useState(false);
  const [currentJob, setCurrentJob] = useState<DoSJob | null>(null);
  const [history, setHistory] = useState<DoSJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [stats, setStats] = useState<LiveStats>({ requests_sent: 0, responses_received: 0, errors: 0, avg_latency: 0, error_rate: 0, jitter: 0 });

  const INTENSITY_CAPS: Record<string, number> = { low: 300, medium: 120, high: 30, critical: 10, nuclear: 5 };
  const maxDuration = INTENSITY_CAPS[intensity] || 300;

  if (!user || user.role !== 'admin') {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center p-8 border-2 border-red-500 rounded-lg">
          <h2 className="text-2xl font-bold text-red-600">Admin Access Required</h2>
          <p className="text-gray-600 mt-2">Please log in as admin to access DoS testing.</p>
        </div>
      </div>
    );
  }

  const fetchHistory = async () => {
    try {
      const data = await getDosHistory();
      setHistory(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => { fetchHistory(); }, []);

  useEffect(() => {
    if (!running || !currentJob) return;
    const interval = setInterval(async () => {
      try {
        const data = await getDosStatus(currentJob.job_id);
        setStats({
          requests_sent: data.requests_sent || 0,
          responses_received: data.responses_received || 0,
          errors: data.errors || 0,
          avg_latency: data.avg_latency_during || 0,
          error_rate: data.error_rate || 0,
          jitter: data.jitter_ms || 0,
        });
        if (data.status !== 'running') {
          setRunning(false);
          setCurrentJob(data);
          await fetchHistory();
        }
      } catch {
        // ignore
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [running, currentJob]);

  const handleStart = async () => {
    if (!target) { setError('Please enter a target URL'); return; }
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const data = await startDos(target, intensity, duration);
      if (data.warning) { setNotice(data.warning); }
      setCurrentJob(data);
      setRunning(true);
      setStats({ requests_sent: 0, responses_received: 0, errors: 0, avg_latency: 0, error_rate: 0, jitter: 0 });
      await fetchHistory();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to start DoS attack'));
    } finally { setLoading(false); }
  };

  const handleStop = async () => {
    if (!currentJob) return;
    try {
      await stopDos(currentJob.job_id);
      setError('');
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to stop attack'));
    }
  };

  const intensityColor = (level: string) => {
    const map: Record<string, string> = { low: 'bg-green-500', medium: 'bg-yellow-500', high: 'bg-orange-500', critical: 'bg-red-600', nuclear: 'bg-red-900' };
    return map[level] || 'bg-gray-500';
  };

  const statusBadge = (status: string) => {
    const map: Record<string, string> = { running: 'text-green-500', completed: 'text-blue-500', stopped: 'text-yellow-500', error: 'text-red-500' };
    return <span className={`${map[status] || 'text-gray-500'}`}>{'\u25CF'} {status}</span>;
  };

  const maxExpected = currentJob
    ? currentJob.duration * (currentJob.intensity === 'low' ? 2 : currentJob.intensity === 'medium' ? 10 : currentJob.intensity === 'high' ? 50 : currentJob.intensity === 'nuclear' ? 10000 : 100)
    : 1;

  const showReport = !running && currentJob && (currentJob.status === 'completed' || currentJob.status === 'stopped' || currentJob.status === 'error');

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">DoS Testing</h1>
        <p className="text-gray-600 mt-1">Simulate Denial of Service attacks on authorized targets for educational purposes.</p>
        <div className="mt-2 p-3 bg-red-50 border border-red-300 rounded-lg text-sm text-red-700">
          WARNING: Only use on your own websites, PhantomBank Lab, or localhost. Unauthorized DoS attacks are illegal.
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-500 text-red-700 p-4 rounded-lg mb-6">{error}</div>
      )}

      <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
        <h2 className="text-xl font-bold mb-4">Attack Controls</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com or localhost:8000"
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Intensity</label>
            <select
              value={intensity}
              onChange={(e) => {
                const newIntensity = e.target.value;
                setIntensity(newIntensity);
                const cap = INTENSITY_CAPS[newIntensity] || 300;
                setDuration((d) => Math.min(d, cap));
              }}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            >
              <option value="low">Low (2 req/s) — max 300s</option>
              <option value="medium">Medium (10 req/s) — max 120s</option>
              <option value="high">High (50 req/s) — max 30s</option>
              <option value="critical">Critical (100 req/s) — max 10s — Lab only</option>
              <option value="nuclear">🔴🔴 Nuclear (10,000 req/s) — max 5s — LAB ONLY</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Duration</label>
            <div className="flex gap-2">
              <input
                type="number"
                value={duration}
                min={1}
                max={maxDuration}
                onChange={(e) => setDuration(Math.min(maxDuration, Math.max(1, parseInt(e.target.value) || 1)))}
                className="w-24 px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                disabled={running}
              />
              <span className="flex items-center text-gray-500">seconds <span className="ml-1 text-xs text-orange-500 font-medium">(max {maxDuration}s)</span></span>
            </div>
          </div>
        </div>

        {intensity === 'nuclear' && (
          <div className="p-3 bg-red-100 border border-red-500 text-red-700 rounded-lg mt-2">
            ⚠️ WARNING: Nuclear intensity sends 10,000 requests per second.
            This can crash your system. Only use on PhantomBank Lab or localhost.
            Auto-downgraded if targeting external sites.
          </div>
        )}

        {notice && (
          <div className="p-3 bg-yellow-50 border border-yellow-500 text-yellow-800 rounded-lg mt-2">{notice}</div>
        )}

        <div className="mt-4 flex gap-3">
          {!running ? (
            <button
              onClick={handleStart}
              disabled={loading}
              className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Starting...' : 'Launch Attack'}
            </button>
          ) : (
            <button
              onClick={handleStop}
              className="px-6 py-2 bg-yellow-600 hover:bg-yellow-700 text-white font-semibold rounded-lg transition-colors"
            >
              Stop Attack
            </button>
          )}
          <button
            onClick={() => setTarget('http://localhost:8000/lab/phantombank')}
            className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg transition-colors"
            disabled={running}
          >
            Target Lab
          </button>
        </div>

        {running && currentJob && (
          <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold">Attack Running</span>
                <span className="ml-2 text-sm text-gray-600">
                  {currentJob.intensity} intensity &middot; {currentJob.duration}s duration &middot; measuring DNS/TCP/TLS/TTFB per request
                </span>
              </div>
              {statusBadge('running')}
            </div>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mt-3 text-sm">
              <div><span className="text-gray-500">Requests Sent</span><div className="font-bold text-lg">{stats.requests_sent}</div></div>
              <div><span className="text-gray-500">Responses</span><div className="font-bold text-lg text-green-600">{stats.responses_received}</div></div>
              <div><span className="text-gray-500">Errors</span><div className="font-bold text-lg text-red-600">{stats.errors}</div></div>
              <div><span className="text-gray-500">Avg Latency</span><div className="font-bold text-lg">{fmt(stats.avg_latency)} ms</div></div>
              <div><span className="text-gray-500">Error Rate</span><div className="font-bold text-lg">{fmt(stats.error_rate, 1)}%</div></div>
              <div><span className="text-gray-500">Jitter</span><div className="font-bold text-lg">{fmt(stats.jitter)} ms</div></div>
            </div>
            <div className="mt-2 w-full bg-gray-200 rounded-full h-2">
              <div
                className="h-full bg-red-500 rounded-full transition-all duration-1000"
                style={{ width: `${Math.min(100, (stats.requests_sent / maxExpected) * 100)}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {showReport && currentJob && (
        <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
          <h3 className="text-xl font-bold mb-4">📊 Attack Accuracy Report</h3>

          <div className="flex items-center gap-6 mb-6 p-4 bg-gray-50 rounded-lg">
            <div className={`text-5xl font-bold ${healthColor(currentJob.health_score).text}`}>
              {fmt(currentJob.health_score)}%
            </div>
            <div>
              <div className="text-lg font-semibold">Website Health Score</div>
              <div className="text-sm text-gray-600">
                {statusInfo(currentJob.website_status).icon} {statusInfo(currentJob.website_status).label}
              </div>
            </div>
            <div className="ml-auto text-sm text-gray-500">
              Impact Score: {fmt(currentJob.impact_score)}%
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-blue-50 p-3 rounded border border-blue-200">
              <div className="text-xs text-gray-600">Baseline Latency (Mean)</div>
              <div className="font-bold text-lg">{fmt(currentJob.baseline_latency)} ms</div>
              <div className="text-xs text-gray-500">Normal response time</div>
            </div>
            <div className="bg-red-50 p-3 rounded border border-red-200">
              <div className="text-xs text-gray-600">Peak Latency</div>
              <div className="font-bold text-lg text-red-600">{fmt(currentJob.peak_latency)} ms</div>
              <div className="text-xs text-red-500">
                {currentJob.baseline_latency ? `↑ ${Math.round((Number(currentJob.peak_latency) / Number(currentJob.baseline_latency)) * 100 - 100)}% increase` : ''}
              </div>
            </div>
            <div className="bg-orange-50 p-3 rounded border border-orange-200">
              <div className="text-xs text-gray-600">P95 / P99 Latency</div>
              <div className="font-bold text-lg">{fmt(currentJob.p95_latency)} / {fmt(currentJob.p99_latency)} ms</div>
              <div className="text-xs text-gray-500">Tail latency percentiles</div>
            </div>
            <div className="bg-green-50 p-3 rounded border border-green-200">
              <div className="text-xs text-gray-600">Recovery Latency</div>
              <div className="font-bold text-lg text-green-600">{fmt(currentJob.recovery_latency)} ms</div>
              <div className="text-xs text-gray-500">
                {currentJob.recovery_latency && currentJob.baseline_latency
                  ? (Number(currentJob.recovery_latency) / Number(currentJob.baseline_latency) < 1.2 ? '✅ Fully recovered' : '⚠️ Slow recovery')
                  : ''}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Error Rate / Packet Loss</div>
              <div className="font-bold">{fmt(currentJob.error_rate, 1)}% / {fmt(currentJob.packet_loss, 1)}%</div>
              <div className="text-xs text-gray-400">5xx: {currentJob.status_5xx || 0} &middot; 4xx: {currentJob.status_4xx || 0} &middot; 3xx: {currentJob.status_3xx || 0} &middot; 2xx: {currentJob.status_2xx || 0}</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Jitter (Latency Variability)</div>
              <div className="font-bold">{fmt(currentJob.jitter_ms)} ms</div>
              <div className="text-xs text-gray-400">{Number(currentJob.jitter_ms || 0) > 100 ? '⚠️ High instability' : '✅ Stable'}</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Throughput</div>
              <div className="font-bold">{fmt(currentJob.throughput_mbps, 2)} MB/s</div>
              <div className="text-xs text-gray-400">Total: {fmt(currentJob.total_data_mb, 2)} MB</div>
            </div>
            <div className="bg-gray-50 p-3 rounded">
              <div className="text-xs text-gray-500">Transaction Phases (avg)</div>
              <div className="font-bold">{fmt(currentJob.avg_ttfb_ms)} ms TTFB</div>
              <div className="text-xs text-gray-400">DNS {fmt(currentJob.avg_dns_ms)} &middot; TCP {fmt(currentJob.avg_tcp_ms)} &middot; TLS {fmt(currentJob.avg_tls_ms)} ms</div>
            </div>
          </div>

          <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
            <div
              className="h-full transition-all duration-1000"
              style={{ width: `${Number(currentJob.health_score ?? 100)}%`, background: healthColor(currentJob.health_score).bg }}
            />
          </div>

          <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-start gap-2">
              <span className="text-xl">{currentJob.effective ? '⚠️' : '✅'}</span>
              <div>
                <strong>Attack Effectiveness: </strong>
                {currentJob.effective ? (
                  `Attack caused significant impact. Website health dropped from 100% to ${fmt(currentJob.health_score)}%. `
                ) : (
                  'No significant impact detected. The website handled the traffic normally. '
                )}
                {currentJob.recovered
                  ? 'The website recovered successfully.'
                  : `Recovery issue: post-attack latency is ${fmt((Number(currentJob.recovery_ratio) - 1) * 100, 0)}% above baseline.`}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="text-xl font-bold">Attack History</h2>
          <button onClick={fetchHistory} className="text-sm text-blue-600 hover:text-blue-800">Refresh</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Intensity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requests</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Errors</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Impact</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Health</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {history.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">No DoS attacks in history</td></tr>
              ) : (
                history.map((job) => (
                  <tr key={job.job_id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm truncate max-w-xs">{job.target_url}</td>
                    <td className="px-4 py-3 text-sm">
                      <span className={`px-2 py-1 rounded-full text-white text-xs ${intensityColor(job.intensity)}`}>{job.intensity}</span>
                    </td>
                    <td className="px-4 py-3 text-sm">{statusBadge(job.status)}</td>
                    <td className="px-4 py-3 text-sm">{job.requests_sent || 0}</td>
                    <td className="px-4 py-3 text-sm text-red-600">{job.errors || 0}</td>
                    <td className="px-4 py-3 text-sm">
                      {job.impact_score !== undefined && job.impact_score !== null && job.status !== 'running' ? (
                        <span className={Number(job.impact_score) >= 50 ? 'text-red-600 font-medium' : Number(job.impact_score) >= 25 ? 'text-orange-500' : 'text-gray-600'}>
                          {fmt(job.impact_score)}% {job.website_status ? statusInfo(job.website_status).icon : ''}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {job.health_score !== undefined && job.health_score !== null && job.status !== 'running' ? (
                        <span className={healthColor(job.health_score).text}>{fmt(job.health_score)}%</span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">{job.started_at ? new Date(job.started_at).toLocaleTimeString() : '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
