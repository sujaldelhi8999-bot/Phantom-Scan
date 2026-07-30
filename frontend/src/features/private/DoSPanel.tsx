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
}

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
  const [stats, setStats] = useState({ requests_sent: 0, responses_received: 0, errors: 0 });

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
        });
        if (data.status !== 'running') {
          setRunning(false);
          setCurrentJob(null);
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
    try {
      const data = await startDos(target, intensity, duration);
      setCurrentJob(data);
      setRunning(true);
      setStats({ requests_sent: 0, responses_received: 0, errors: 0 });
      await fetchHistory();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to start DoS attack'));
    } finally { setLoading(false); }
  };

  const handleStop = async () => {
    if (!currentJob) return;
    try {
      await stopDos(currentJob.job_id);
      setRunning(false);
      setCurrentJob(null);
      await fetchHistory();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Failed to stop attack'));
    }
  };

  const intensityColor = (level: string) => {
    const map: Record<string, string> = { low: 'bg-green-500', medium: 'bg-yellow-500', high: 'bg-orange-500', critical: 'bg-red-600' };
    return map[level] || 'bg-gray-500';
  };

  const statusBadge = (status: string) => {
    const map: Record<string, string> = { running: 'text-green-500', completed: 'text-blue-500', stopped: 'text-yellow-500', error: 'text-red-500' };
    return <span className={`${map[status] || 'text-gray-500'}`}>{'\u25CF'} {status}</span>;
  };

  const maxExpected = currentJob
    ? currentJob.duration * (currentJob.intensity === 'low' ? 2 : currentJob.intensity === 'medium' ? 10 : currentJob.intensity === 'high' ? 50 : 100)
    : 1;

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
              onChange={(e) => setIntensity(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={running}
            >
              <option value="low">Low (2 req/s) - Safe</option>
              <option value="medium">Medium (10 req/s)</option>
              <option value="high">High (50 req/s)</option>
              <option value="critical">Critical (100 req/s) - Lab only</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Duration</label>
            <div className="flex gap-2">
              <input
                type="number"
                value={duration}
                onChange={(e) => setDuration(Math.min(300, Math.max(5, parseInt(e.target.value) || 30)))}
                className="w-24 px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                disabled={running}
              />
              <span className="flex items-center text-gray-500">seconds</span>
            </div>
          </div>
        </div>

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
                  {currentJob.intensity} intensity &middot; {currentJob.duration}s duration
                </span>
              </div>
              {statusBadge('running')}
            </div>
            <div className="grid grid-cols-3 gap-4 mt-3 text-sm">
              <div><span className="text-gray-500">Requests Sent</span><div className="font-bold text-lg">{stats.requests_sent}</div></div>
              <div><span className="text-gray-500">Responses</span><div className="font-bold text-lg text-green-600">{stats.responses_received}</div></div>
              <div><span className="text-gray-500">Errors</span><div className="font-bold text-lg text-red-600">{stats.errors}</div></div>
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
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {history.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No DoS attacks in history</td></tr>
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
