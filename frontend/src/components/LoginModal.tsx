import React, { useState } from 'react';
import { GitBranch, Globe, Loader2, Lock, Mail, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [ssoProvider, setSsoProvider] = useState<'google' | 'github' | null>(null);
  const { loginUser, loginWithProvider, supabaseConfigured } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await loginUser(username, password);
      onClose();
      window.location.reload();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed. Try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleSso = async (provider: 'google' | 'github') => {
    setError('');
    setSsoProvider(provider);
    try {
      await loginWithProvider(provider);
      // Redirect to the provider happens in the browser; do not close the modal.
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || `Could not start ${provider} login.`);
      setSsoProvider(null);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 max-w-md w-full shadow-xl">
        <h2 className="text-2xl font-bold mb-6 text-center text-gray-800 dark:text-white">
          🔒 Admin Login
        </h2>

        {supabaseConfigured && (
          <>
            <div className="space-y-3 mb-6">
              <button
                type="button"
                onClick={() => void handleSso('google')}
                disabled={ssoProvider !== null}
                className="w-full flex items-center justify-center gap-2 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-2.5 text-sm font-medium text-gray-800 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
              >
                {ssoProvider === 'google' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                Continue with Google
              </button>
              <button
                type="button"
                onClick={() => void handleSso('github')}
                disabled={ssoProvider !== null}
                className="w-full flex items-center justify-center gap-2 bg-gray-900 dark:bg-gray-950 rounded-lg px-4 py-2.5 text-sm font-medium text-white hover:bg-gray-800 dark:hover:bg-gray-900 transition-colors disabled:opacity-50"
              >
                {ssoProvider === 'github' ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitBranch className="h-4 w-4" />}
                Continue with GitHub
              </button>
            </div>

            <div className="flex items-center gap-3 mb-6">
              <div className="flex-1 border-t border-gray-200 dark:border-gray-700" />
              <span className="text-xs text-gray-500 dark:text-gray-400">or with password</span>
              <div className="flex-1 border-t border-gray-200 dark:border-gray-700" />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-gray-700 dark:text-gray-300 mb-2">Username / ID</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full pl-9 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:border-gray-600"
                placeholder="Enter admin username"
                required
              />
            </div>
          </div>
          <div className="mb-6">
            <label className="block text-gray-700 dark:text-gray-300 mb-2">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 dark:bg-gray-700 dark:border-gray-600"
                placeholder="Enter password"
                required
              />
            </div>
          </div>
          {error && (
            <div className="mb-4 text-red-600 text-sm text-center">{error}</div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {loading ? 'Logging in...' : 'Unlock Private Console'}
          </button>
        </form>
        <button
          onClick={onClose}
          className="mt-4 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 w-full text-center"
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default LoginModal;
