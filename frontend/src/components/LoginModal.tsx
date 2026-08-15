import React, { useState } from 'react';
import { GitBranch, Globe, Loader2, Lock, Mail, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiErrorMessage } from '../services/api';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const [email, setEmail] = useState('');
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
      await loginUser(email, password);
      onClose();
    } catch (err: any) {
      setError(apiErrorMessage(err, 'Login failed. Try again.'));
    } finally {
      setLoading(false);
    }
  };

  const handleSso = async (provider: 'google' | 'github') => {
    setError('');
    setSsoProvider(provider);
    try {
      await loginWithProvider(provider);
    } catch (err: any) {
      setError(apiErrorMessage(err, `Could not start ${provider} login.`));
      setSsoProvider(null);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[var(--surface-primary)] rounded-2xl p-8 max-w-md w-full border border-[var(--border-light)] shadow-[var(--shadow-float)]">
        <div className="text-center mb-6">
          <div className="flex justify-center mb-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[var(--brand)]">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
          </div>
          <h2 className="text-xl font-bold text-[var(--text-strong)]">
            Sign In to PhantomScan
          </h2>
          <p className="text-xs text-[var(--text-muted)] mt-1">Enter your credentials to access your security workspace</p>
        </div>

        {supabaseConfigured && (
          <>
            <div className="space-y-2.5 mb-5">
              <button
                type="button"
                onClick={() => void handleSso('google')}
                disabled={ssoProvider !== null}
                className="w-full flex items-center justify-center gap-2 border border-[var(--border-light)] rounded-lg px-4 py-2 text-xs font-medium text-[var(--text-strong)] hover:bg-[var(--surface-hover)] transition-colors disabled:opacity-50"
              >
                {ssoProvider === 'google' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                Continue with Google
              </button>
              <button
                type="button"
                onClick={() => void handleSso('github')}
                disabled={ssoProvider !== null}
                className="w-full flex items-center justify-center gap-2 bg-gray-900 dark:bg-gray-950 rounded-lg px-4 py-2 text-xs font-medium text-white hover:bg-gray-800 transition-colors disabled:opacity-50"
              >
                {ssoProvider === 'github' ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitBranch className="h-4 w-4" />}
                Continue with GitHub
              </button>
            </div>

            <div className="flex items-center gap-3 mb-5">
              <div className="flex-1 border-t border-[var(--border-light)]" />
              <span className="text-[11px] text-[var(--text-muted)]">or with email</span>
              <div className="flex-1 border-t border-[var(--border-light)]" />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-[var(--text-strong)] mb-1.5">Email Address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-muted)]" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-xs border border-[var(--border-light)] rounded-lg bg-[var(--surface-secondary)] text-[var(--text-strong)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
                placeholder="you@example.com"
                required
                autoComplete="email"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-strong)] mb-1.5">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-muted)]" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-9 pr-4 py-2 text-xs border border-[var(--border-light)] rounded-lg bg-[var(--surface-secondary)] text-[var(--text-strong)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)]"
                placeholder="Enter password"
                required
                autoComplete="current-password"
              />
            </div>
          </div>
          {error && (
            <div className="p-2.5 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-xs text-red-600 dark:text-red-400 text-center">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[var(--brand)] hover:bg-[var(--brand-hover)] text-white font-semibold py-2.5 px-4 rounded-lg text-xs transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <button
          onClick={onClose}
          className="mt-3 text-xs text-[var(--text-muted)] hover:text-[var(--text-strong)] w-full text-center py-1"
        >
          Cancel
        </button>
      </div>
    </div>
  );
};

export default LoginModal;
