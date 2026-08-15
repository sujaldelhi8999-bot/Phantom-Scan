import { useEffect, useRef, useState } from 'react';
import { ChevronDown, LayoutDashboard, LogOut, Settings } from 'lucide-react';
import { Link } from 'react-router-dom';

import { useAuth } from '../../context/AuthContext';
import { cx } from '../ui/Primitives';

export default function UserMenu() {
  const { user, logoutUser } = useAuth();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: PointerEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [open]);

  if (!user) return null;

  const displayName = user.name || user.username || user.email || 'User';
  const emailDisplay = user.email || user.username || '';
  const initial = (displayName.charAt(0) || 'U').toUpperCase();

  return (
    <div className="relative ml-2" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full border border-[var(--border-light)] bg-white dark:bg-gray-800 py-1.5 px-3 text-xs shadow-sm hover:bg-[var(--surface-hover)] transition-all"
        aria-label="User menu"
        aria-expanded={open}
      >
        {/* Avatar (first letter) */}
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-gradient-to-br from-[var(--brand)] to-indigo-600 text-[11px] font-bold text-white">
          {initial}
        </span>

        {/* Role / Plan Badge inside pill */}
        {user.role === 'admin' ? (
          <span className="flex items-center gap-1 rounded-full bg-purple-100 dark:bg-purple-900/50 px-2 py-0.5 text-[10px] font-bold text-purple-700 dark:text-purple-300">
            👑 Admin
          </span>
        ) : user.subscriptionTier === 'PRO' ? (
          <span className="flex items-center gap-1 rounded-full bg-amber-100 dark:bg-amber-900/50 px-2 py-0.5 text-[10px] font-bold text-amber-700 dark:text-amber-300">
            ⚡ Pro
          </span>
        ) : (
          <span className="flex items-center gap-1 rounded-full bg-gray-100 dark:bg-gray-700 px-2 py-0.5 text-[10px] font-semibold text-gray-600 dark:text-gray-300">
            Free
          </span>
        )}

        <span className="font-semibold text-gray-800 dark:text-gray-200 max-w-[150px] truncate sm:inline">
          {emailDisplay}
        </span>
        <ChevronDown className={cx('h-3.5 w-3.5 text-gray-400 transition-transform', open && 'rotate-180')} />
      </button>

      {open ? (
        <div className="absolute right-0 top-11 z-50 w-60 overflow-hidden rounded-2xl border border-[var(--border-light)] bg-white dark:bg-gray-900 p-2 shadow-xl animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="border-b border-gray-100 dark:border-gray-800 px-3 py-2.5 mb-1">
            <div className="flex items-center gap-2">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[var(--brand)] to-indigo-600 text-sm font-bold text-white">
                {initial}
              </span>
              <div className="min-w-0">
                <div className="truncate text-xs font-bold text-gray-900 dark:text-white">{displayName}</div>
                <div className="mt-0.5 truncate text-[11px] text-gray-500 dark:text-gray-400">{emailDisplay}</div>
              </div>
            </div>
          </div>

          <div className="space-y-0.5">
            <Link
              to="/dashboard"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              <LayoutDashboard className="h-4 w-4 text-blue-600 dark:text-blue-400" />
              Dashboard
            </Link>

            <Link
              to="/profile"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              <Settings className="h-4 w-4 text-gray-500 dark:text-gray-400" />
              Profile Settings
            </Link>

            <button
              type="button"
              onClick={() => {
                setOpen(false);
                void logoutUser();
              }}
              className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors"
            >
              <LogOut className="h-4 w-4" />
              Sign Out
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
