import { useEffect, useRef, useState } from 'react';
import { ChevronDown, LogOut, Settings } from 'lucide-react';
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

  const displayName = user.name || user.username || 'User';
  const initial = displayName.charAt(0).toUpperCase();

  return (
    <div className="relative ml-2" ref={containerRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-[var(--radius-control)] border border-[var(--border-light)] bg-[var(--surface-secondary)] py-1 pl-1 pr-2 text-xs hover:bg-[var(--surface-hover)]"
        aria-label="User menu"
        aria-expanded={open}
      >
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--brand)] text-[11px] font-bold text-white">
          {initial}
        </span>
        <span className="hidden max-w-[120px] truncate font-medium text-[var(--text-default)] sm:inline">{displayName}</span>
        <ChevronDown className={cx('h-3 w-3 text-[var(--text-subtle)] transition-transform', open && 'rotate-180')} />
      </button>

      {open ? (
        <div className="absolute right-0 top-10 z-30 w-64 overflow-hidden rounded-xl border border-[var(--border-light)] bg-[var(--surface-primary)] shadow-[var(--shadow-float)]">
          <div className="border-b border-[var(--border-light)] px-4 py-3">
            <div className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[var(--brand)] text-sm font-bold text-white">
                {initial}
              </span>
              <div className="min-w-0">
                <div className="truncate text-xs font-semibold text-[var(--text-strong)]">{displayName}</div>
                <div className="mt-0.5 truncate text-[10px] text-[var(--text-muted)]">{user.email || user.username}</div>
              </div>
            </div>
            <div className="mt-2.5 text-[10px] font-semibold text-[var(--brand)]">
              {user.role === 'admin' ? '👑 Admin' : 'User'}
            </div>
          </div>

          <div className="p-1.5">
            <Link
              to="/profile"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs text-[var(--text-default)] hover:bg-[var(--surface-hover)]"
            >
              <Settings className="h-3.5 w-3.5 text-[var(--text-subtle)]" />
              Profile Settings
            </Link>
            <button
              onClick={() => { setOpen(false); void logoutUser(); }}
              className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-xs text-[var(--danger)] hover:bg-[var(--surface-hover)]"
            >
              <LogOut className="h-3.5 w-3.5" />
              Logout
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
