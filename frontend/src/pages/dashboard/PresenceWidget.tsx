// Real-time "who's logged in" widget, backed by GET /api/users/presence —
// derives "online" from lastActiveAt, stamped by the `protect` middleware on
// every authenticated request rather than a separate heartbeat/socket. Only
// admin callers get back a `roster`; others see counts only.
import React, { useEffect, useState } from 'react';
import { Users, ShieldCheck, Eye, ChevronDown, Loader2, Wrench, ClipboardCheck } from 'lucide-react';
import { apiGetPresenceSummary } from '../../services/api';
import type { PresenceSummary, PresenceRosterEntry } from '../../services/api';

const POLL_MS = 20 * 1000;

// Shared poll — call this once per page and pass the result down, so the
// Overview stat card and the presence widget don't each open their own
// interval against the same endpoint.
export function usePresenceSummary(token: string | null) {
  const [summary, setSummary] = useState<PresenceSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    let cancelled = false;

    const load = async () => {
      try {
        const data = await apiGetPresenceSummary(token);
        if (!cancelled) { setSummary(data); setError(''); }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load presence.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    load();
    const interval = setInterval(load, POLL_MS);
    return () => { cancelled = true; clearInterval(interval); };
  }, [token]);

  return { summary, loading, error };
}

function timeAgo(iso: string | null): string {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return 'just now';
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return new Date(iso).toLocaleDateString();
}

const RosterList: React.FC<{ entries: PresenceRosterEntry[] }> = ({ entries }) => (
  <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
    {entries.map((u) => (
      <div key={u.id} className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors">
        <div className="flex items-center gap-2 min-w-0">
          <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${u.online ? 'bg-emerald-400 animate-pulse' : 'bg-slate-200 dark:bg-slate-700'}`} />
          <div className="min-w-0">
            <p className="text-xs text-slate-900 dark:text-white font-medium truncate">{u.name}</p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 truncate">{u.email}</p>
          </div>
        </div>
        <span className={`text-[11px] whitespace-nowrap flex-shrink-0 ${u.online ? 'text-emerald-400' : 'text-slate-400 dark:text-slate-600'}`}>
          {u.online ? 'Online' : timeAgo(u.lastActiveAt)}
        </span>
      </div>
    ))}
  </div>
);

type PresenceBucketKey = 'admins' | 'analysts' | 'biomed' | 'auditors';

const PresenceWidget: React.FC<{ summary: PresenceSummary | null; loading: boolean; error: string }> = ({ summary, loading, error }) => {
  const [showRoster, setShowRoster] = useState<PresenceBucketKey | null>(null);
  const hasRoster = !!summary?.roster;
  // Biomed/auditor tiles only take up grid space once at least one such
  // account exists — most installs will only ever have admins + analysts,
  // and an always-visible "0 / 0 Biomedical Eng." tile is just noise.
  const showBiomed = !!summary && summary.biomed.total > 0;
  const showAuditors = !!summary && summary.auditors.total > 0;

  return (
    <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Users className="w-4 h-4 text-cyan-400" />
            Team Presence
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Who's logged in right now</p>
        </div>
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20">
          {loading && !summary ? (
            <Loader2 className="w-3 h-3 text-emerald-400 animate-spin" />
          ) : (
            <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
          )}
          <span className="text-[11px] text-emerald-400 font-medium">Live</span>
        </div>
      </div>

      {error && !summary ? (
        <p className="text-xs text-red-400">{error}</p>
      ) : (
        <div className="grid grid-cols-2 gap-3">
          {(
            [
              { key: 'admins' as const, label: 'Admins Online', icon: <ShieldCheck className="w-4 h-4 text-violet-400" /> },
              { key: 'analysts' as const, label: 'Analysts Online', icon: <Eye className="w-4 h-4 text-cyan-400" /> },
              ...(showBiomed ? [{ key: 'biomed' as const, label: 'Biomedical Eng. Online', icon: <Wrench className="w-4 h-4 text-amber-400" /> }] : []),
              ...(showAuditors ? [{ key: 'auditors' as const, label: 'Auditors Online', icon: <ClipboardCheck className="w-4 h-4 text-emerald-400" /> }] : []),
            ]
          ).map(({ key, label, icon }) => {
            const bucket = summary?.[key];
            const roster = summary?.roster?.[key];
            const open = showRoster === key;
            return (
              <div key={key} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white/40 dark:bg-slate-950/40 p-3">
                <button
                  type="button"
                  onClick={() => hasRoster && setShowRoster(open ? null : key)}
                  disabled={!hasRoster}
                  className={`w-full flex items-center justify-between ${hasRoster ? 'cursor-pointer' : 'cursor-default'}`}
                >
                  <div className="flex items-center gap-2">
                    {icon}
                    <div className="text-left">
                      <p className="text-lg font-bold text-slate-900 dark:text-white leading-none">
                        {bucket ? bucket.online : '—'}
                        <span className="text-xs text-slate-400 dark:text-slate-500 font-normal"> / {bucket ? bucket.total : '—'}</span>
                      </p>
                      <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1">{label}</p>
                    </div>
                  </div>
                  {hasRoster && (
                    <ChevronDown className={`w-3.5 h-3.5 text-slate-400 dark:text-slate-500 transition-transform flex-shrink-0 ${open ? 'rotate-180' : ''}`} />
                  )}
                </button>
                {open && roster && (
                  <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800">
                    {roster.length === 0 ? (
                      <p className="text-xs text-slate-400 dark:text-slate-600 text-center py-2">No {key} yet.</p>
                    ) : (
                      <RosterList entries={roster} />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default PresenceWidget;
