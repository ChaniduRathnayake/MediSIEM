// "How am I doing" — turns verdict data captured at case-close time into feedback the analyst can see.
import React, { useEffect, useState } from 'react';
import { BarChart3, CheckCircle2, Clock, Loader2, ShieldCheck, ShieldX, ShieldQuestion, HelpCircle } from 'lucide-react';
import { apiGetMyStats } from '../../services/alertsApi';
import type { MyAlertStats } from '../../services/alertsApi';

const VERDICT_META: { key: keyof MyAlertStats['verdictCounts']; label: string; icon: React.ReactNode; className: string }[] = [
  { key: 'true_positive', label: 'True positive', icon: <ShieldCheck className="w-3 h-3" />, className: 'bg-red-500' },
  { key: 'false_positive', label: 'False positive', icon: <ShieldX className="w-3 h-3" />, className: 'bg-emerald-500' },
  { key: 'benign', label: 'Benign', icon: <ShieldQuestion className="w-3 h-3" />, className: 'bg-slate-400' },
  { key: 'uncertain', label: 'Uncertain', icon: <HelpCircle className="w-3 h-3" />, className: 'bg-amber-500' },
];

const MyStatsWidget: React.FC<{ token: string | null }> = ({ token }) => {
  const [stats, setStats] = useState<MyAlertStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) { setLoading(false); return; }
    let cancelled = false;
    apiGetMyStats(token)
      .then((s) => { if (!cancelled) setStats(s); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [token]);

  if (loading) {
    return (
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-center gap-2 text-slate-400 dark:text-slate-500 text-sm">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading your stats…
      </div>
    );
  }

  if (!stats || stats.totalClosed === 0) {
    return (
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
        <h2 className="text-base font-semibold text-slate-900 dark:text-white flex items-center gap-2 mb-1">
          <BarChart3 className="w-4 h-4 text-cyan-500 dark:text-cyan-400" /> Your stats
        </h2>
        <p className="text-sm text-slate-400 dark:text-slate-500">No closed cases yet — your resolution stats will show up here.</p>
      </div>
    );
  }

  const maxVerdict = Math.max(1, ...VERDICT_META.map((v) => stats.verdictCounts[v.key]));

  return (
    <div className="p-5 rounded-xl bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
      <h2 className="text-base font-semibold text-slate-900 dark:text-white flex items-center gap-2 mb-4">
        <BarChart3 className="w-4 h-4 text-cyan-500 dark:text-cyan-400" /> Your stats
      </h2>
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500 text-[11px] uppercase tracking-wider mb-1">
            <CheckCircle2 className="w-3 h-3" /> Closed this week
          </div>
          <div className="text-xl font-bold text-slate-900 dark:text-white">{stats.closedThisWeek}</div>
        </div>
        <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500 text-[11px] uppercase tracking-wider mb-1">
            <CheckCircle2 className="w-3 h-3" /> Total closed
          </div>
          <div className="text-xl font-bold text-slate-900 dark:text-white">{stats.totalClosed}</div>
        </div>
        <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-1.5 text-slate-400 dark:text-slate-500 text-[11px] uppercase tracking-wider mb-1">
            <Clock className="w-3 h-3" /> Avg. time to resolve
          </div>
          <div className="text-xl font-bold text-slate-900 dark:text-white">
            {stats.avgResolutionMinutes === null
              ? '—'
              : stats.avgResolutionMinutes < 60
              ? `${stats.avgResolutionMinutes}m`
              : `${(stats.avgResolutionMinutes / 60).toFixed(1)}h`}
          </div>
        </div>
      </div>
      <p className="text-[11px] text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-2">Verdict breakdown</p>
      <div className="space-y-1.5">
        {VERDICT_META.map((v) => {
          const count = stats.verdictCounts[v.key];
          return (
            <div key={v.key} className="flex items-center gap-2.5">
              <span className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 w-32 flex-shrink-0">{v.icon} {v.label}</span>
              <div className="flex-1 bg-slate-200 dark:bg-slate-800 rounded-full h-1.5">
                <div className={`h-1.5 rounded-full ${v.className}`} style={{ width: `${(count / maxVerdict) * 100}%` }} />
              </div>
              <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400 w-6 text-right">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default MyStatsWidget;
