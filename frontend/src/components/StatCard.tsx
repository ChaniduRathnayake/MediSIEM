import React from 'react';
import { Loader2 } from 'lucide-react';

// Explicit class map instead of dynamic `bg-${color}-500/10` template
// literals — Tailwind's scanner only picks up literal class strings, so
// interpolated color classes silently drop out of the production build.
export type StatColor = 'cyan' | 'red' | 'orange' | 'amber' | 'emerald' | 'violet' | 'blue' | 'slate';

// Color here is a left-edge accent + icon tint, not a background block —
// most stat cards on this dashboard aren't reporting a severity or status,
// they're reporting a plain count (device totals, session counts), and
// giving every one of them an equally loud colored icon box flattens real
// signal (Critical Alerts) to the same visual weight as decoration
// (Monitored Devices). The accent stays, sized down to where it belongs.
const COLOR_CLASSES: Record<StatColor, { edge: string; text: string }> = {
  cyan:    { edge: 'before:bg-cyan-500',    text: 'text-cyan-600 dark:text-cyan-400' },
  red:     { edge: 'before:bg-red-500',     text: 'text-red-600 dark:text-red-400' },
  orange:  { edge: 'before:bg-orange-500',  text: 'text-orange-600 dark:text-orange-400' },
  amber:   { edge: 'before:bg-amber-500',   text: 'text-amber-600 dark:text-amber-400' },
  emerald: { edge: 'before:bg-emerald-500', text: 'text-emerald-600 dark:text-emerald-400' },
  violet:  { edge: 'before:bg-violet-500',  text: 'text-violet-600 dark:text-violet-400' },
  blue:    { edge: 'before:bg-blue-500',    text: 'text-blue-600 dark:text-blue-400' },
  slate:   { edge: 'before:bg-slate-400 dark:before:bg-slate-600', text: 'text-slate-500 dark:text-slate-400' },
};

const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  color: StatColor;
  trend?: string;
  loading?: boolean;
}> = ({ icon, label, value, sub, color, trend, loading }) => {
  const c = COLOR_CLASSES[color];
  return (
    <div
      className={`relative pl-4 pr-4 py-3.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800
        before:absolute before:left-0 before:top-3 before:bottom-3 before:w-[3px] before:rounded-full ${c.edge}`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className={`flex items-center gap-1.5 ${c.text}`}>
          <span className="[&>svg]:w-3.5 [&>svg]:h-3.5">{icon}</span>
          <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</span>
        </div>
        {loading ? (
          <Loader2 className="w-3 h-3 text-slate-400 dark:text-slate-600 animate-spin flex-shrink-0" />
        ) : trend ? (
          <span className={`text-[11px] font-medium tabular-nums flex-shrink-0 ${trend.startsWith('+') ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
            {trend}
          </span>
        ) : null}
      </div>
      <div className="text-[26px] leading-tight font-bold tabular-nums text-slate-900 dark:text-white mt-1.5">
        {loading ? '—' : value}
      </div>
      <div className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 truncate">{sub}</div>
    </div>
  );
};

export default StatCard;
