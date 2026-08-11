import React from 'react';
import { Loader2 } from 'lucide-react';

// Explicit class map instead of dynamic `bg-${color}-500/10` template
// literals — Tailwind's scanner only picks up literal class strings, so
// interpolated color classes silently drop out of the production build.
export type StatColor = 'cyan' | 'red' | 'orange' | 'amber' | 'emerald' | 'violet' | 'blue' | 'slate';

const COLOR_CLASSES: Record<StatColor, { bg: string; text: string; border: string }> = {
  cyan:    { bg: 'bg-cyan-500/10',    text: 'text-cyan-500 dark:text-cyan-400',       border: 'hover:border-cyan-500/30' },
  red:     { bg: 'bg-red-500/10',     text: 'text-red-500 dark:text-red-400',         border: 'hover:border-red-500/30' },
  orange:  { bg: 'bg-orange-500/10',  text: 'text-orange-500 dark:text-orange-400',   border: 'hover:border-orange-500/30' },
  amber:   { bg: 'bg-amber-500/10',   text: 'text-amber-600 dark:text-amber-400',     border: 'hover:border-amber-500/30' },
  emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-600 dark:text-emerald-400', border: 'hover:border-emerald-500/30' },
  violet:  { bg: 'bg-violet-500/10',  text: 'text-violet-500 dark:text-violet-400',   border: 'hover:border-violet-500/30' },
  blue:    { bg: 'bg-blue-500/10',    text: 'text-blue-500 dark:text-blue-400',       border: 'hover:border-blue-500/30' },
  slate:   { bg: 'bg-slate-500/10',   text: 'text-slate-500 dark:text-slate-400',     border: 'hover:border-slate-500/30' },
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
    <div className={`p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 ${c.border} transition-colors`}>
      <div className="flex items-start justify-between mb-3">
        <div className={`w-10 h-10 rounded-xl ${c.bg} flex items-center justify-center ${c.text}`}>{icon}</div>
        {loading ? (
          <Loader2 className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 animate-spin" />
        ) : trend ? (
          <span className={`text-xs px-2 py-0.5 rounded-full ${trend.startsWith('+') ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-red-500/10 text-red-600 dark:text-red-400'}`}>
            {trend}
          </span>
        ) : null}
      </div>
      <div className="text-2xl font-black text-slate-900 dark:text-white mb-0.5">{loading ? '…' : value}</div>
      <div className="text-xs font-medium text-slate-600 dark:text-slate-300">{label}</div>
      <div className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{sub}</div>
    </div>
  );
};

export default StatCard;
