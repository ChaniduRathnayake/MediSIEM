// Small shared UI building blocks used across the IP Reputation sub-views —
// mirrors the Metric/DataRow helpers each source .jsx file defined locally,
// consolidated once here and re-implemented with Tailwind (matching
// CompliancePanel.tsx's card/stat-tile/badge conventions) instead of the
// original app's bespoke App.css classes.
import React from 'react';
import { AlertCircle, Loader2 } from 'lucide-react';

export type Tone = 'good' | 'warn' | 'bad' | 'neutral';

const GOOD = new Set(['low', 'minimal', 'allow', 'allowed', 'benign', 'none', 'trusted_with_monitoring', 'healthy', 'passed', 'resolved', 'closed', 'enabled']);
const WARN = new Set(['medium', 'watch', 'suspicious', 'degraded', 'pending', 'in_progress', 'enhanced_monitoring', 'undetermined']);
const BAD = new Set(['critical', 'high', 'block', 'blocked', 'malicious', 'unavailable', 'conflict', 'analyst_review_required', 'block_or_contain', 'open']);

// Best-effort classification of a risk/status word into a color tone. Used for
// risk levels, verdicts, decisions, and internal-list statuses alike — the
// vocabularies overlap enough (Low/Medium/High/Critical, allow/watch/block,
// benign/suspicious/malicious) that one mapping covers all of them.
export function toneOf(value?: string | null): Tone {
  const v = (value || '').trim().toLowerCase();
  if (!v) return 'neutral';
  if (BAD.has(v)) return 'bad';
  if (WARN.has(v)) return 'warn';
  if (GOOD.has(v)) return 'good';
  return 'neutral';
}

export const TONE_TEXT: Record<Tone, string> = {
  good: 'text-emerald-500 dark:text-emerald-400',
  warn: 'text-amber-500 dark:text-amber-400',
  bad: 'text-red-500 dark:text-red-400',
  neutral: 'text-slate-500 dark:text-slate-400',
};

export const TONE_BADGE: Record<Tone, string> = {
  good: 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  warn: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/30',
  bad: 'text-red-600 dark:text-red-400 bg-red-500/10 border-red-500/30',
  neutral: 'text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
};

export const MetricTile: React.FC<{ label: string; value: React.ReactNode; tone?: Tone }> = ({ label, value, tone = 'neutral' }) => (
  <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3">
    <p className="text-xs text-slate-400 dark:text-slate-500">{label}</p>
    <p className={`text-sm font-bold mt-1 ${TONE_TEXT[tone]}`}>{value}</p>
  </div>
);

export const DataRow: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div className="flex items-center justify-between gap-3 py-1.5 text-sm border-b border-slate-100 dark:border-slate-800/60 last:border-0">
    <span className="text-slate-500 dark:text-slate-400">{label}</span>
    <span className="text-slate-900 dark:text-white font-medium text-right">{value}</span>
  </div>
);

export const Badge: React.FC<{ children: React.ReactNode; tone?: Tone }> = ({ children, tone = 'neutral' }) => (
  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-medium whitespace-nowrap ${TONE_BADGE[tone]}`}>
    {children}
  </span>
);

export const SectionCard: React.FC<{
  eyebrow?: string;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}> = ({ eyebrow, title, subtitle, right, className, children }) => (
  <section className={`rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5 ${className ?? ''}`}>
    {(title || right || eyebrow) && (
      <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
        <div>
          {eyebrow && <span className="text-[10px] font-semibold tracking-wider text-cyan-600 dark:text-cyan-400 uppercase">{eyebrow}</span>}
          {title && <h3 className="text-sm font-semibold text-slate-900 dark:text-white mt-0.5">{title}</h3>}
          {subtitle && <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{subtitle}</p>}
        </div>
        {right}
      </div>
    )}
    {children}
  </section>
);

export const EmptyNotice: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">{children}</p>
);

export const ErrorBanner: React.FC<{ message: string }> = ({ message }) => (
  <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-sm">
    <AlertCircle className="w-4 h-4 flex-shrink-0" /> {message}
  </div>
);

export const LoadingBlock: React.FC<{ label?: string }> = ({ label = 'Loading…' }) => (
  <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
    <Loader2 className="w-4 h-4 animate-spin" /> {label}
  </div>
);

export const RefreshButton: React.FC<{ onClick: () => void; loading?: boolean }> = ({ onClick, loading }) => (
  <button
    onClick={onClick}
    disabled={loading}
    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
  >
    <Loader2 className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : 'hidden'}`} />
    Refresh
  </button>
);

export function fmtDateTime(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function formatLabel(value?: string | null): string {
  if (!value) return 'Unknown';
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
}

export function formatMirsDimension(score?: number | null, weight?: number | null): string {
  const scoreText = score == null ? 'Unavailable' : `${Number(score).toFixed(2)}/100`;
  if (weight == null) return scoreText;
  return `${scoreText} • weight ${(Number(weight) * 100).toFixed(2)}%`;
}
