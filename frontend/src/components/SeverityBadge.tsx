// Single source of truth for how severity renders as UI (previously
// duplicated with drifting values across several panels). Deliberately not
// four equally-weighted pills — visual weight drops with severity instead:
// CRITICAL is a solid filled block, HIGH a tinted outline, MEDIUM plain
// text, LOW muted, so the one thing that should stop a scrolling eye does.
import React from 'react';
import type { Severity } from '../utils/chartData';

const STYLES: Record<Severity, string> = {
  CRITICAL: 'bg-red-600 text-white font-bold',
  HIGH: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border border-orange-500/30 font-semibold',
  MEDIUM: 'text-amber-700 dark:text-amber-400 font-semibold',
  LOW: 'text-slate-400 dark:text-slate-500 font-medium',
};

const SeverityBadge: React.FC<{ severity: Severity; className?: string }> = ({ severity, className = '' }) => (
  <span
    className={`inline-flex items-center text-[11px] tracking-wide uppercase px-1.5 py-0.5 rounded ${STYLES[severity]} ${className}`}
  >
    {severity}
  </span>
);

export default SeverityBadge;
