// frontend/src/components/SeverityBadge.tsx
// Single source of truth for how severity renders as UI, replacing the
// sevColor/SEV_CLASS objects previously duplicated (with drifting values)
// across AlertsPanel, CaseTable, AlertDetailsModal, and Wallboard.
//
// Deliberately NOT four equally-weighted colored pills — that treats a
// CRITICAL clinical alert and a LOW one as the same shape of fact, just
// tinted differently, which is exactly backwards for a tool whose entire
// job is triage. Weight drops with severity instead: CRITICAL is a solid
// filled block (the one thing that should stop a scrolling eye), HIGH is a
// tinted outline, MEDIUM is plain colored text, LOW is muted and recedes.
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
