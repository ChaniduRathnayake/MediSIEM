// frontend/src/pages/dashboard/CaseTable.tsx
//
// Shared row-rendering for a list of cases (alerts with assignment/closure
// state) in one of two fixed variants — 'open' (has a Close case action) or
// 'closed' (read-only, expandable to show the recorded reason/evidence).
// Used by both MyAlertsPanel (an analyst's own queue) and AdminCasesPanel
// (every case across all analysts) so the two "open cases / closed cases"
// sections look and behave identically everywhere they appear.
import React, { useState } from 'react';
import { Inbox, CheckCircle2, Maximize2, ChevronRight, ChevronDown, Siren } from 'lucide-react';
import type { EnrichedAlert, AlertClosure } from '../../services/alertsApi';
import { casToSeverity } from '../../utils/chartData';
import SeverityBadge from '../../components/SeverityBadge';

const CaseTable: React.FC<{
  variant: 'open' | 'closed';
  alerts: EnrichedAlert[];
  closureOf: (a: EnrichedAlert) => AlertClosure | null;
  showAssignedTo: boolean;
  emptyMessage: string;
  onDetails: (a: EnrichedAlert) => void;
  onCloseCase?: (a: EnrichedAlert) => void;
}> = ({ variant, alerts, closureOf, showAssignedTo, emptyMessage, onDetails, onCloseCase }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // Severity, Device, Department, Event, CAS, Time/Closed, Actions = 7 fixed
  // columns, plus Assigned To and (closed only) Reason when shown — used for
  // the expanded row's colSpan.
  const colCount = 7 + (showAssignedTo ? 1 : 0) + (variant === 'closed' ? 1 : 0);

  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-10 text-slate-400 dark:text-slate-500">
        <Inbox className="w-7 h-7" />
        <p className="text-sm">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
            <th className="py-2.5 px-4 text-left">Severity</th>
            <th className="py-2.5 px-4 text-left">Device</th>
            <th className="py-2.5 px-4 text-left">Department</th>
            <th className="py-2.5 px-4 text-left">Event</th>
            <th className="py-2.5 px-4 text-left">CAS</th>
            {showAssignedTo && <th className="py-2.5 px-4 text-left">Assigned To</th>}
            {variant === 'closed' && <th className="py-2.5 px-4 text-left">Reason</th>}
            <th className="py-2.5 px-4 text-left">{variant === 'closed' ? 'Closed' : 'Time'}</th>
            <th className="py-2.5 px-4 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => {
            const severity = casToSeverity(a.CAS);
            const closure = closureOf(a);
            const isExpanded = expandedId === a.id;
            return (
              <React.Fragment key={a.id}>
                <tr
                  onClick={() => variant === 'closed' && setExpandedId(isExpanded ? null : a.id)}
                  className={`border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors ${
                    variant === 'closed' ? 'cursor-pointer' : ''
                  }`}
                >
                  <td className="py-3 px-4">
                    <span className="flex items-center gap-1.5 flex-wrap">
                      <SeverityBadge severity={severity} />
                      {variant === 'open' && a.escalated && (
                        <span
                          title="CAS-critical, still unassigned, open 10+ minutes"
                          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-red-600 text-white text-[10px] font-bold uppercase tracking-wide animate-pulse"
                        >
                          <Siren className="w-2.5 h-2.5" /> Escalated
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-slate-700 dark:text-slate-300 font-mono">{a.agent}</td>
                  <td className="py-3 px-4 text-sm text-slate-500 dark:text-slate-400">{a.department}</td>
                  <td className="py-3 px-4 text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate">
                    {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                  </td>
                  <td className="py-3 px-4 text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">{a.CAS.toFixed(1)}</td>
                  {showAssignedTo && (
                    <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">
                      {a.assignedTo?.name ?? <span className="text-slate-400 dark:text-slate-600">Unassigned</span>}
                    </td>
                  )}
                  {variant === 'closed' && (
                    <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400 max-w-[16rem] truncate" title={closure?.reason ?? ''}>
                      {closure?.reason ?? '—'}
                    </td>
                  )}
                  <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">
                    {variant === 'closed' && closure
                      ? `${closure.closedBy.name} · ${new Date(closure.createdAt).toLocaleString()}`
                      : new Date(a.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => onDetails(a)}
                        className="flex items-center gap-1 text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors"
                      >
                        <Maximize2 className="w-3 h-3" /> Details
                      </button>
                      {variant === 'open' && onCloseCase && (
                        <button
                          onClick={() => onCloseCase(a)}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-700 transition-colors"
                        >
                          <CheckCircle2 className="w-3 h-3" /> Close case
                        </button>
                      )}
                      {variant === 'closed' && (
                        isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                      )}
                    </div>
                  </td>
                </tr>
                {variant === 'closed' && isExpanded && (
                  <tr className="bg-slate-50 dark:bg-slate-950/50 border-b border-slate-100 dark:border-slate-800/60">
                    <td colSpan={colCount} className="px-4 py-4">
                      {closure ? (
                        <div className="space-y-2">
                          <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 flex-shrink-0" />
                            <span className="text-slate-400 dark:text-slate-500">Reason: </span>{closure.reason}
                          </p>
                          <p className="text-xs text-slate-500 dark:text-slate-400 whitespace-pre-wrap pl-4">
                            <span className="text-slate-400 dark:text-slate-500">Evidence: </span>{closure.evidence}
                          </p>
                        </div>
                      ) : (
                        <p className="text-xs text-slate-400 dark:text-slate-500">No closure details recorded.</p>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default CaseTable;
