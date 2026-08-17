// Shared row-rendering for a list of cases, in one of two fixed variants —
// 'open' (has a Close action) or 'closed' (expandable reason/evidence).
// Used by both MyAlertsPanel and AdminCasesPanel so open/closed sections
// look and behave identically everywhere.
import React, { useState } from 'react';
import { Inbox, CheckCircle2, Maximize2, ChevronRight, ChevronDown, Siren, GitBranch } from 'lucide-react';
import type { EnrichedAlert, AlertClosure } from '../../services/alertsApi';
import { casToSeverity } from '../../utils/chartData';
import SeverityBadge from '../../components/SeverityBadge';

// "Kill-chain" grouping window for the Related activity strip — no backend
// Case model groups alerts (see alertPipeline.js/routes/alerts.js: a case is
// just one alert plus its assignment/closure state), so this is a purely
// client-side read of "what else happened on this device recently",
// computed from whatever's already loaded rather than a real incident graph.
const RELATED_ACTIVITY_WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours
const MAX_RELATED_SHOWN = 8;

function relatedActivity(alert: EnrichedAlert, allAlerts: EnrichedAlert[]): EnrichedAlert[] {
  const t = new Date(alert.timestamp).getTime();
  return allAlerts
    .filter((a) => a.id !== alert.id && a.agent === alert.agent && Math.abs(new Date(a.timestamp).getTime() - t) <= RELATED_ACTIVITY_WINDOW_MS)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

const RelatedActivityStrip: React.FC<{ alert: EnrichedAlert; allAlerts: EnrichedAlert[]; onDetails: (a: EnrichedAlert) => void }> = ({ alert, allAlerts, onDetails }) => {
  const related = relatedActivity(alert, allAlerts);
  if (related.length === 0) {
    return (
      <p className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1.5">
        <GitBranch className="w-3 h-3 flex-shrink-0" /> No other activity on this device within 2 hours of this alert.
      </p>
    );
  }
  const shown = related.slice(0, MAX_RELATED_SHOWN);
  return (
    <div>
      <p className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1.5 mb-2">
        <GitBranch className="w-3 h-3 flex-shrink-0" />
        {related.length} other alert{related.length === 1 ? '' : 's'} on {alert.agent} within 2 hours — earliest first
      </p>
      <div className="flex items-stretch gap-2 overflow-x-auto pb-1">
        {shown.map((r) => {
          const sev = casToSeverity(r.CAS);
          const tactic = r.mitre?.tactic?.[0];
          return (
            <button
              key={r.id}
              onClick={() => onDetails(r)}
              className="flex-shrink-0 w-40 text-left rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-cyan-500/40 px-2.5 py-2 transition-colors"
            >
              <div className="flex items-center justify-between gap-1">
                <SeverityBadge severity={sev} />
                <span className="text-[10px] text-slate-400 dark:text-slate-600 whitespace-nowrap">
                  {new Date(r.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
              <p className="text-xs text-slate-700 dark:text-slate-300 mt-1 truncate" title={r.label !== 'Unclassified' ? r.label : r.ruleDescription}>
                {r.label !== 'Unclassified' ? r.label : r.ruleDescription}
              </p>
              {tactic && (
                <span className="inline-block mt-1 text-[10px] px-1.5 py-0.5 rounded-full bg-violet-500/10 text-violet-600 dark:text-violet-400 border border-violet-500/30 truncate max-w-full">
                  {tactic}
                </span>
              )}
            </button>
          );
        })}
        {related.length > MAX_RELATED_SHOWN && (
          <div className="flex-shrink-0 w-24 flex items-center justify-center text-xs text-slate-400 dark:text-slate-500">
            +{related.length - MAX_RELATED_SHOWN} more
          </div>
        )}
      </div>
    </div>
  );
};

const CaseTable: React.FC<{
  variant: 'open' | 'closed';
  alerts: EnrichedAlert[];
  // Unfiltered alert set (open + closed + everything else currently
  // loaded) — used only to compute each row's Related activity strip,
  // which should look across every case, not just the ones in this table.
  allAlerts: EnrichedAlert[];
  closureOf: (a: EnrichedAlert) => AlertClosure | null;
  showAssignedTo: boolean;
  emptyMessage: string;
  onDetails: (a: EnrichedAlert) => void;
  onCloseCase?: (a: EnrichedAlert) => void;
}> = ({ variant, alerts, allAlerts, closureOf, showAssignedTo, emptyMessage, onDetails, onCloseCase }) => {
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
                  onClick={() => setExpandedId(isExpanded ? null : a.id)}
                  className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors cursor-pointer"
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
                    <span className="inline-flex items-center gap-1.5">
                      {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                      {(a.duplicateCount ?? 1) > 1 && (
                        <span
                          title={`Repeated ${a.duplicateCount}× within a short window — collapsed into one row`}
                          className="flex-shrink-0 text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                        >
                          ×{a.duplicateCount}
                        </span>
                      )}
                    </span>
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
                      {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />}
                    </div>
                  </td>
                </tr>
                {isExpanded && (
                  <tr className="bg-slate-50 dark:bg-slate-950/50 border-b border-slate-100 dark:border-slate-800/60">
                    <td colSpan={colCount} className="px-4 py-4 space-y-3">
                      {variant === 'closed' && (
                        closure ? (
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
                        )
                      )}
                      <RelatedActivityStrip alert={a} allAlerts={allAlerts} onDetails={onDetails} />
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
