// Admin-wide case status view — every alert across all analysts, split into
// Open/Closed tabs. Complements AlertsPanel's raw monitoring view with a
// case-management lens (who resolved what, and why); admins can also close
// any case directly here, unlike analysts who are restricted to their own.
import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, AlertCircle, CheckCircle2, Clock, Siren, Download } from 'lucide-react';
import type { EnrichedAlert, AlertClosure } from '../../services/alertsApi';
import { apiCloseAlert } from '../../services/alertsApi';
import type { AlertVerdict } from '../../services/alertsApi';
import AlertDetailsModal from './AlertDetailsModal';
import CloseAlertModal from './CloseAlertModal';
import CaseTable from './CaseTable';
import { downloadCsv } from '../../utils/csv';
import { casToSeverity } from '../../utils/chartData';

const AdminCasesPanel: React.FC<{
  alerts: EnrichedAlert[];
  loading: boolean;
  error: string | null;
  token: string | null;
}> = ({ alerts, loading, error, token }) => {
  const [statusTab, setStatusTab] = useState<'open' | 'closed'>('open');
  const [detailsAlert, setDetailsAlert] = useState<EnrichedAlert | null>(null);
  const [closingAlert, setClosingAlert] = useState<EnrichedAlert | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Same reasoning as AlertsPanel's assignmentOverrides: live-pushed alerts
  // over Socket.IO don't carry `closure`, and a just-closed case should
  // reflect immediately without waiting on the next poll.
  const [closureOverrides, setClosureOverrides] = useState<Record<string, AlertClosure | null>>({});

  const closureOf = (a: EnrichedAlert): AlertClosure | null =>
    a.id in closureOverrides ? closureOverrides[a.id] : (a.closure ?? null);

  // The `escalated` flag on `alerts` is only ever correct as of the moment
  // GET /api/alerts last ran — alerts pushed live over Socket.IO never carry
  // it at all (alertPipeline.js doesn't compute it), and it never updates on
  // its own as an already-loaded alert ages past the 10-minute threshold
  // during a long-running session. Recomputing it here, ticking every 30s,
  // means a case actually flips to escalated in front of whoever's watching
  // instead of only ever reflecting whatever was true at the last page load.
  const ESCALATION_THRESHOLD_MS = 10 * 60 * 1000; // mirrors backend/routes/alerts.js
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(interval);
  }, []);

  const isEscalated = (a: EnrichedAlert): boolean =>
    casToSeverity(a.CAS) === 'CRITICAL' &&
    !a.assignedTo &&
    now - new Date(a.timestamp).getTime() >= ESCALATION_THRESHOLD_MS;

  const openCases = useMemo(
    () =>
      alerts
        .filter((a) => !closureOf(a))
        .map((a) => ({ ...a, escalated: isEscalated(a) }))
        // Escalated cases surface above everything else regardless of CAS,
        // since "has anyone even looked at this yet" matters more here than
        // the raw score.
        .sort((a, b) => Number(!!b.escalated) - Number(!!a.escalated) || b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, closureOverrides, now]
  );
  const escalatedCount = useMemo(() => openCases.filter((a) => a.escalated).length, [openCases]);

  // Client-side export — every column here is already loaded for the table
  // above, so there's no reason to round-trip the backend for a second copy
  // of the same data. Gives compliance/audit reviewers something to attach
  // to a report instead of screenshotting the table.
  const handleExportClosedCasesCsv = () => {
    const headers = [
      'Alert ID', 'Timestamp', 'Severity', 'CAS', 'Device', 'Device Type', 'Department',
      'Event', 'Action', 'Closed By', 'Closed By Email', 'Closed At', 'Reason', 'Evidence',
    ];
    const rows = closedCases.map((a) => {
      const closure = closureOf(a);
      return [
        a.id,
        a.timestamp,
        casToSeverity(a.CAS),
        a.CAS.toFixed(1),
        a.agent,
        a.deviceType ?? '',
        a.department,
        a.label !== 'Unclassified' ? a.label : a.ruleDescription,
        a.action,
        closure?.closedBy.name ?? '',
        closure?.closedBy.email ?? '',
        closure?.createdAt ?? '',
        closure?.reason ?? '',
        closure?.evidence ?? '',
      ];
    });
    downloadCsv(`medisiem-closed-cases-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };
  const closedCases = useMemo(
    () => alerts.filter((a) => !!closureOf(a)).sort((a, b) => b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, closureOverrides]
  );

  const handleSubmitClose = async (reason: string, evidence: string, verdict: AlertVerdict) => {
    if (!token || !closingAlert) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const { closure } = await apiCloseAlert(token, closingAlert.id, reason, evidence, verdict);
      setClosureOverrides((prev) => ({ ...prev, [closingAlert.id]: closure }));
      setClosingAlert(null);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Failed to close case.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="p-5">
        <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading alerts…
        </div>
      </div>
    );
  }

  if (error && alerts.length === 0) {
    return (
      <div className="p-5">
        <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Case Status</h2>
          <p className="text-xs text-slate-500 mt-0.5">Every alert across all analysts</p>
        </div>
        <div className="flex items-center gap-2.5">
          {escalatedCount > 0 && (
            <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-600/10 border border-red-600/30 text-red-500 dark:text-red-400 text-xs font-semibold">
              <Siren className="w-3.5 h-3.5" /> {escalatedCount} escalated
            </span>
          )}
          {statusTab === 'closed' && closedCases.length > 0 && (
            <button
              onClick={handleExportClosedCasesCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>
          )}
        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl w-fit">
          {([
            { id: 'open', label: 'Open Cases', count: openCases.length, icon: <Clock className="w-3.5 h-3.5" /> },
            { id: 'closed', label: 'Closed Cases', count: closedCases.length, icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
          ] as { id: 'open' | 'closed'; label: string; count: number; icon: React.ReactNode }[]).map((t) => (
            <button
              key={t.id}
              onClick={() => setStatusTab(t.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                statusTab === t.id
                  ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {t.icon}
              {t.label} ({t.count})
            </button>
          ))}
        </div>
        </div>
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {statusTab === 'open' ? (
          <CaseTable
            variant="open"
            alerts={openCases}
            allAlerts={alerts}
            closureOf={closureOf}
            showAssignedTo
            emptyMessage="No open cases — everything currently in the buffer has been closed."
            onDetails={setDetailsAlert}
            onCloseCase={(a) => { setSubmitError(null); setClosingAlert(a); }}
          />
        ) : (
          <CaseTable
            variant="closed"
            alerts={closedCases}
            allAlerts={alerts}
            closureOf={closureOf}
            showAssignedTo
            emptyMessage="No cases closed yet."
            onDetails={setDetailsAlert}
          />
        )}
      </div>

      {detailsAlert && <AlertDetailsModal kind="ml" alert={detailsAlert} onClose={() => setDetailsAlert(null)} token={token} />}
      {closingAlert && (
        <CloseAlertModal
          alertTitle={closingAlert.label !== 'Unclassified' ? closingAlert.label : closingAlert.ruleDescription}
          submitting={submitting}
          error={submitError}
          onClose={() => setClosingAlert(null)}
          onSubmit={handleSubmitClose}
          alertId={closingAlert.id}
          token={token}
        />
      )}
    </div>
  );
};

export default AdminCasesPanel;
