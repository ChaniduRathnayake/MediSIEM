// frontend/src/pages/dashboard/AdminCasesPanel.tsx
//
// Admin-wide view of case status — every alert across all analysts, split
// into an Open Cases / Closed Cases tab switcher. Complements AlertsPanel
// (the raw CAS-ranked/severity monitoring view) with a case-management lens:
// what's still being worked vs. what's been resolved, by whom, and why —
// the Closed Cases tab surfaces each analyst's recorded reason + evidence
// for admin oversight. Admins can also close a case directly from here (the
// backend allows admin to close any alert, assigned or not — analysts are
// restricted to their own assignments).
import React, { useMemo, useState } from 'react';
import { Loader2, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import type { EnrichedAlert, AlertClosure } from '../../services/alertsApi';
import { apiCloseAlert } from '../../services/alertsApi';
import AlertDetailsModal from './AlertDetailsModal';
import CloseAlertModal from './CloseAlertModal';
import CaseTable from './CaseTable';

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

  const openCases = useMemo(
    () => alerts.filter((a) => !closureOf(a)).sort((a, b) => b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, closureOverrides]
  );
  const closedCases = useMemo(
    () => alerts.filter((a) => !!closureOf(a)).sort((a, b) => b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, closureOverrides]
  );

  const handleSubmitClose = async (reason: string, evidence: string) => {
    if (!token || !closingAlert) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const { closure } = await apiCloseAlert(token, closingAlert.id, reason, evidence);
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

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {statusTab === 'open' ? (
          <CaseTable
            variant="open"
            alerts={openCases}
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
            closureOf={closureOf}
            showAssignedTo
            emptyMessage="No cases closed yet."
            onDetails={setDetailsAlert}
          />
        )}
      </div>

      {detailsAlert && <AlertDetailsModal kind="ml" alert={detailsAlert} onClose={() => setDetailsAlert(null)} />}
      {closingAlert && (
        <CloseAlertModal
          alertTitle={closingAlert.label !== 'Unclassified' ? closingAlert.label : closingAlert.ruleDescription}
          submitting={submitting}
          error={submitError}
          onClose={() => setClosingAlert(null)}
          onSubmit={handleSubmitClose}
        />
      )}
    </div>
  );
};

export default AdminCasesPanel;
