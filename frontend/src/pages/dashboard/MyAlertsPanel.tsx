// frontend/src/pages/dashboard/MyAlertsPanel.tsx
//
// SOC analyst's personal queue: only alerts assigned to them, split into two
// always-visible sections — Open Cases (with the Close case action) and
// Closed Cases (read-only, reason + evidence kept as a permanent record) —
// rather than a single filtered table, so an analyst's own resolution
// history stays visible alongside their open work.
import React, { useMemo, useState } from 'react';
import { Loader2, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import type { EnrichedAlert, AlertClosure } from '../../services/alertsApi';
import { apiCloseAlert } from '../../services/alertsApi';
import AlertDetailsModal from './AlertDetailsModal';
import CloseAlertModal from './CloseAlertModal';
import CaseTable from './CaseTable';

const MyAlertsPanel: React.FC<{
  alerts: EnrichedAlert[];
  loading: boolean;
  error: string | null;
  token: string | null;
  userId?: string;
}> = ({ alerts, loading, error, token, userId }) => {
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

  const mine = useMemo(
    () => (userId ? alerts.filter((a) => a.assignedTo?.id === userId) : []),
    [alerts, userId]
  );

  const openCases = useMemo(
    () => mine.filter((a) => !closureOf(a)).sort((a, b) => b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [mine, closureOverrides]
  );
  const closedCases = useMemo(
    () => mine.filter((a) => !!closureOf(a)).sort((a, b) => b.CAS - a.CAS),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [mine, closureOverrides]
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

  if (error && mine.length === 0) {
    return (
      <div className="p-5">
        <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">My Assigned Alerts</h2>
        <p className="text-xs text-slate-500 mt-0.5">
          Cases assigned to you · {openCases.length} open · {closedCases.length} closed
        </p>
      </div>

      {/* ── Open Cases ── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          <Clock className="w-4 h-4 text-amber-500 dark:text-amber-400" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Open Cases</h3>
          <span className="text-xs text-slate-400 dark:text-slate-500">({openCases.length})</span>
        </div>
        <CaseTable
          variant="open"
          alerts={openCases}
          closureOf={closureOf}
          showAssignedTo={false}
          emptyMessage="You're all caught up — no open cases."
          onDetails={setDetailsAlert}
          onCloseCase={(a) => { setSubmitError(null); setClosingAlert(a); }}
        />
      </div>

      {/* ── Closed Cases ── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          <CheckCircle2 className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Closed Cases</h3>
          <span className="text-xs text-slate-400 dark:text-slate-500">({closedCases.length})</span>
        </div>
        <CaseTable
          variant="closed"
          alerts={closedCases}
          closureOf={closureOf}
          showAssignedTo={false}
          emptyMessage="No cases closed yet — closed cases (with your reason and evidence) will appear here for future reference."
          onDetails={setDetailsAlert}
        />
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

export default MyAlertsPanel;
