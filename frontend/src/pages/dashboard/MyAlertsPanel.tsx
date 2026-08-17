// SOC analyst's personal queue — Open Cases (with Close case) and Closed Cases (read-only).
import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, AlertCircle, CheckCircle2, Clock, Search, History, ChevronDown, ChevronRight, ClipboardCopy } from 'lucide-react';
import type { EnrichedAlert, AlertClosure, MyHistoryClosure } from '../../services/alertsApi';
import { apiCloseAlert, apiGetMyCaseHistory } from '../../services/alertsApi';
import type { AlertVerdict } from '../../services/alertsApi';
import AlertDetailsModal from './AlertDetailsModal';
import CloseAlertModal from './CloseAlertModal';
import CaseTable from './CaseTable';

// A closed case aged out of the live buffer — reconstructed from alertSnapshot, no full
// EnrichedAlert to hand to AlertDetailsModal.
const OlderMatchRow: React.FC<{ closure: MyHistoryClosure }> = ({ closure }) => {
  const [expanded, setExpanded] = useState(false);
  const snap = closure.alertSnapshot;
  return (
    <div className="border-b border-slate-100 dark:border-slate-800/60 last:border-b-0">
      <button onClick={() => setExpanded((v) => !v)} className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
        {expanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />}
        <span className="text-sm text-slate-700 dark:text-slate-300 truncate flex-1">{snap ? (snap.label !== 'Unclassified' ? snap.label : snap.ruleDescription) : closure.alertId}</span>
        <span className="text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap flex-shrink-0">{snap?.agent ?? '—'} · {new Date(closure.createdAt).toLocaleDateString()}</span>
      </button>
      {expanded && (
        <div className="px-4 pb-3 pl-10 space-y-1.5">
          <p className="text-xs text-slate-500 dark:text-slate-400"><span className="text-slate-400 dark:text-slate-500">Reason: </span>{closure.reason}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 whitespace-pre-wrap"><span className="text-slate-400 dark:text-slate-500">Evidence: </span>{closure.evidence}</p>
        </div>
      )}
    </div>
  );
};

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

  // Covers both what's loaded (instant, client-side) and, once there's a real query, the
  // permanent record via /my-history — a case may have aged out of the live buffer entirely.
  const [historySearch, setHistorySearch] = useState('');
  const [olderMatches, setOlderMatches] = useState<MyHistoryClosure[]>([]);
  const [searchingHistory, setSearchingHistory] = useState(false);

  const visibleClosedCases = useMemo(() => {
    const q = historySearch.trim().toLowerCase();
    if (!q) return closedCases;
    return closedCases.filter((a) => {
      const closure = closureOf(a);
      const haystack = `${a.label} ${a.ruleDescription} ${a.agent} ${closure?.reason ?? ''} ${closure?.evidence ?? ''}`.toLowerCase();
      return haystack.includes(q);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    });
  }, [closedCases, historySearch, closureOverrides]);

  useEffect(() => {
    const q = historySearch.trim();
    if (!token || q.length < 2) { setOlderMatches([]); return; }
    let cancelled = false;
    setSearchingHistory(true);
    const timer = setTimeout(() => {
      apiGetMyCaseHistory(token, q)
        .then(({ closures }) => {
          if (cancelled) return;
          const loadedIds = new Set(mine.map((a) => a.id));
          setOlderMatches(closures.filter((c) => !loadedIds.has(c.alertId)));
        })
        .catch(() => { if (!cancelled) setOlderMatches([]); })
        .finally(() => { if (!cancelled) setSearchingHistory(false); });
    }, 300);
    return () => { cancelled = true; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [historySearch, token]);

  const [copiedSummary, setCopiedSummary] = useState(false);
  const copyShiftSummary = () => {
    const now = new Date();
    const critical = openCases.filter((a) => a.CAS >= 8).length;
    const lines = [
      `MediSIEM shift handoff — ${now.toLocaleString()}`,
      `${openCases.length} open case${openCases.length === 1 ? '' : 's'} assigned to me${critical > 0 ? ` (${critical} CRITICAL)` : ''}`,
      '',
      ...openCases.slice(0, 25).map((a) => {
        const label = a.label !== 'Unclassified' ? a.label : a.ruleDescription;
        const flags = [a.escalated ? 'ESCALATED' : null, a.CAS >= 8 ? 'CRITICAL' : null].filter(Boolean).join(', ');
        return `- [CAS ${a.CAS.toFixed(1)}${flags ? ` · ${flags}` : ''}] ${label} — ${a.agent} (${a.department})`;
      }),
      openCases.length > 25 ? `…and ${openCases.length - 25} more` : '',
    ].filter(Boolean);
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2500);
    }).catch(() => {});
  };

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
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">My Assigned Alerts</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Cases assigned to you · {openCases.length} open · {closedCases.length} closed
          </p>
        </div>
        {openCases.length > 0 && (
          <button
            onClick={copyShiftSummary}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            {copiedSummary ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> : <ClipboardCopy className="w-3.5 h-3.5" />}
            {copiedSummary ? 'Copied!' : 'Copy shift summary'}
          </button>
        )}
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          <Clock className="w-4 h-4 text-amber-500 dark:text-amber-400" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Open Cases</h3>
          <span className="text-xs text-slate-400 dark:text-slate-500">({openCases.length})</span>
        </div>
        <CaseTable
          variant="open"
          alerts={openCases}
          allAlerts={alerts}
          closureOf={closureOf}
          showAssignedTo={false}
          emptyMessage="You're all caught up — no open cases."
          onDetails={setDetailsAlert}
          onCloseCase={(a) => { setSubmitError(null); setClosingAlert(a); }}
        />
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex-wrap">
          <CheckCircle2 className="w-4 h-4 text-emerald-500 dark:text-emerald-400 flex-shrink-0" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Closed Cases</h3>
          <span className="text-xs text-slate-400 dark:text-slate-500">({closedCases.length})</span>
          <div className="relative ml-auto">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
            <input
              value={historySearch}
              onChange={(e) => setHistorySearch(e.target.value)}
              placeholder="Search your case history…"
              className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-56"
            />
          </div>
        </div>
        <CaseTable
          variant="closed"
          alerts={visibleClosedCases}
          allAlerts={alerts}
          closureOf={closureOf}
          showAssignedTo={false}
          emptyMessage={
            historySearch.trim()
              ? 'No currently-loaded closed cases match that search.'
              : 'No cases closed yet — closed cases (with your reason and evidence) will appear here for future reference.'
          }
          onDetails={setDetailsAlert}
        />
        {historySearch.trim().length >= 2 && (
          <div className="border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2 px-4 py-2.5 bg-slate-50 dark:bg-slate-950/40">
              <History className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Older matches — not in the current buffer</span>
              {searchingHistory && <Loader2 className="w-3 h-3 animate-spin text-slate-400" />}
            </div>
            {!searchingHistory && olderMatches.length === 0 ? (
              <p className="text-xs text-slate-400 dark:text-slate-500 px-4 py-3">No older cases match.</p>
            ) : (
              olderMatches.map((c) => <OlderMatchRow key={c.id} closure={c} />)
            )}
          </div>
        )}
      </div>

      {detailsAlert && <AlertDetailsModal kind="ml" alert={detailsAlert} onClose={() => setDetailsAlert(null)} token={token} allAlerts={alerts} />}
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

export default MyAlertsPanel;
