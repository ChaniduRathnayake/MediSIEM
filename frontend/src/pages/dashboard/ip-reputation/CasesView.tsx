// Port of components/CasesPage.jsx — IP-reputation-scoped investigation cases
// stored in the FastAPI service's own `cases` Mongo collection
// (medshield_ip_reputation database). NOT the same feature as MediSIEM's
// existing AdminCasesPanel.tsx incident-case tool (different data model,
// different collection, different database) — kept fully separate here.
import React, { useCallback, useEffect, useState } from 'react';
import { listCases, updateCaseStatus } from './ipReputationApi';
import type { CaseItem } from './ipReputationApi';
import { useToast } from '../../../context/ToastContext';
import { useAuth } from '../../../context/AuthContext';
import { SectionCard, Badge, EmptyNotice, ErrorBanner, LoadingBlock, RefreshButton, fmtDateTime, toneOf } from './shared';

const CasesView: React.FC = () => {
  const { showToast } = useToast();
  // The real logged-in analyst, not a hardcoded placeholder — this feeds the
  // FastAPI service's audit_collection, so a fixed fake actor here would
  // misattribute every case status change regardless of who actually made it.
  const { user } = useAuth();
  const actor = user?.email || user?.name || 'unknown-analyst';
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadCases = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await listCases(100);
      setCases(data.cases || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to load cases.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCases();
  }, [loadCases]);

  const changeStatus = async (caseId: string, newStatus: string) => {
    const reason = window.prompt(`Reason for changing case status to ${newStatus}:`, 'Updated from MedShield case management');
    if (reason === null) return;

    try {
      await updateCaseStatus(caseId, { status: newStatus, reason, actor });
      showToast({ title: 'Case updated', message: `Case status changed to ${newStatus}.`, severity: 'info' });
      await loadCases();
    } catch (err: unknown) {
      showToast({ title: 'Update failed', message: err instanceof Error ? err.message : 'Unable to update case status.', severity: 'high' });
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <span className="text-[10px] font-semibold tracking-wider text-cyan-600 dark:text-cyan-400 uppercase">MedShield Case Management</span>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mt-0.5">Investigation Cases</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Persistent analyst investigations created from MedShield security intelligence.</p>
        </div>
        <RefreshButton onClick={() => void loadCases()} loading={loading} />
      </div>

      {error && <ErrorBanner message={error} />}

      {loading && cases.length === 0 ? (
        <LoadingBlock label="Loading cases…" />
      ) : cases.length === 0 ? (
        <SectionCard>
          <EmptyNotice>No investigation cases exist yet.</EmptyNotice>
        </SectionCard>
      ) : (
        <SectionCard>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full min-w-[920px]">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2 px-2 text-left">Case</th>
                  <th className="py-2 px-2 text-left">IP Address</th>
                  <th className="py-2 px-2 text-left">Severity</th>
                  <th className="py-2 px-2 text-left">Status</th>
                  <th className="py-2 px-2 text-left">Reputation</th>
                  <th className="py-2 px-2 text-left">Updated</th>
                  <th className="py-2 px-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((item) => (
                  <tr key={item._id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm align-top">
                    <td className="py-2.5 px-2">
                      <p className="font-medium text-slate-900 dark:text-white">{item.title}</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500">{item.description || 'No description'}</p>
                    </td>
                    <td className="py-2.5 px-2 font-medium text-slate-900 dark:text-white whitespace-nowrap">{item.ip}</td>
                    <td className="py-2.5 px-2">
                      <Badge tone={toneOf(item.severity)}>{item.severity}</Badge>
                    </td>
                    <td className="py-2.5 px-2">
                      <Badge tone={toneOf(item.status)}>{item.status}</Badge>
                    </td>
                    <td className="py-2.5 px-2">
                      <p className="font-medium text-slate-900 dark:text-white">{item.reputation_snapshot?.risk_level || 'Unknown'}</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500">Score: {item.reputation_snapshot?.score ?? '—'}</p>
                    </td>
                    <td className="py-2.5 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(item.updated_at)}</td>
                    <td className="py-2.5 px-2">
                      <div className="flex flex-col gap-1 items-end">
                        {item.status !== 'in_progress' && (
                          <button onClick={() => void changeStatus(item._id, 'in_progress')} className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-medium">
                            Investigate
                          </button>
                        )}
                        {item.status !== 'resolved' && (
                          <button onClick={() => void changeStatus(item._id, 'resolved')} className="text-xs text-emerald-600 dark:text-emerald-400 hover:text-emerald-500 dark:hover:text-emerald-300 font-medium">
                            Resolve
                          </button>
                        )}
                        {item.status !== 'closed' && (
                          <button onClick={() => void changeStatus(item._id, 'closed')} className="text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white font-medium">
                            Close
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}
    </div>
  );
};

export default CasesView;
