// Port of components/AuditPage.jsx — immutable record of analyst and
// intelligence actions.
import React, { useCallback, useEffect, useState } from 'react';
import { getAuditEvents } from './ipReputationApi';
import type { AuditEvent } from './ipReputationApi';
import { SectionCard, EmptyNotice, ErrorBanner, LoadingBlock, RefreshButton, fmtDateTime } from './shared';

const AuditView: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await getAuditEvents(100);
      setEvents(data.events || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to load audit trail.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAudit();
  }, [loadAudit]);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">Audit Trail</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Immutable record of analyst and intelligence actions.</p>
        </div>
        <RefreshButton onClick={() => void loadAudit()} loading={loading} />
      </div>

      {error && <ErrorBanner message={error} />}

      {loading && events.length === 0 ? (
        <LoadingBlock label="Loading audit trail…" />
      ) : events.length === 0 ? (
        <SectionCard>
          <EmptyNotice>No audit events recorded.</EmptyNotice>
        </SectionCard>
      ) : (
        <SectionCard>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full min-w-[880px]">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2 px-2 text-left">Time</th>
                  <th className="py-2 px-2 text-left">Actor</th>
                  <th className="py-2 px-2 text-left">Action</th>
                  <th className="py-2 px-2 text-left">Subject</th>
                  <th className="py-2 px-2 text-left">Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event._id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm align-top">
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(event.created_at)}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{event.actor || 'system'}</td>
                    <td className="py-2 px-2 font-medium text-slate-900 dark:text-white whitespace-nowrap">{event.action}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{event.subject || '—'}</td>
                    <td className="py-2 px-2 text-xs text-slate-400 dark:text-slate-500 font-mono break-all max-w-xs">
                      {event.details ? JSON.stringify(event.details) : '—'}
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

export default AuditView;
