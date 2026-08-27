// Port of components/IntelligenceLists.jsx — organization-managed allow /
// watch / block intelligence, with entry removal.
import React, { useCallback, useEffect, useState } from 'react';
import { getAllLists, removeListEntry } from './ipReputationApi';
import type { ListEntry } from './ipReputationApi';
import { useToast } from '../../../context/ToastContext';
import { useAuth } from '../../../context/AuthContext';
import { SectionCard, Badge, EmptyNotice, ErrorBanner, LoadingBlock, RefreshButton, fmtDateTime, toneOf } from './shared';

const IntelligenceListsView: React.FC = () => {
  const { showToast } = useToast();
  const { user } = useAuth();
  const actor = user?.email || user?.name || 'unknown-analyst';
  const [items, setItems] = useState<ListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadLists = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await getAllLists();
      setItems(data.items || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to load intelligence lists.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLists();
  }, [loadLists]);

  const removeEntry = async (listType: string, ip: string) => {
    const confirmed = window.confirm(`Remove ${ip} from ${listType} list?`);
    if (!confirmed) return;

    try {
      await removeListEntry(listType, ip, actor);
      showToast({ title: 'Entry removed', message: `${ip} removed from ${listType} list.`, severity: 'info' });
      await loadLists();
    } catch (err: unknown) {
      showToast({ title: 'Removal failed', message: err instanceof Error ? err.message : 'Unable to remove list entry.', severity: 'high' });
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">Intelligence Lists</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Organization-managed allow, watch and block intelligence.</p>
        </div>
        <RefreshButton onClick={() => void loadLists()} loading={loading} />
      </div>

      {error && <ErrorBanner message={error} />}

      {loading && items.length === 0 ? (
        <LoadingBlock label="Loading intelligence lists…" />
      ) : items.length === 0 ? (
        <SectionCard>
          <EmptyNotice>No internal intelligence entries exist yet.</EmptyNotice>
        </SectionCard>
      ) : (
        <SectionCard>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full min-w-[720px]">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2 px-2 text-left">IP Address</th>
                  <th className="py-2 px-2 text-left">List</th>
                  <th className="py-2 px-2 text-left">Analyst</th>
                  <th className="py-2 px-2 text-left">Reason</th>
                  <th className="py-2 px-2 text-left">Updated</th>
                  <th className="py-2 px-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item._id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                    <td className="py-2 px-2 font-medium text-slate-900 dark:text-white">{item.ip}</td>
                    <td className="py-2 px-2">
                      <Badge tone={toneOf(item.list_type)}>{item.list_type}</Badge>
                    </td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{item.actor}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{item.reason || '—'}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(item.updated_at)}</td>
                    <td className="py-2 px-2 text-right">
                      <button
                        onClick={() => void removeEntry(item.list_type, item.ip)}
                        className="text-xs text-red-600 dark:text-red-400 hover:text-red-500 dark:hover:text-red-300 font-medium"
                      >
                        Remove
                      </button>
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

export default IntelligenceListsView;
