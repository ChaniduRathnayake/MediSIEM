// Shared between AdminDashboard.tsx and UserDashboard.tsx so the auditor
// role can reach it too. Read-only everywhere it's used.
import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, AlertCircle, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';
import { apiGetAuditLog } from '../../services/api';
import type { AuditLogEntry } from '../../types';

const auditActionLabel = (action: AuditLogEntry['action']) => {
  switch (action) {
    case 'create_user': return 'Created user';
    case 'update_user': return 'Updated user';
    case 'delete_user': return 'Deleted user';
    case 'create_device_group': return 'Created group';
    case 'update_device_group': return 'Updated group';
    case 'delete_device_group': return 'Deleted group';
    case 'update_device_groups': return 'Changed device groups';
    case 'update_device_os_category': return 'Changed OS category';
    case 'assign_alert': return 'Assigned alert';
    case 'unassign_alert': return 'Unassigned alert';
    case 'close_alert': return 'Closed case';
    case 'onboard_medical_device': return 'Onboarded device';
    case 'update_medical_device': return 'Updated device';
    case 'update_medical_device_groups': return 'Changed device groups';
    case 'delete_medical_device': return 'Removed device';
    case 'update_settings': return 'Updated integrations';
    case 'enable_mfa': return 'Enabled two-factor auth';
    case 'disable_mfa': return 'Disabled two-factor auth';
    case 'reset_password': return 'Reset password';
    default: return 'Updated';
  }
};

const auditActionBadge = (action: AuditLogEntry['action']) => {
  switch (action) {
    case 'create_user':
    case 'create_device_group':
    case 'onboard_medical_device':
    case 'enable_mfa':
      return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    case 'delete_user':
    case 'delete_device_group':
    case 'unassign_alert':
    case 'delete_medical_device':
    case 'disable_mfa':
      return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'update_device_groups':
    case 'update_device_os_category':
    case 'update_device_group':
    case 'assign_alert':
    case 'update_medical_device':
    case 'update_medical_device_groups':
      return 'text-violet-400 bg-violet-500/10 border-violet-500/30';
    case 'close_alert':
    case 'update_settings':
    case 'reset_password':
      return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
    default:
      return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
  }
};

type AuditSortKey = 'action' | 'actor' | 'target' | 'when';

const AuditLogPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [sortKey, setSortKey] = useState<AuditSortKey>('when');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    if (!token) {
      setError('Your session has expired. Please sign in again.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    apiGetAuditLog(token)
      .then((data) => setLogs(data.logs))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load audit log.'))
      .finally(() => setLoading(false));
  }, [token]);

  const toggleSort = (key: AuditSortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir(key === 'when' ? 'desc' : 'asc'); // newest-first by default; A→Z for text columns
    }
  };

  const sortedLogs = useMemo(() => {
    const list = [...logs];
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case 'action':
          cmp = auditActionLabel(a.action).localeCompare(auditActionLabel(b.action));
          break;
        case 'actor':
          cmp = (a.actor.name || a.actor.email || '').localeCompare(b.actor.name || b.actor.email || '');
          break;
        case 'target':
          cmp = (a.target.name || a.target.email || '').localeCompare(b.target.name || b.target.email || '');
          break;
        case 'when':
          cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [logs, sortKey, sortDir]);

  const SortHeader: React.FC<{ label: string; sortk: AuditSortKey }> = ({ label, sortk }) => (
    <th className="py-2.5 px-5 text-left">
      <button
        onClick={() => toggleSort(sortk)}
        className="flex items-center gap-1 text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider hover:text-slate-700 dark:text-slate-300 transition-colors"
      >
        {label}
        {sortKey === sortk ? (
          sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
        ) : (
          <ChevronsUpDown className="w-3 h-3 opacity-30" />
        )}
      </button>
    </th>
  );

  return (
    <div className="p-5 space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Audit Log</h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">What admins have done — user accounts, device groups, and OS categorization</p>
      </div>

      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading audit log…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : logs.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">No admin activity recorded yet.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <SortHeader label="Action" sortk="action" />
                <SortHeader label="Admin" sortk="actor" />
                <SortHeader label="Target" sortk="target" />
                <th className="py-2.5 px-5 text-left">Details</th>
                <SortHeader label="When" sortk="when" />
              </tr>
            </thead>
            <tbody>
              {sortedLogs.map((log) => (
                <tr key={log.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${auditActionBadge(log.action)}`}>
                      {auditActionLabel(log.action)}
                    </span>
                  </td>
                  <td className="py-3 px-5 text-sm text-slate-900 dark:text-white">{log.actor.name || log.actor.email || '—'}</td>
                  <td className="py-3 px-5 text-sm text-slate-500 dark:text-slate-400">{log.target.name || log.target.email || '—'}</td>
                  <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500">{log.details}</td>
                  <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                    {new Date(log.createdAt).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default AuditLogPanel;
