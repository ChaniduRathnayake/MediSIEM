import React, { useEffect, useMemo, useRef, useState } from 'react';
import WazuhDashboard from './WazuhDashboard';
import { WazuhProvider, useWazuhContext } from './WazuhContext';
import { normalizeAgentStatus, formatOs, inferOsCategory, OS_CATEGORY_LABELS } from './wazuhApi';
import type { WazuhAgent, OsCategory } from './wazuhApi';
import { useDeviceMeta } from './useDeviceMeta';
import type { DeviceGroup } from './deviceApi';
import AgentDetailsModal from './AgentDetailsModal';
import CompliancePanel from './CompliancePanel';
import type { FrameworkTab } from './CompliancePanel';
import { hasIndexerConfig, searchAlerts } from './complianceApi';
import type { WazuhAlertRow } from './complianceApi';
import {
  Shield, Activity, AlertTriangle, Users, Server, Bell,
  Settings, ChevronDown, Menu, X, BarChart3,
  TrendingUp, Network, Zap, CheckCircle,
  Clock, AlertCircle, Database, Plus, Loader2, Mail, Lock, Pencil, Trash2, RefreshCw,
  Tag, Filter, ChevronUp, ChevronsUpDown, ShieldCheck, Globe, ClipboardCheck,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { apiGetAllUsers, apiCreateUser, apiUpdateUser, apiDeleteUser, apiGetAuditLog } from '../../services/api';
import type { User as MediUser, AuditLogEntry } from '../../types';
import AccountMenu from '../../components/AccountMenu';

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  color: string;
  trend?: string;
}> = ({ icon, label, value, sub, color, trend }) => (
  <div className={`p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-${color}-500/30 transition-all`}>
    <div className="flex items-start justify-between mb-3">
      <div className={`w-10 h-10 rounded-xl bg-${color}-500/10 flex items-center justify-center`}>{icon}</div>
      {trend && (
        <span className={`text-xs px-2 py-0.5 rounded-full ${trend.startsWith('+') ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
          {trend}
        </span>
      )}
    </div>
    <div className="text-2xl font-black text-white mb-0.5">{value}</div>
    <div className="text-xs font-medium text-slate-300">{label}</div>
    <div className="text-xs text-slate-500 mt-0.5">{sub}</div>
  </div>
);

// ─── Alert Row ────────────────────────────────────────────────────────────────
const AlertRow: React.FC<{
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  device: string;
  event: string;
  cas: number;
  time: string;
  status: 'Open' | 'Investigating' | 'Resolved';
}> = ({ severity, device, event, cas, time, status }) => {
  const sevColor: Record<string, string> = {
    CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
    HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  };
  const statusColor: Record<string, string> = {
    Open: 'text-red-400',
    Investigating: 'text-amber-400',
    Resolved: 'text-emerald-400',
  };
  return (
    <tr className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
      <td className="py-3 px-4">
        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sevColor[severity]}`}>{severity}</span>
      </td>
      <td className="py-3 px-4 text-sm text-slate-300 font-mono">{device}</td>
      <td className="py-3 px-4 text-sm text-slate-400 max-w-xs truncate">{event}</td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-slate-700 rounded-full h-1.5 w-16">
            <div
              className={`h-1.5 rounded-full ${cas >= 8 ? 'bg-red-500' : cas >= 6 ? 'bg-orange-500' : cas >= 4 ? 'bg-amber-500' : 'bg-blue-500'}`}
              style={{ width: `${(cas / 10) * 100}%` }}
            />
          </div>
          <span className="text-xs font-mono text-slate-400">{cas.toFixed(1)}</span>
        </div>
      </td>
      <td className="py-3 px-4 text-xs text-slate-500">{time}</td>
      <td className="py-3 px-4">
        <span className={`text-xs font-medium ${statusColor[status]}`}>{status}</span>
      </td>
    </tr>
  );
};

const MOCK_ALERTS = [
  { severity: 'CRITICAL' as const, device: 'ICU-VENT-04', event: 'Unauthorised firmware modification detected', cas: 9.6, time: '2 min ago', status: 'Open' as const },
  { severity: 'HIGH' as const, device: 'INF-PUMP-12', event: 'Anomalous network traffic to external IP', cas: 7.8, time: '8 min ago', status: 'Investigating' as const },
  { severity: 'HIGH' as const, device: 'CARDIAC-MON-7', event: 'Failed authentication — brute force pattern', cas: 7.2, time: '15 min ago', status: 'Investigating' as const },
  { severity: 'MEDIUM' as const, device: 'WORKSTATION-ER', event: 'Unusual process execution via PowerShell', cas: 5.4, time: '31 min ago', status: 'Open' as const },
  { severity: 'LOW' as const, device: 'NURSE-STATION-3', event: 'Port scan from internal subnet', cas: 2.1, time: '1 hr ago', status: 'Resolved' as const },
];

// ─── Users Panel ────────────────────────────────────────────────────────────
const roleLabel = (role: string) => (role === 'admin' ? 'Admin' : 'SOC Analyst');

const UserFormModal: React.FC<{
  mode: 'create' | 'edit';
  initial?: MediUser;
  onClose: () => void;
  onSaved: (user: MediUser) => void;
  token: string | null;
}> = ({ mode, initial, onClose, onSaved, token }) => {
  const [form, setForm] = useState({
    name: initial?.name ?? '',
    email: initial?.email ?? '',
    password: '',
    role: (initial?.role ?? 'user') as 'admin' | 'user',
  });
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.email || (mode === 'create' && !form.password)) {
      setError('Name, email and password are required.');
      return;
    }
    if (form.password && form.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (!token) {
      setError('Your session has expired. Please sign in again.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      if (mode === 'create') {
        const { user } = await apiCreateUser(token, { name: form.name, email: form.email, password: form.password, role: form.role });
        onSaved(user);
      } else {
        const { user } = await apiUpdateUser(token, initial!.id, {
          name: form.name,
          email: form.email,
          role: form.role,
          ...(form.password ? { password: form.password } : {}),
        });
        onSaved(user);
      }
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to ${mode === 'create' ? 'create' : 'update'} user.`);
    } finally {
      setSubmitting(false);
    }
  };

  const input =
    'w-full pl-10 pr-3 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white ' +
    'placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <h2 className="text-sm font-bold text-white">{mode === 'create' ? 'Add User' : 'Edit User'}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Full name</label>
            <div className="relative">
              <Users className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
              <input
                className={input}
                value={form.name}
                onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
                placeholder="Jane Perera"
                autoComplete="off"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Email address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
              <input
                type="email"
                className={input}
                value={form.email}
                onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))}
                placeholder="analyst@medisiem.com"
                autoComplete="off"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">
              {mode === 'create' ? 'Temporary password' : 'New password'}
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
              <input
                type="password"
                className={input}
                value={form.password}
                onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))}
                placeholder={mode === 'create' ? '••••••••' : 'Leave blank to keep current password'}
                autoComplete="new-password"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Role</label>
            <div className="grid grid-cols-2 gap-2">
              {(['user', 'admin'] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setForm((p) => ({ ...p, role: r }))}
                  className={`px-3 py-2.5 rounded-lg text-sm font-medium border transition-all ${
                    form.role === r
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-white'
                  }`}
                >
                  {roleLabel(r)}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2.5 mt-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold text-sm rounded-lg transition-all"
          >
            {submitting ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> {mode === 'create' ? 'Creating…' : 'Saving…'}</>
            ) : mode === 'create' ? (
              <><Plus className="w-4 h-4" /> Create User</>
            ) : (
              <><Pencil className="w-4 h-4" /> Save Changes</>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

type UserModalState = { mode: 'create' } | { mode: 'edit'; user: MediUser } | null;

const ConfirmDeleteModal: React.FC<{
  user: MediUser;
  token: string | null;
  onClose: () => void;
  onDeleted: (id: string) => void;
}> = ({ user, token, onClose, onDeleted }) => {
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleDelete = async () => {
    if (!token) {
      setError('Your session has expired. Please sign in again.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await apiDeleteUser(token, user.id);
      onDeleted(user.id);
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete user.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <h2 className="text-sm font-bold text-white">Delete User</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <p className="text-sm text-slate-300">
            Permanently delete <span className="font-semibold text-white">{user.name}</span> ({user.email})? This cannot be undone.
          </p>

          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="flex-1 py-2.5 rounded-lg text-sm font-medium text-slate-300 bg-slate-800 border border-slate-700 hover:bg-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleDelete}
              disabled={submitting}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-white bg-red-500 hover:bg-red-400 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Deleting…</> : 'Delete'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const UsersPanel: React.FC<{ token: string | null; currentUserId?: string }> = ({ token, currentUserId }) => {
  const [users, setUsers] = useState<MediUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [modal, setModal] = useState<UserModalState>(null);
  const [deleteTarget, setDeleteTarget] = useState<MediUser | null>(null);

  const loadUsers = () => {
    if (!token) {
      setError('Your session has expired. Please sign in again.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    apiGetAllUsers(token)
      .then((data) => setUsers(data.users))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load users.'))
      .finally(() => setLoading(false));
  };

  useEffect(loadUsers, [token]);

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Users</h2>
          <p className="text-xs text-slate-500 mt-0.5">Manage admin and SOC analyst accounts</p>
        </div>
        <button
          onClick={() => setModal({ mode: 'create' })}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-sm font-semibold transition-colors"
        >
          <Plus className="w-4 h-4" /> Add User
        </button>
      </div>

      <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading users…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : users.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-14">No users yet.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                <th className="py-2.5 px-5 text-left">Name</th>
                <th className="py-2.5 px-5 text-left">Email</th>
                <th className="py-2.5 px-5 text-left">Role</th>
                <th className="py-2.5 px-5 text-left">Joined</th>
                <th className="py-2.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5">
                    <div className="flex items-center gap-3">
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white flex-shrink-0 ${
                        u.role === 'admin' ? 'bg-gradient-to-br from-red-400 to-orange-500' : 'bg-gradient-to-br from-cyan-500 to-blue-600'
                      }`}>
                        {u.name?.[0]?.toUpperCase()}
                      </div>
                      <span className="text-sm text-white font-medium">
                        {u.name}{u.id === currentUserId && <span className="text-slate-500 font-normal"> (you)</span>}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-5 text-sm text-slate-400">{u.email}</td>
                  <td className="py-3 px-5">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${
                      u.role === 'admin'
                        ? 'text-red-400 bg-red-500/10 border-red-500/30'
                        : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
                    }`}>
                      {roleLabel(u.role)}
                    </span>
                  </td>
                  <td className="py-3 px-5 text-xs text-slate-500">
                    {u.createdAt ? new Date(u.createdAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '—'}
                  </td>
                  <td className="py-3 px-5 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setModal({ mode: 'edit', user: u })}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" /> Edit
                      </button>
                      {u.id !== currentUserId && (
                        <button
                          onClick={() => setDeleteTarget(u)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" /> Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <UserFormModal
          mode={modal.mode}
          initial={modal.mode === 'edit' ? modal.user : undefined}
          token={token}
          onClose={() => setModal(null)}
          onSaved={(u) =>
            setUsers((prev) =>
              modal.mode === 'create' ? [u, ...prev] : prev.map((existing) => (existing.id === u.id ? u : existing))
            )
          }
        />
      )}

      {deleteTarget && (
        <ConfirmDeleteModal
          user={deleteTarget}
          token={token}
          onClose={() => setDeleteTarget(null)}
          onDeleted={(id) => setUsers((prev) => prev.filter((u) => u.id !== id))}
        />
      )}
    </div>
  );
};

// ─── Audit Log Panel ────────────────────────────────────────────────────────────
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
    default: return 'Updated';
  }
};

const auditActionBadge = (action: AuditLogEntry['action']) => {
  switch (action) {
    case 'create_user':
    case 'create_device_group':
      return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    case 'delete_user':
    case 'delete_device_group':
      return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'update_device_groups':
    case 'update_device_os_category':
    case 'update_device_group':
      return 'text-violet-400 bg-violet-500/10 border-violet-500/30';
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
        className="flex items-center gap-1 text-xs text-slate-500 uppercase tracking-wider hover:text-slate-300 transition-colors"
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
        <h2 className="text-lg font-semibold text-white">Audit Log</h2>
        <p className="text-xs text-slate-500 mt-0.5">What admins have done — user accounts, device groups, and OS categorization</p>
      </div>

      <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading audit log…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : logs.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-14">No admin activity recorded yet.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                <SortHeader label="Action" sortk="action" />
                <SortHeader label="Admin" sortk="actor" />
                <SortHeader label="Target" sortk="target" />
                <th className="py-2.5 px-5 text-left">Details</th>
                <SortHeader label="When" sortk="when" />
              </tr>
            </thead>
            <tbody>
              {sortedLogs.map((log) => (
                <tr key={log.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${auditActionBadge(log.action)}`}>
                      {auditActionLabel(log.action)}
                    </span>
                  </td>
                  <td className="py-3 px-5 text-sm text-white">{log.actor.name || log.actor.email || '—'}</td>
                  <td className="py-3 px-5 text-sm text-slate-400">{log.target.name || log.target.email || '—'}</td>
                  <td className="py-3 px-5 text-xs text-slate-500">{log.details}</td>
                  <td className="py-3 px-5 text-xs text-slate-500 whitespace-nowrap">
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

// ─── Devices Panel (live agent inventory from Wazuh SIEM) ──────────────────────
const deviceStatusDot: Record<string, string> = {
  active: 'bg-emerald-400',
  disconnected: 'bg-red-400',
  never_connected: 'bg-slate-600',
  pending: 'bg-amber-400',
};

// ─── OS category badge ──────────────────────────────────────────────────────
const osCategoryDot: Record<OsCategory, string> = {
  windows: 'bg-cyan-400',
  linux:   'bg-amber-400',
  macos:   'bg-slate-300',
  network: 'bg-violet-400',
  iot:     'bg-pink-400',
  unknown: 'bg-slate-600',
};

const OsCategoryBadge: React.FC<{ category: OsCategory }> = ({ category }) => (
  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 whitespace-nowrap">
    <span className={`w-1.5 h-1.5 rounded-full ${osCategoryDot[category]}`} />
    <span className="text-xs text-slate-300">{OS_CATEGORY_LABELS[category]}</span>
  </span>
);

// ─── Per-device group assignment dropdown ───────────────────────────────────
const GroupAssignDropdown: React.FC<{
  agentGroups: string[];
  allGroups: DeviceGroup[];
  onToggle: (groupName: string) => void;
  onCreateAndAssign: (name: string) => Promise<void>;
}> = ({ agentGroups, allGroups, onToggle, onCreateAndAssign }) => {
  const [open, setOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const handleCreate = async () => {
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      await onCreateAndAssign(name);
      setNewName('');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center gap-1 flex-wrap">
        {agentGroups.map((g) => (
          <span
            key={g}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs whitespace-nowrap"
          >
            <Tag className="w-2.5 h-2.5" /> {g}
          </span>
        ))}
        <button
          onClick={() => setOpen((o) => !o)}
          className="w-5 h-5 flex items-center justify-center rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:text-white transition-colors flex-shrink-0"
          title="Assign groups"
        >
          <Plus className="w-3 h-3" />
        </button>
      </div>

      {open && (
        <div className="absolute z-40 top-full left-0 mt-1.5 w-56 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-2">
          {allGroups.length === 0 ? (
            <p className="text-xs text-slate-500 px-2 py-1.5">No groups yet — create one below.</p>
          ) : (
            <div className="max-h-40 overflow-y-auto space-y-0.5">
              {allGroups.map((g) => {
                const checked = agentGroups.includes(g.name);
                return (
                  <label key={g.id} className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-800 cursor-pointer">
                    <input type="checkbox" checked={checked} onChange={() => onToggle(g.name)} className="accent-cyan-500" />
                    <span className="text-xs text-slate-200 truncate">{g.name}</span>
                  </label>
                );
              })}
            </div>
          )}
          <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-slate-800">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCreate(); } }}
              placeholder="New group…"
              className="flex-1 min-w-0 px-2 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newName.trim()}
              className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 disabled:opacity-40 transition-colors flex-shrink-0"
            >
              {creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Manage Device Groups modal ─────────────────────────────────────────────
const DeviceGroupsModal: React.FC<{
  groups: DeviceGroup[];
  onClose: () => void;
  onCreate: (name: string) => Promise<unknown>;
  onRename: (id: string, name: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}> = ({ groups, onClose, onCreate, onRename, onDelete }) => {
  const [newName, setNewName] = useState('');
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);

  const handleCreate = async () => {
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    setError('');
    try {
      await onCreate(name);
      setNewName('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create group.');
    } finally {
      setCreating(false);
    }
  };

  const handleRename = async (id: string) => {
    if (!editing || !editing.name.trim()) return;
    setBusyId(id);
    setError('');
    try {
      await onRename(id, editing.name.trim());
      setEditing(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to rename group.');
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setBusyId(id);
    setError('');
    try {
      await onDelete(id);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete group.');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <h2 className="text-sm font-bold text-white">Manage Device Groups</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center gap-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCreate(); } }}
              placeholder="New group name…"
              className="flex-1 px-3 py-2.5 bg-slate-800 border border-slate-700 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all"
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newName.trim()}
              className="flex items-center gap-1.5 px-3 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-all"
            >
              {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            </button>
          </div>

          <div className="space-y-1.5 max-h-72 overflow-y-auto">
            {groups.length === 0 && (
              <p className="text-xs text-slate-500 text-center py-6">No groups yet. Create one above.</p>
            )}
            {groups.map((g) => (
              <div key={g.id} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-slate-800/60 border border-slate-800">
                {editing?.id === g.id ? (
                  <input
                    autoFocus
                    value={editing.name}
                    onChange={(e) => setEditing({ id: g.id, name: e.target.value })}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleRename(g.id); if (e.key === 'Escape') setEditing(null); }}
                    className="flex-1 px-2 py-1 bg-slate-900 border border-cyan-500/40 rounded-md text-sm text-white focus:outline-none"
                  />
                ) : (
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white font-medium truncate">{g.name}</p>
                    <p className="text-xs text-slate-500">{g.deviceCount} device{g.deviceCount === 1 ? '' : 's'}</p>
                  </div>
                )}

                {busyId === g.id ? (
                  <Loader2 className="w-3.5 h-3.5 text-slate-500 animate-spin flex-shrink-0" />
                ) : editing?.id === g.id ? (
                  <>
                    <button onClick={() => handleRename(g.id)} className="text-emerald-400 hover:text-emerald-300 text-xs font-medium px-1.5 flex-shrink-0">Save</button>
                    <button onClick={() => setEditing(null)} className="text-slate-500 hover:text-slate-300 text-xs px-1.5 flex-shrink-0">Cancel</button>
                  </>
                ) : (
                  <>
                    <button onClick={() => setEditing({ id: g.id, name: g.name })} className="text-slate-400 hover:text-white transition-colors p-1 flex-shrink-0">
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => handleDelete(g.id)} className="text-slate-400 hover:text-red-400 transition-colors p-1 flex-shrink-0">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

const DevicesPanel: React.FC = () => {
  const { token } = useAuth();
  const { config, connected, connecting, agents, loadingAgents, connectionError, refresh, lastRefresh } = useWazuhContext();
  const {
    groups, deviceMeta, createGroup, renameGroup, deleteGroup, assignGroups,
  } = useDeviceMeta(token);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);
  const [showGroupsModal, setShowGroupsModal] = useState(false);
  const [osFilter, setOsFilter] = useState<OsCategory | 'all'>('all');
  const [groupFilter, setGroupFilter] = useState<string>('all');

  const metaByAgent = useMemo(() => new Map(deviceMeta.map((m) => [m.agentId, m])), [deviceMeta]);

  const normalizedStatuses = agents.map((a) => normalizeAgentStatus(a.status));
  const counts = {
    total: agents.length,
    active: normalizedStatuses.filter((s) => s === 'active').length,
    disconnected: normalizedStatuses.filter((s) => s === 'disconnected').length,
    other: normalizedStatuses.filter((s) => s !== 'active' && s !== 'disconnected').length,
  };

  const categoryFor = (ag: WazuhAgent): OsCategory => metaByAgent.get(ag.id)?.osCategoryOverride ?? inferOsCategory(ag.os);
  const groupsFor = (ag: WazuhAgent): string[] => metaByAgent.get(ag.id)?.groups ?? [];

  const filteredAgents = agents.filter((ag) => {
    if (osFilter !== 'all' && categoryFor(ag) !== osFilter) return false;
    if (groupFilter === 'ungrouped' && groupsFor(ag).length > 0) return false;
    if (groupFilter !== 'all' && groupFilter !== 'ungrouped' && !groupsFor(ag).includes(groupFilter)) return false;
    return true;
  });

  const toggleAgentGroup = (ag: WazuhAgent, groupName: string) => {
    const current = groupsFor(ag);
    const next = current.includes(groupName) ? current.filter((g) => g !== groupName) : [...current, groupName];
    assignGroups(ag.id, next, ag.name);
  };

  const createAndAssign = async (ag: WazuhAgent, name: string) => {
    const group = await createGroup(name);
    await assignGroups(ag.id, [...groupsFor(ag), group.name], ag.name);
  };

  if (!config) {
    return (
      <div className="p-5">
        <div>
          <h2 className="text-lg font-semibold text-white">Devices</h2>
          <p className="text-xs text-slate-500 mt-0.5">Live IoMT / endpoint inventory from Wazuh SIEM</p>
        </div>
        <div className="mt-5 rounded-2xl bg-slate-900 border border-slate-800 p-10 text-center">
          <Server className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-300 font-medium">Wazuh SIEM is not connected</p>
          <p className="text-xs text-slate-500 mt-1">Connect it under Settings → Wazuh SIEM to see live device data here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Devices</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Live IoMT / endpoint inventory from Wazuh SIEM
            {lastRefresh ? ` · Updated ${lastRefresh.toLocaleTimeString()}` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGroupsModal(true)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-sm transition-colors"
          >
            <Settings className="w-3.5 h-3.5" /> Manage Groups
          </button>
          <button
            onClick={refresh}
            disabled={!connected || loadingAgents}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {connectionError && !connected && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {connectionError}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<Server className="w-5 h-5 text-cyan-400" />} label="Total Devices" value={String(counts.total)} sub="Registered agents" color="cyan" />
        <StatCard icon={<CheckCircle className="w-5 h-5 text-emerald-400" />} label="Active" value={String(counts.active)} sub="Online now" color="emerald" />
        <StatCard icon={<AlertTriangle className="w-5 h-5 text-red-400" />} label="Disconnected" value={String(counts.disconnected)} sub="Needs attention" color="red" />
        <StatCard icon={<Clock className="w-5 h-5 text-amber-400" />} label="Other" value={String(counts.other)} sub="Pending / never connected" color="amber" />
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <span className="flex items-center gap-1.5 text-xs text-slate-500">
          <Filter className="w-3.5 h-3.5" /> Filter
        </span>
        <select
          value={osFilter}
          onChange={(e) => setOsFilter(e.target.value as OsCategory | 'all')}
          className="px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All OS types</option>
          {(Object.keys(OS_CATEGORY_LABELS) as OsCategory[]).map((c) => (
            <option key={c} value={c}>{OS_CATEGORY_LABELS[c]}</option>
          ))}
        </select>
        <select
          value={groupFilter}
          onChange={(e) => setGroupFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All groups</option>
          <option value="ungrouped">Ungrouped</option>
          {groups.map((g) => (
            <option key={g.id} value={g.name}>{g.name}</option>
          ))}
        </select>
      </div>

      <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
        {(connecting || loadingAgents) && agents.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading devices…
          </div>
        ) : filteredAgents.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-14">
            {agents.length === 0 ? 'No devices found.' : 'No devices match the current filters.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                  <th className="py-2.5 px-5 text-left">Status</th>
                  <th className="py-2.5 px-5 text-left">ID</th>
                  <th className="py-2.5 px-5 text-left">Name</th>
                  <th className="py-2.5 px-5 text-left">IP</th>
                  <th className="py-2.5 px-5 text-left">OS</th>
                  <th className="py-2.5 px-5 text-left">Category</th>
                  <th className="py-2.5 px-5 text-left">Version</th>
                  <th className="py-2.5 px-5 text-left">Groups</th>
                  <th className="py-2.5 px-5 text-left">Last Seen</th>
                  <th className="py-2.5 px-5 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {filteredAgents.map((ag) => {
                  const normalized = normalizeAgentStatus(ag.status);
                  return (
                  <tr key={ag.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-5">
                      <span className="flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${deviceStatusDot[normalized] ?? 'bg-slate-600'}`} />
                        <span className="text-xs text-slate-400 capitalize">{normalized.replace('_', ' ')}</span>
                      </span>
                    </td>
                    <td className="py-3 px-5 font-mono text-xs text-slate-500">{ag.id}</td>
                    <td className="py-3 px-5 text-sm">
                      <button
                        onClick={() => setSelectedAgent(ag)}
                        className="text-white font-medium hover:text-cyan-400 transition-colors text-left"
                      >
                        {ag.name}
                      </button>
                    </td>
                    <td className="py-3 px-5 text-xs text-slate-400 font-mono">{ag.ip ?? '—'}</td>
                    <td className="py-3 px-5 text-xs text-slate-400 whitespace-nowrap">{formatOs(ag.os)}</td>
                    <td className="py-3 px-5"><OsCategoryBadge category={categoryFor(ag)} /></td>
                    <td className="py-3 px-5 text-xs text-slate-500 font-mono">{ag.version ?? '—'}</td>
                    <td className="py-3 px-5">
                      <GroupAssignDropdown
                        agentGroups={groupsFor(ag)}
                        allGroups={groups}
                        onToggle={(name) => toggleAgentGroup(ag, name)}
                        onCreateAndAssign={(name) => createAndAssign(ag, name)}
                      />
                    </td>
                    <td className="py-3 px-5 text-xs text-slate-500 whitespace-nowrap">
                      {ag.lastKeepAlive ? new Date(ag.lastKeepAlive).toLocaleString() : '—'}
                    </td>
                    <td className="py-3 px-5 text-right">
                      <button
                        onClick={() => setSelectedAgent(ag)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedAgent && config && (
        <AgentDetailsModal agent={selectedAgent} config={config} onClose={() => setSelectedAgent(null)} />
      )}

      {showGroupsModal && (
        <DeviceGroupsModal
          groups={groups}
          onClose={() => setShowGroupsModal(false)}
          onCreate={createGroup}
          onRename={renameGroup}
          onDelete={deleteGroup}
        />
      )}
    </div>
  );
};

// ─── Notification Bell (recent high-severity Wazuh alerts) ─────────────────
const severityDot = (level: number) => {
  if (level >= 12) return 'bg-red-500';
  if (level >= 8) return 'bg-orange-400';
  return 'bg-amber-400';
};

const NotificationBell: React.FC<{ onViewAll: () => void }> = ({ onViewAll }) => {
  const { config } = useWazuhContext();
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<WazuhAlertRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  const indexerReady = hasIndexerConfig(config);

  const load = () => {
    if (!config || !indexerReady) return;
    setLoading(true);
    setError('');
    searchAlerts(config, { page: 1, pageSize: 10, severity: 8 })
      .then((r) => setAlerts(r.alerts))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load alerts.'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 60_000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, indexerReady]);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const count = alerts.length;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => { setOpen((o) => !o); if (!open) load(); }}
        className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
      >
        <Bell className="w-4 h-4" />
        {count > 0 && (
          <span className="absolute top-1 right-1 min-w-[14px] h-3.5 px-0.5 flex items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white leading-none">
            {count > 9 ? '9+' : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-12 w-80 bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden z-50">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <p className="text-sm font-semibold text-white">Notifications</p>
            <button onClick={() => setOpen(false)} className="text-slate-500 hover:text-slate-300 transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="max-h-80 overflow-y-auto">
            {!config ? (
              <p className="text-xs text-slate-500 text-center py-8 px-4">
                Connect Wazuh SIEM in Settings to see alert notifications here.
              </p>
            ) : !indexerReady ? (
              <p className="text-xs text-slate-500 text-center py-8 px-4">
                Configure the Wazuh Indexer in Settings → Wazuh SIEM to see alert notifications here.
              </p>
            ) : loading ? (
              <div className="flex items-center justify-center gap-2 py-8 text-slate-500 text-xs">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading…
              </div>
            ) : error ? (
              <p className="text-xs text-red-400 text-center py-8 px-4">{error}</p>
            ) : alerts.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-8 px-4">No high-severity alerts right now.</p>
            ) : (
              <div className="divide-y divide-slate-800">
                {alerts.map((al) => (
                  <div key={al.id} className="px-4 py-3 hover:bg-slate-800/40 transition-colors">
                    <div className="flex items-start gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${severityDot(al.ruleLevel ?? 0)}`} />
                      <div className="min-w-0">
                        <p className="text-xs text-white font-medium truncate">{al.ruleDescription ?? 'Unknown alert'}</p>
                        <p className="text-xs text-slate-500 mt-0.5 truncate">
                          {al.agentName ?? 'Unknown agent'}{al.agentIp ? ` · ${al.agentIp}` : ''}
                        </p>
                        <p className="text-xs text-slate-600 mt-0.5">
                          {al.timestamp ? new Date(al.timestamp).toLocaleString() : ''}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <button
            onClick={() => { setOpen(false); onViewAll(); }}
            className="w-full px-4 py-2.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-800/60 border-t border-slate-800 transition-colors font-medium"
          >
            View all alerts →
          </button>
        </div>
      )}
    </div>
  );
};

const AdminDashboard: React.FC = () => {
  const { user, logout, token } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeNav, setActiveNav] = useState('Overview');
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [complianceOpen, setComplianceOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const navItems = [
    { label: 'Overview', icon: <BarChart3 className="w-4 h-4" /> },
    { label: 'Alerts', icon: <Bell className="w-4 h-4" /> },
    { label: 'Devices', icon: <Server className="w-4 h-4" /> },
    { label: 'IP Reputation', icon: <Network className="w-4 h-4" /> },
    { label: 'Playbooks', icon: <Zap className="w-4 h-4" /> },
  ];

  const settingsSubItems = [
    { label: 'Users', icon: <Users className="w-3.5 h-3.5" /> },
    { label: 'Wazuh SIEM', icon: <Shield className="w-3.5 h-3.5" /> },
    { label: 'Audit Log', icon: <Database className="w-3.5 h-3.5" /> },
  ];
  const isSettingsActive = settingsSubItems.some((s) => s.label === activeNav);

  const complianceSubItems: { label: string; icon: React.ReactNode; framework: FrameworkTab }[] = [
    { label: 'HIPAA', icon: <ShieldCheck className="w-3.5 h-3.5" />, framework: 'hipaa' },
    { label: 'GDPR', icon: <Globe className="w-3.5 h-3.5" />, framework: 'gdpr' },
    { label: 'CIS', icon: <ClipboardCheck className="w-3.5 h-3.5" />, framework: 'cis' },
  ];
  const isComplianceActive = complianceSubItems.some((s) => s.label === activeNav);

  return (
    <WazuhProvider>
    <div className="h-screen overflow-hidden bg-slate-950 text-white flex flex-col">

      {/* ── Below-banner layout: sidebar + main ── */}
      <div className="flex flex-1 min-h-0">

        {/* Sidebar */}
        <aside
          className={`fixed inset-y-0 left-0 z-40 flex flex-col w-64 bg-slate-900 border-r border-slate-800 transition-transform duration-300 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 lg:static lg:z-auto`}
        >
          {/* Logo */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/30">
                <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
              </div>
              <span className="font-bold text-sm text-white">
                Medi<span className="text-cyan-400">SIEM</span>
              </span>
            </div>
            <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-slate-400 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Role Badge */}
          <div className="px-5 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20">
              <Shield className="w-3.5 h-3.5 text-red-400" />
              <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Admin Console</span>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            {navItems.map((item) => (
              <button
                key={item.label}
                onClick={() => setActiveNav(item.label)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all text-left ${
                  activeNav === item.label
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {item.icon}
                {item.label}
              </button>
            ))}

            {/* Compliances — expandable, holds HIPAA / GDPR / CIS */}
            <button
              onClick={() => {
                const next = !complianceOpen;
                setComplianceOpen(next);
                if (next && !isComplianceActive) setActiveNav('HIPAA');
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all text-left ${
                isComplianceActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              Compliances
              <ChevronDown className={`w-3.5 h-3.5 ml-auto transition-transform ${complianceOpen || isComplianceActive ? 'rotate-180' : ''}`} />
            </button>

            {(complianceOpen || isComplianceActive) && (
              <div className="ml-3 pl-3 border-l border-slate-800 space-y-0.5">
                {complianceSubItems.map((item) => (
                  <button
                    key={item.label}
                    onClick={() => setActiveNav(item.label)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all text-left ${
                      activeNav === item.label
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    {item.icon}
                    {item.label}
                  </button>
                ))}
              </div>
            )}

            {/* Settings — expandable, holds Users / Wazuh SIEM / Audit Log */}
            <button
              onClick={() => {
                const next = !settingsOpen;
                setSettingsOpen(next);
                if (next && !isSettingsActive) setActiveNav('Users');
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all text-left ${
                isSettingsActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Settings className="w-4 h-4" />
              Settings
              <ChevronDown className={`w-3.5 h-3.5 ml-auto transition-transform ${settingsOpen || isSettingsActive ? 'rotate-180' : ''}`} />
            </button>

            {(settingsOpen || isSettingsActive) && (
              <div className="ml-3 pl-3 border-l border-slate-800 space-y-0.5">
                {settingsSubItems.map((item) => (
                  <button
                    key={item.label}
                    onClick={() => setActiveNav(item.label)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all text-left ${
                      activeNav === item.label
                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    {item.icon}
                    {item.label}
                  </button>
                ))}
              </div>
            )}
          </nav>

          {/* User */}
          <div className="px-4 py-4 border-t border-slate-800">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-gradient-to-br from-red-400 to-orange-500 flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                {user?.name?.[0]?.toUpperCase()}
              </div>
              <div className="min-w-0">
                <div className="text-sm font-medium text-white truncate">{user?.name}</div>
                <div className="text-xs text-slate-500 truncate">{user?.email}</div>
              </div>
            </div>
          </div>
        </aside>

        {/* Overlay for mobile */}
        {sidebarOpen && (
          <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
        )}

        {/* Main */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Top bar */}
          <header className="sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-slate-950/90 backdrop-blur border-b border-slate-800">
            <div className="flex items-center gap-3">
              <button onClick={() => setSidebarOpen(true)} className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">
                <Menu className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-sm font-bold text-white">Admin Dashboard</h1>
                <p className="text-xs text-slate-500 hidden sm:block">R26-CS-008 · MediSIEM Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                <span className="text-xs text-emerald-400 font-medium hidden sm:block">System Active</span>
              </div>
              <NotificationBell onViewAll={() => setActiveNav('Wazuh SIEM')} />
              <div className="relative pl-3 border-l border-slate-800">
                <button
                  onClick={() => setShowAccountMenu(!showAccountMenu)}
                  className="flex items-center gap-2"
                >
                  <div className="w-7 h-7 rounded-full bg-gradient-to-br from-red-400 to-orange-500 flex items-center justify-center text-xs font-bold text-white">
                    {user?.name?.[0]?.toUpperCase()}
                  </div>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-500 transition-transform ${showAccountMenu ? 'rotate-180' : ''}`} />
                </button>

                {showAccountMenu && (
                  <AccountMenu
                    token={token}
                    userId={user?.id}
                    onClose={() => setShowAccountMenu(false)}
                    onLogout={handleLogout}
                  />
                )}
              </div>
            </div>
          </header>

          {/* Content */}
          <main className="flex-1 overflow-y-auto">
            {activeNav === 'Wazuh SIEM' && <WazuhDashboard />}
            {activeNav === 'Users' && <UsersPanel token={token} currentUserId={user?.id} />}
            {activeNav === 'Audit Log' && <AuditLogPanel token={token} />}
            {activeNav === 'Devices' && <DevicesPanel />}
            {activeNav === 'HIPAA' && <CompliancePanel framework="hipaa" />}
            {activeNav === 'GDPR' && <CompliancePanel framework="gdpr" />}
            {activeNav === 'CIS' && <CompliancePanel framework="cis" />}
            {activeNav !== 'Wazuh SIEM' && activeNav !== 'Users' && activeNav !== 'Audit Log' && activeNav !== 'Devices' &&
             activeNav !== 'HIPAA' && activeNav !== 'GDPR' && activeNav !== 'CIS' && <div className="p-5 space-y-6">
            {/* Stats */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon={<AlertTriangle className="w-5 h-5 text-red-400" />} label="Critical Alerts" value="3" sub="Requires immediate action" color="red" trend="+2" />
              <StatCard icon={<Activity className="w-5 h-5 text-cyan-400" />} label="Monitored Devices" value="47" sub="IoMT assets online" color="cyan" trend="+3" />
              <StatCard icon={<Users className="w-5 h-5 text-violet-400" />} label="Active Users" value="12" sub="SOC analysts online" color="violet" />
              <StatCard icon={<TrendingUp className="w-5 h-5 text-emerald-400" />} label="Alert Reduction" value="76%" sub="vs. last 30 days" color="emerald" trend="+12%" />
            </div>

            {/* CAS Overview + IP Reputation */}
            <div className="grid lg:grid-cols-3 gap-5">
              {/* CAS Distribution */}
              <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900 border border-slate-800">
                <div className="flex items-center justify-between mb-5">
                  <div>
                    <h2 className="font-semibold text-white">Clinical Alert Score (CAS) Distribution</h2>
                    <p className="text-xs text-slate-500 mt-0.5">TR × CC × TS — last 24 hours</p>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-400">Live</span>
                </div>
                <div className="space-y-3">
                  {[
                    { label: 'Critical (8–10)', count: 3, pct: 6, color: 'bg-red-500' },
                    { label: 'High (6–8)', count: 9, pct: 18, color: 'bg-orange-500' },
                    { label: 'Medium (4–6)', count: 16, pct: 32, color: 'bg-amber-500' },
                    { label: 'Low (0–4)', count: 22, pct: 44, color: 'bg-blue-500' },
                  ].map((row) => (
                    <div key={row.label} className="flex items-center gap-3">
                      <div className="w-28 text-xs text-slate-400 flex-shrink-0">{row.label}</div>
                      <div className="flex-1 bg-slate-800 rounded-full h-2">
                        <div className={`${row.color} h-2 rounded-full transition-all`} style={{ width: `${row.pct}%` }} />
                      </div>
                      <div className="text-xs font-mono text-slate-400 w-10 text-right">{row.count}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* IP Reputation */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800">
                <h2 className="font-semibold text-white mb-1">IP Reputation</h2>
                <p className="text-xs text-slate-500 mb-5">Top suspicious sources</p>
                <div className="space-y-3">
                  {[
                    { ip: '185.220.101.x', score: 9.2, label: 'Malicious', color: 'text-red-400 bg-red-500/10' },
                    { ip: '92.118.160.x', score: 7.4, label: 'Suspicious', color: 'text-orange-400 bg-orange-500/10' },
                    { ip: '45.142.212.x', score: 6.1, label: 'Suspicious', color: 'text-amber-400 bg-amber-500/10' },
                    { ip: '10.0.14.22', score: 2.3, label: 'Internal', color: 'text-blue-400 bg-blue-500/10' },
                  ].map((ip) => (
                    <div key={ip.ip} className="flex items-center justify-between py-2 border-b border-slate-800/60 last:border-0">
                      <div>
                        <div className="text-sm font-mono text-slate-300">{ip.ip}</div>
                        <div className={`text-xs px-1.5 py-0.5 rounded mt-0.5 inline-block ${ip.color}`}>{ip.label}</div>
                      </div>
                      <div className="text-sm font-bold text-white">{ip.score}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Alerts Table */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
                <div>
                  <h2 className="font-semibold text-white">Active Security Alerts</h2>
                  <p className="text-xs text-slate-500 mt-0.5">Sorted by Clinical Alert Score (CAS)</p>
                </div>
                <button className="px-3 py-1.5 text-xs rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white transition-colors">
                  View All
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                      <th className="py-2.5 px-4 text-left">Severity</th>
                      <th className="py-2.5 px-4 text-left">Device</th>
                      <th className="py-2.5 px-4 text-left">Event</th>
                      <th className="py-2.5 px-4 text-left">CAS Score</th>
                      <th className="py-2.5 px-4 text-left">Time</th>
                      <th className="py-2.5 px-4 text-left">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_ALERTS.map((a) => (
                      <AlertRow key={a.device + a.time} {...a} />
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Life-Critical Status */}
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'ICU Ventilators', status: 'Protected', icon: <CheckCircle className="w-4 h-4" />, color: 'emerald' },
                { label: 'Infusion Pumps', status: 'Protected', icon: <CheckCircle className="w-4 h-4" />, color: 'emerald' },
                { label: 'Cardiac Monitors', status: 'Monitoring', icon: <Clock className="w-4 h-4" />, color: 'amber' },
                { label: 'CT/MRI Systems', status: 'Alert Active', icon: <AlertCircle className="w-4 h-4" />, color: 'red' },
              ].map((item) => (
                <div key={item.label} className={`flex items-center gap-3 p-4 rounded-xl bg-${item.color}-500/5 border border-${item.color}-500/20`}>
                  <span className={`text-${item.color}-400`}>{item.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-white">{item.label}</div>
                    <div className={`text-xs text-${item.color}-400`}>{item.status}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Footer */}
            <div className="text-center py-4 text-xs text-slate-700">
              MediSIEM Admin Console · R26-CS-008 · SLIIT 2026 · Logged in as {user?.name}
            </div>
            </div>}
          </main>
        </div>
      </div>
    </div>
    </WazuhProvider>
  );
};

export default AdminDashboard;
