import React, { useEffect, useState } from 'react';
import WazuhDashboard from './WazuhDashboard';
import { WazuhProvider, useWazuhContext } from './WazuhContext';
import { normalizeAgentStatus, formatOs } from './wazuhApi';
import type { WazuhAgent } from './wazuhApi';
import AgentDetailsModal from './AgentDetailsModal';
import {
  Shield, Activity, AlertTriangle, Users, Server, Bell,
  Settings, ChevronDown, Menu, X, BarChart3,
  TrendingUp, Network, Zap, CheckCircle,
  Clock, AlertCircle, Database, Plus, Loader2, Mail, Lock, Pencil, Trash2, RefreshCw,
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
  if (action === 'create_user') return 'Created user';
  if (action === 'delete_user') return 'Deleted user';
  return 'Updated user';
};

const auditActionBadge = (action: AuditLogEntry['action']) => {
  if (action === 'create_user') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  if (action === 'delete_user') return 'text-red-400 bg-red-500/10 border-red-500/30';
  return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
};

const AuditLogPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

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

  return (
    <div className="p-5 space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-white">Audit Log</h2>
        <p className="text-xs text-slate-500 mt-0.5">What admins have done — user accounts created or changed</p>
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
                <th className="py-2.5 px-5 text-left">Action</th>
                <th className="py-2.5 px-5 text-left">Admin</th>
                <th className="py-2.5 px-5 text-left">Target User</th>
                <th className="py-2.5 px-5 text-left">Details</th>
                <th className="py-2.5 px-5 text-left">When</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
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

const DevicesPanel: React.FC = () => {
  const { config, connected, connecting, agents, loadingAgents, connectionError, refresh, lastRefresh } = useWazuhContext();
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);

  const normalizedStatuses = agents.map((a) => normalizeAgentStatus(a.status));
  const counts = {
    total: agents.length,
    active: normalizedStatuses.filter((s) => s === 'active').length,
    disconnected: normalizedStatuses.filter((s) => s === 'disconnected').length,
    other: normalizedStatuses.filter((s) => s !== 'active' && s !== 'disconnected').length,
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
        <button
          onClick={refresh}
          disabled={!connected || loadingAgents}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : ''}`} /> Refresh
        </button>
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

      <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
        {(connecting || loadingAgents) && agents.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading devices…
          </div>
        ) : agents.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-14">No devices found.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-800">
                <th className="py-2.5 px-5 text-left">Status</th>
                <th className="py-2.5 px-5 text-left">Name</th>
                <th className="py-2.5 px-5 text-left">IP</th>
                <th className="py-2.5 px-5 text-left">OS</th>
                <th className="py-2.5 px-5 text-left">Version</th>
                <th className="py-2.5 px-5 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((ag) => {
                const normalized = normalizeAgentStatus(ag.status);
                return (
                <tr key={ag.id} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${deviceStatusDot[normalized] ?? 'bg-slate-600'}`} />
                      <span className="text-xs text-slate-400 capitalize">{normalized.replace('_', ' ')}</span>
                    </span>
                  </td>
                  <td className="py-3 px-5 text-sm">
                    <button
                      onClick={() => setSelectedAgent(ag)}
                      className="text-white font-medium hover:text-cyan-400 transition-colors text-left"
                    >
                      {ag.name}
                    </button>
                  </td>
                  <td className="py-3 px-5 text-xs text-slate-400 font-mono">{ag.ip ?? '—'}</td>
                  <td className="py-3 px-5 text-xs text-slate-400">{formatOs(ag.os)}</td>
                  <td className="py-3 px-5 text-xs text-slate-500 font-mono">{ag.version ?? '—'}</td>
                  <td className="py-3 px-5 text-xs text-slate-500 whitespace-nowrap">
                    {ag.lastKeepAlive ? new Date(ag.lastKeepAlive).toLocaleString() : '—'}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {selectedAgent && config && (
        <AgentDetailsModal agent={selectedAgent} config={config} onClose={() => setSelectedAgent(null)} />
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
              <button className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">
                <Bell className="w-4 h-4" />
                <span className="absolute top-1 right-1 w-1.5 h-1.5 bg-red-500 rounded-full" />
              </button>
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
            {activeNav !== 'Wazuh SIEM' && activeNav !== 'Users' && activeNav !== 'Audit Log' && activeNav !== 'Devices' && <div className="p-5 space-y-6">
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
