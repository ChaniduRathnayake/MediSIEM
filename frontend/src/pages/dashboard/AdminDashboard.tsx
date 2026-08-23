import React, { useEffect, useMemo, useRef, useState } from 'react';
import WazuhDashboard from './WazuhDashboard';
import { WazuhProvider, useWazuhContext } from './WazuhContext';
import { normalizeAgentStatus, formatOs, inferOsCategory, OS_CATEGORY_LABELS } from './wazuhApi';
import type { WazuhAgent, OsCategory } from './wazuhApi';
import { useDeviceMeta } from './useDeviceMeta';
import type { DeviceGroup } from './deviceApi';
import GroupAssignDropdown from './GroupAssignDropdown';
import MedicalDeviceInventoryPanel from './MedicalDeviceInventoryPanel';
import MedicalDeviceTagDropdown from './MedicalDeviceTagDropdown';
import { getMedicalDevices } from '../../services/medicalDeviceApi';
import type { MedicalDevice } from '../../services/medicalDeviceApi';
import AgentDetailsModal from './AgentDetailsModal';
import CompliancePanel from './CompliancePanel';
import type { FrameworkTab } from './CompliancePanel';
import VulnerabilitiesPanel from './VulnerabilitiesPanel';
import { hasIndexerConfig, searchAlerts } from './complianceApi';
import type { WazuhAlertRow } from './complianceApi';
import {
  Shield, Activity, AlertTriangle, Users, Server, Bell,
  Settings, ChevronDown, Menu, X, BarChart3,
  TrendingUp, Network, Zap, CheckCircle,
  Clock, AlertCircle, Database, Plus, Loader2, Mail, Lock, Pencil, Trash2, RefreshCw,
  Tag, Filter, ShieldCheck, Globe, ClipboardCheck, Bug, ShieldAlert, KeyRound, Tv, Gauge, Plug, SlidersHorizontal, Radio,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { apiGetAllUsers, apiCreateUser, apiUpdateUser, apiDeleteUser } from '../../services/api';
import { apiSetUserMfaRequired, apiAdminResetUserMfa } from '../../services/authExtrasApi';
import type { User as MediUser, UserRole } from '../../types';
import AccountMenu from '../../components/AccountMenu';
import PresenceWidget, { usePresenceSummary } from './PresenceWidget';
import { useLiveAlerts } from '../../hooks/useLiveAlerts';
import type { EnrichedAlert } from '../../services/alertsApi';
import StatCard from '../../components/StatCard';
import SeverityBadge from '../../components/SeverityBadge';
import AlertsPanel from './AlertsPanel';
import DeviceEventsPanel from './DeviceEventsPanel';
import AdminCasesPanel from './AdminCasesPanel';
import RulesPanel from './RulesPanel';
import SecuritySettingsPanel from './SecuritySettingsPanel';
import IntegrationsSettingsPanel from './IntegrationsSettingsPanel';
import CasWeightsSettingsPanel from './CasWeightsSettingsPanel';
import PlaybooksPanel from './PlaybooksPanel';
import DetectionPerformancePanel from './DetectionPerformancePanel';
import AuditLogPanel from './AuditLogPanel';
import PasswordChecklist from '../../components/PasswordChecklist';
import { apiGetPasswordPolicy } from '../../services/passwordPolicyApi';
import type { PasswordPolicy } from '../../services/passwordPolicyApi';
import { passwordMeetsPolicy } from '../../utils/passwordPolicy';
import ThemeToggle from '../../components/ThemeToggle';
import SoundToggle from '../../components/SoundToggle';
import NotificationCenterBell from '../../components/NotificationCenterBell';
import ChartCard from '../../components/charts/ChartCard';
import AlertsTimelineChart from '../../components/charts/AlertsTimelineChart';
import SeverityDonutChart from '../../components/charts/SeverityDonutChart';
import TopBarChart from '../../components/charts/TopBarChart';
import DonutChart from '../../components/charts/DonutChart';
import { casToSeverity, actionToStatus, severityCounts, bucketAlertsByHour, countBy, latestTimestamp, SEVERITY_ORDER, SEVERITY_COLORS } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';

// ─── Alert Row (Overview tab preview table) ────────────────────────────────────
const AlertRow: React.FC<{
  severity: Severity;
  device: string;
  event: string;
  cas: number;
  time: string;
  status: 'Open' | 'Investigating' | 'Resolved';
}> = ({ severity, device, event, cas, time, status }) => {
  const statusColor: Record<string, string> = {
    Open: 'text-red-500 dark:text-red-400',
    Investigating: 'text-amber-600 dark:text-amber-400',
    Resolved: 'text-emerald-600 dark:text-emerald-400',
  };
  return (
    <tr className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
      <td className="py-3 px-4">
        <SeverityBadge severity={severity} />
      </td>
      <td className="py-3 px-4 text-sm text-slate-700 dark:text-slate-300 font-mono">{device}</td>
      <td className="py-3 px-4 text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate">{event}</td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <div className="flex-1 bg-slate-200 dark:bg-slate-700 rounded-full h-1.5 w-16">
            <div
              className={`h-1.5 rounded-full ${cas >= 8 ? 'bg-red-500' : cas >= 6 ? 'bg-orange-500' : cas >= 4 ? 'bg-amber-500' : 'bg-blue-500'}`}
              style={{ width: `${(cas / 10) * 100}%` }}
            />
          </div>
          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">{cas.toFixed(1)}</span>
        </div>
      </td>
      <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500">{time}</td>
      <td className="py-3 px-4">
        <span className={`text-xs font-medium ${statusColor[status]}`}>{status}</span>
      </td>
    </tr>
  );
};

// ─── Users Panel ────────────────────────────────────────────────────────────
// Kept in sync with backend/controllers/userController.js's ROLE_LABEL and
// services/api.ts's MOCK_ROLE_LABEL — all three exist only because Node and
// Vite don't share a module graph, not because the labels are meant to diverge.
const ROLE_LABELS: Record<UserRole, string> = { admin: 'Admin', user: 'SOC Analyst', biomed: 'Biomedical Engineer', auditor: 'Auditor' };
const roleLabel = (role: string) => ROLE_LABELS[role as UserRole] ?? role;

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
    role: (initial?.role ?? 'user') as UserRole,
  });
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy | null>(null);

  useEffect(() => {
    if (!token) return;
    apiGetPasswordPolicy(token).then((data) => setPasswordPolicy(data.policy)).catch(() => {});
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.email || (mode === 'create' && !form.password)) {
      setError('Name, email and password are required.');
      return;
    }
    if (form.password && passwordPolicy && !passwordMeetsPolicy(form.password, passwordPolicy)) {
      setError('Password does not meet the policy requirements below.');
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
    'w-full pl-10 pr-3 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white ' +
    'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">{mode === 'create' ? 'Add User' : 'Edit User'}</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
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
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Full name</label>
            <div className="relative">
              <Users className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
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
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Email address</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
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
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">
              {mode === 'create' ? 'Temporary password' : 'New password'}
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
              <input
                type="password"
                className={input}
                value={form.password}
                onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))}
                placeholder={mode === 'create' ? '••••••••' : 'Leave blank to keep current password'}
                autoComplete="new-password"
              />
            </div>
            {form.password && <PasswordChecklist password={form.password} policy={passwordPolicy} />}
          </div>

          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Role</label>
            <div className="grid grid-cols-2 gap-2">
              {(['user', 'biomed', 'auditor', 'admin'] as UserRole[]).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => setForm((p) => ({ ...p, role: r }))}
                  className={`px-3 py-2.5 rounded-lg text-sm font-medium border transition-all ${
                    form.role === r
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-400'
                      : 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {roleLabel(r)}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-slate-400 dark:text-slate-600 mt-1.5">
              {form.role === 'biomed'
                ? 'Read access everywhere SOC analysts have it, plus write access to the medical device inventory.'
                : form.role === 'auditor'
                ? 'Read-only — compliance views and the audit log, no case assignment or write access.'
                : form.role === 'user'
                ? 'SOC analyst — triages and closes alert cases.'
                : 'Full access, including user management and settings.'}
            </p>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2.5 mt-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-slate-900 dark:text-white font-semibold text-sm rounded-lg transition-all"
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
      <div className="w-full max-w-sm rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Delete User</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
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

          <p className="text-sm text-slate-700 dark:text-slate-300">
            Permanently delete <span className="font-semibold text-slate-900 dark:text-white">{user.name}</span> ({user.email})? This cannot be undone.
          </p>

          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="flex-1 py-2.5 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleDelete}
              disabled={submitting}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-slate-900 dark:text-white bg-red-500 hover:bg-red-400 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Deleting…</> : 'Delete'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Configure 2FA modal (Users tab → non-admin targets only) ─────────────────
// Admins can force a non-admin to set up 2FA next login, and reset a lost
// device's enrollment — but never generate/see a secret on the user's
// behalf, since TOTP requires the account owner's own authenticator app.
const MfaControlModal: React.FC<{
  user: MediUser;
  token: string | null;
  onClose: () => void;
  onUpdated: (user: MediUser) => void;
}> = ({ user, token, onClose, onUpdated }) => {
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);

  const toggleRequired = async (required: boolean) => {
    if (!token) { setError('Your session has expired. Please sign in again.'); return; }
    setSubmitting(true);
    setError('');
    try {
      const { user: updated } = await apiSetUserMfaRequired(token, user.id, required);
      onUpdated(updated);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update two-factor requirement.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = async () => {
    if (!token) { setError('Your session has expired. Please sign in again.'); return; }
    setSubmitting(true);
    setError('');
    try {
      const { user: updated } = await apiAdminResetUserMfa(token, user.id);
      onUpdated(updated);
      setConfirmReset(false);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset two-factor authentication.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Configure 2FA — {user.name}</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
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

          <p className="text-xs text-slate-400 dark:text-slate-500">
            2FA is set up on the user's own device, so it can only be required or reset here — not enabled directly.
          </p>

          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-500 dark:text-slate-400">Status:</span>
            {user.mfaEnabled ? (
              <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400 font-medium"><ShieldCheck className="w-3.5 h-3.5" /> Enrolled</span>
            ) : user.mfaRequiredByAdmin ? (
              <span className="flex items-center gap-1.5 text-amber-600 dark:text-amber-400 font-medium"><ShieldAlert className="w-3.5 h-3.5" /> Required, not yet set up</span>
            ) : (
              <span className="text-slate-500 dark:text-slate-400">Not enabled</span>
            )}
          </div>

          <label className="flex items-center justify-between gap-3 cursor-pointer pt-2 border-t border-slate-200 dark:border-slate-800">
            <div>
              <p className="text-sm text-slate-700 dark:text-slate-300">Require two-factor authentication</p>
              <p className="text-xs text-slate-400 dark:text-slate-600">Prompts setup at this user's next login</p>
            </div>
            <button
              type="button"
              disabled={submitting}
              onClick={() => toggleRequired(!user.mfaRequiredByAdmin)}
              className={`relative flex-shrink-0 w-10 h-5.5 rounded-full transition-colors disabled:opacity-60 ${user.mfaRequiredByAdmin ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'}`}
              aria-pressed={!!user.mfaRequiredByAdmin}
              aria-label="Require two-factor authentication"
            >
              <span className={`absolute top-0.5 left-0.5 w-4.5 h-4.5 rounded-full bg-white shadow transition-transform ${user.mfaRequiredByAdmin ? 'translate-x-[19px]' : 'translate-x-0'}`} />
            </button>
          </label>

          {user.mfaEnabled && (
            <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
              {confirmReset ? (
                <div className="space-y-2">
                  <p className="text-xs text-red-500 dark:text-red-400">
                    This clears their authenticator enrollment and backup codes (lost-device recovery). They'll need to set 2FA up again.
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setConfirmReset(false)}
                      className="flex-1 py-2 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleReset}
                      disabled={submitting}
                      className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold text-white bg-red-500 hover:bg-red-400 disabled:opacity-60 transition-colors"
                    >
                      {submitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Resetting…</> : 'Confirm reset'}
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmReset(true)}
                  className="w-full py-2 rounded-lg border border-red-500/30 text-red-500 dark:text-red-400 text-xs font-semibold hover:bg-red-500/10 transition-colors"
                >
                  Reset two-factor authentication
                </button>
              )}
            </div>
          )}
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
  const [mfaTarget, setMfaTarget] = useState<MediUser | null>(null);

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
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Users</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Manage admin and SOC analyst accounts</p>
        </div>
        <button
          onClick={() => setModal({ mode: 'create' })}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-sm font-semibold transition-colors"
        >
          <Plus className="w-4 h-4" /> Add User
        </button>
      </div>

      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading users…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : users.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">No users yet.</p>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <th className="py-2.5 px-5 text-left">Name</th>
                <th className="py-2.5 px-5 text-left">Email</th>
                <th className="py-2.5 px-5 text-left">Role</th>
                <th className="py-2.5 px-5 text-left">Joined</th>
                <th className="py-2.5 px-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-5">
                    <div className="flex items-center gap-3">
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-slate-900 dark:text-white flex-shrink-0 ${
                        u.role === 'admin' ? 'bg-gradient-to-br from-red-400 to-orange-500' : 'bg-gradient-to-br from-cyan-500 to-blue-600'
                      }`}>
                        {u.name?.[0]?.toUpperCase()}
                      </div>
                      <span className="text-sm text-slate-900 dark:text-white font-medium">
                        {u.name}{u.id === currentUserId && <span className="text-slate-400 dark:text-slate-500 font-normal"> (you)</span>}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-5 text-sm text-slate-500 dark:text-slate-400">{u.email}</td>
                  <td className="py-3 px-5">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${
                      u.role === 'admin'
                        ? 'text-red-400 bg-red-500/10 border-red-500/30'
                        : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
                    }`}>
                      {roleLabel(u.role)}
                    </span>
                  </td>
                  <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500">
                    {u.createdAt ? new Date(u.createdAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '—'}
                  </td>
                  <td className="py-3 px-5 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setModal({ mode: 'edit', user: u })}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                      >
                        <Pencil className="w-3.5 h-3.5" /> Edit
                      </button>
                      {u.role !== 'admin' && (
                        <button
                          onClick={() => setMfaTarget(u)}
                          title="Administrators can only configure their own two-factor authentication"
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-emerald-500 hover:bg-emerald-500/10 transition-colors"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" /> 2FA
                        </button>
                      )}
                      {u.id !== currentUserId && (
                        <button
                          onClick={() => setDeleteTarget(u)}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
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

      {mfaTarget && (
        <MfaControlModal
          user={mfaTarget}
          token={token}
          onClose={() => setMfaTarget(null)}
          onUpdated={(u) => {
            setUsers((prev) => prev.map((existing) => (existing.id === u.id ? u : existing)));
            setMfaTarget(u);
          }}
        />
      )}
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
  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 whitespace-nowrap">
    <span className={`w-1.5 h-1.5 rounded-full ${osCategoryDot[category]}`} />
    <span className="text-xs text-slate-700 dark:text-slate-300">{OS_CATEGORY_LABELS[category]}</span>
  </span>
);

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
      <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">Manage Device Groups</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
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
              className="flex-1 px-3 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all"
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newName.trim()}
              className="flex items-center gap-1.5 px-3 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-60 disabled:cursor-not-allowed text-slate-900 dark:text-white text-sm font-semibold rounded-lg transition-all"
            >
              {creating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            </button>
          </div>

          <div className="space-y-1.5 max-h-72 overflow-y-auto">
            {groups.length === 0 && (
              <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-6">No groups yet. Create one above.</p>
            )}
            {groups.map((g) => (
              <div key={g.id} className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                {editing?.id === g.id ? (
                  <input
                    autoFocus
                    value={editing.name}
                    onChange={(e) => setEditing({ id: g.id, name: e.target.value })}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleRename(g.id); if (e.key === 'Escape') setEditing(null); }}
                    className="flex-1 px-2 py-1 bg-white dark:bg-slate-900 border border-cyan-500/40 rounded-md text-sm text-slate-900 dark:text-white focus:outline-none"
                  />
                ) : (
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-900 dark:text-white font-medium truncate">{g.name}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500">{g.deviceCount} device{g.deviceCount === 1 ? '' : 's'}</p>
                  </div>
                )}

                {busyId === g.id ? (
                  <Loader2 className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 animate-spin flex-shrink-0" />
                ) : editing?.id === g.id ? (
                  <>
                    <button onClick={() => handleRename(g.id)} className="text-emerald-400 hover:text-emerald-300 text-xs font-medium px-1.5 flex-shrink-0">Save</button>
                    <button onClick={() => setEditing(null)} className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 text-xs px-1.5 flex-shrink-0">Cancel</button>
                  </>
                ) : (
                  <>
                    <button onClick={() => setEditing({ id: g.id, name: g.name })} className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors p-1 flex-shrink-0">
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => handleDelete(g.id)} className="text-slate-500 dark:text-slate-400 hover:text-red-400 transition-colors p-1 flex-shrink-0">
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
    groups, deviceMeta, createGroup, renameGroup, deleteGroup, assignGroups, tagMedicalDevice,
  } = useDeviceMeta(token);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);
  const [showGroupsModal, setShowGroupsModal] = useState(false);
  const [osFilter, setOsFilter] = useState<OsCategory | 'all'>('all');
  const [groupFilter, setGroupFilter] = useState<string>('all');
  const [deviceSubTab, setDeviceSubTab] = useState<'network' | 'medical'>('network');
  const [medicalDevices, setMedicalDevices] = useState<MedicalDevice[]>([]);

  useEffect(() => {
    if (!token) return;
    // Re-fetches on every subtab switch (not just token change) so onboarding/
    // editing a device on the 'medical' subtab is reflected in the Tag Medical
    // Device dropdown immediately after switching back to 'network' — this
    // component stays mounted across the switch, so without deviceSubTab in
    // the deps that list would otherwise go stale until a token change/reload.
    getMedicalDevices(token).then(setMedicalDevices).catch(() => {});
  }, [token, deviceSubTab]);

  const metaByAgent = useMemo(() => new Map(deviceMeta.map((m) => [m.agentId, m])), [deviceMeta]);

  const normalizedStatuses = agents.map((a) => normalizeAgentStatus(a.status));
  const counts = {
    total: agents.length,
    active: normalizedStatuses.filter((s) => s === 'active').length,
    disconnected: normalizedStatuses.filter((s) => s === 'disconnected').length,
    other: normalizedStatuses.filter((s) => s !== 'active' && s !== 'disconnected').length,
  };
  // "Online" = actively reporting; disconnected/pending/never-connected all count as "Offline" here.
  const onlineOfflineData = [
    { name: 'Online', value: counts.active, color: '#10b981' },
    { name: 'Offline', value: counts.total - counts.active, color: '#ef4444' },
  ];

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

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Devices</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            {deviceSubTab === 'network'
              ? `Live IoMT / endpoint inventory from Wazuh SIEM${lastRefresh ? ` · Updated ${lastRefresh.toLocaleTimeString()}` : ''}`
              : 'Onboarded clinical assets — independent of Wazuh enrollment'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGroupsModal(true)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors"
          >
            <Settings className="w-3.5 h-3.5" /> Manage Groups
          </button>
          {deviceSubTab === 'network' && (
            <button
              onClick={refresh}
              disabled={!connected || loadingAgents}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : ''}`} /> Refresh
            </button>
          )}
        </div>
      </div>

      <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl w-fit">
        {([
          { id: 'network', label: 'Network Devices', icon: <Server className="w-3.5 h-3.5" /> },
          { id: 'medical', label: 'Medical Device Inventory', icon: <Tag className="w-3.5 h-3.5" /> },
        ] as { id: 'network' | 'medical'; label: string; icon: React.ReactNode }[]).map((t) => (
          <button
            key={t.id}
            onClick={() => setDeviceSubTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              deviceSubTab === t.id
                ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {deviceSubTab === 'medical' ? (
        <MedicalDeviceInventoryPanel groups={groups} createGroup={createGroup} />
      ) : !config ? (
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Server className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh SIEM is not connected</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Connect it under Settings → Wazuh SIEM to see live device data here.</p>
        </div>
      ) : (
        <>
          {connectionError && !connected && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" /> {connectionError}
            </div>
          )}

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard icon={<Server />} label="Total Devices" value={String(counts.total)} sub="Registered agents" color="slate" />
            <StatCard icon={<CheckCircle />} label="Active" value={String(counts.active)} sub="Online now" color="emerald" />
            <StatCard icon={<AlertTriangle />} label="Disconnected" value={String(counts.disconnected)} sub="Needs attention" color="red" />
            <StatCard icon={<Clock />} label="Other" value={String(counts.other)} sub="Pending / never connected" color="amber" />
          </div>

          <ChartCard title="Online vs offline" subtitle="Live device inventory" height={160} empty={counts.total === 0}>
            <DonutChart data={onlineOfflineData} />
          </ChartCard>

          <div className="flex items-center gap-3 flex-wrap">
            <span className="flex items-center gap-1.5 text-xs text-slate-400 dark:text-slate-500">
              <Filter className="w-3.5 h-3.5" /> Filter
            </span>
            <select
              value={osFilter}
              onChange={(e) => setOsFilter(e.target.value as OsCategory | 'all')}
              className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="all">All OS types</option>
              {(Object.keys(OS_CATEGORY_LABELS) as OsCategory[]).map((c) => (
                <option key={c} value={c}>{OS_CATEGORY_LABELS[c]}</option>
              ))}
            </select>
            <select
              value={groupFilter}
              onChange={(e) => setGroupFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="all">All groups</option>
              <option value="ungrouped">Ungrouped</option>
              {groups.map((g) => (
                <option key={g.id} value={g.name}>{g.name}</option>
              ))}
            </select>
          </div>

          <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
            {(connecting || loadingAgents) && agents.length === 0 ? (
              <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading devices…
              </div>
            ) : filteredAgents.length === 0 ? (
              <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">
                {agents.length === 0 ? 'No devices found.' : 'No devices match the current filters.'}
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                      <th className="py-2.5 px-5 text-left">Status</th>
                      <th className="py-2.5 px-5 text-left">ID</th>
                      <th className="py-2.5 px-5 text-left">Name</th>
                      <th className="py-2.5 px-5 text-left">IP</th>
                      <th className="py-2.5 px-5 text-left">OS</th>
                      <th className="py-2.5 px-5 text-left">Category</th>
                      <th className="py-2.5 px-5 text-left">Medical Device</th>
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
                      <tr key={ag.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-5">
                          <span className="flex items-center gap-1.5">
                            <span className={`w-1.5 h-1.5 rounded-full ${deviceStatusDot[normalized] ?? 'bg-slate-600'}`} />
                            <span className="text-xs text-slate-500 dark:text-slate-400 capitalize">{normalized.replace('_', ' ')}</span>
                          </span>
                        </td>
                        <td className="py-3 px-5 font-mono text-xs text-slate-400 dark:text-slate-500">{ag.id}</td>
                        <td className="py-3 px-5 text-sm">
                          <button
                            onClick={() => setSelectedAgent(ag)}
                            className="text-slate-900 dark:text-white font-medium hover:text-cyan-400 transition-colors text-left"
                          >
                            {ag.name}
                          </button>
                        </td>
                        <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400 font-mono">{ag.ip ?? '—'}</td>
                        <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{formatOs(ag.os)}</td>
                        <td className="py-3 px-5"><OsCategoryBadge category={categoryFor(ag)} /></td>
                        <td className="py-3 px-5">
                          <MedicalDeviceTagDropdown
                            devices={medicalDevices}
                            tagged={metaByAgent.get(ag.id)?.medicalDevice ?? null}
                            onTag={(id) => tagMedicalDevice(ag.id, id, ag.name)}
                          />
                        </td>
                        <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500 font-mono">{ag.version ?? '—'}</td>
                        <td className="py-3 px-5">
                          <GroupAssignDropdown
                            agentGroups={groupsFor(ag)}
                            allGroups={groups}
                            onToggle={(name) => toggleAgentGroup(ag, name)}
                            onCreateAndAssign={(name) => createAndAssign(ag, name)}
                          />
                        </td>
                        <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
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
        </>
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
        title="Wazuh alerts (severity 8+)"
        aria-label={`Wazuh alerts, severity 8 and above${count > 0 ? ` — ${count} shown` : ''}`}
        className="relative p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
      >
        <Bell className="w-4 h-4" />
        {count > 0 && (
          <span className="absolute top-1 right-1 min-w-[14px] h-3.5 px-0.5 flex items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-slate-900 dark:text-white leading-none">
            {count > 9 ? '9+' : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-12 w-80 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-2xl shadow-2xl overflow-hidden z-50">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
            <p className="text-sm font-semibold text-slate-900 dark:text-white">Notifications</p>
            <button onClick={() => setOpen(false)} aria-label="Close" className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="max-h-80 overflow-y-auto">
            {!config ? (
              <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8 px-4">
                Connect Wazuh SIEM in Settings to see alert notifications here.
              </p>
            ) : !indexerReady ? (
              <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8 px-4">
                Configure the Wazuh Indexer in Settings → Wazuh SIEM to see alert notifications here.
              </p>
            ) : loading ? (
              <div className="flex items-center justify-center gap-2 py-8 text-slate-400 dark:text-slate-500 text-xs">
                <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading…
              </div>
            ) : error ? (
              <p className="text-xs text-red-400 text-center py-8 px-4">{error}</p>
            ) : alerts.length === 0 ? (
              <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8 px-4">No high-severity alerts right now.</p>
            ) : (
              <div className="divide-y divide-slate-200 dark:divide-slate-800">
                {alerts.map((al) => (
                  <div key={al.id} className="px-4 py-3 hover:bg-slate-100 dark:hover:bg-slate-800/40 transition-colors">
                    <div className="flex items-start gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${severityDot(al.ruleLevel ?? 0)}`} />
                      <div className="min-w-0">
                        <p className="text-xs text-slate-900 dark:text-white font-medium truncate">{al.ruleDescription ?? 'Unknown alert'}</p>
                        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 truncate">
                          {al.agentName ?? 'Unknown agent'}{al.agentIp ? ` · ${al.agentIp}` : ''}
                        </p>
                        <p className="text-xs text-slate-400 dark:text-slate-600 mt-0.5">
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
            className="w-full px-4 py-2.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 border-t border-slate-200 dark:border-slate-800 transition-colors font-medium"
          >
            View all alerts →
          </button>
        </div>
      )}
    </div>
  );
};


// ─── Overview tab (real data — must render inside <WazuhProvider> for device counts) ──
const OverviewTab: React.FC<{
  userName?: string;
  liveAlerts: EnrichedAlert[];
  alertsConnected: boolean;
  alertsLoading: boolean;
  alertsError: string | null;
  presenceSummary: import('../../services/api').PresenceSummary | null;
  presenceLoading: boolean;
  presenceError: string;
  onViewAllAlerts: () => void;
  // Cumulative since the backend process started — see useLiveAlerts.ts.
  // Falls back to buffer-derived counts if omitted.
  alertsSeverityTotals?: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
}> = ({
  userName, liveAlerts, alertsConnected, alertsLoading, alertsError, presenceSummary, presenceLoading, presenceError,
  onViewAllAlerts, alertsSeverityTotals,
}) => {
  const { agents, connected: wazuhConnected } = useWazuhContext();

  // Closed cases have their own dedicated views (Case Status) — the Overview
  // tab is a "what's still live" snapshot, same as the Alerts tab, so
  // anything already closed is excluded from every KPI/chart/table here too.
  const liveOpenAlerts = useMemo(() => liveAlerts.filter((a) => !a.closure), [liveAlerts]);

  const criticalCount = alertsSeverityTotals?.CRITICAL ?? liveOpenAlerts.filter((a) => casToSeverity(a.CAS) === 'CRITICAL').length;
  // Anchored to the newest alert actually in the buffer, not wall-clock now —
  // see latestTimestamp()'s doc comment for why (matches the timeline chart below).
  const alertsAnchor = latestTimestamp(liveOpenAlerts, (a) => a.timestamp);
  const last24h = liveOpenAlerts.filter((a) => alertsAnchor - new Date(a.timestamp).getTime() <= 24 * 60 * 60 * 1000).length;

  const timeline = useMemo(
    () => bucketAlertsByHour(liveOpenAlerts, (a) => a.timestamp, (a) => casToSeverity(a.CAS), 24),
    [liveOpenAlerts]
  );
  const severityDist = useMemo(() => {
    if (alertsSeverityTotals) {
      return SEVERITY_ORDER.map((name) => ({ name, value: alertsSeverityTotals[name], color: SEVERITY_COLORS[name] }));
    }
    return severityCounts(liveOpenAlerts, (a) => casToSeverity(a.CAS));
  }, [liveOpenAlerts, alertsSeverityTotals]);
  const topAlertTypes = useMemo(
    () => countBy(liveOpenAlerts, (a) => (a.label !== 'Unclassified' ? a.label : a.ruleDescription)),
    [liveOpenAlerts]
  );
  const byDepartment = useMemo(() => countBy(liveOpenAlerts, (a) => a.department), [liveOpenAlerts]);

  return (
    <div className="p-5 space-y-6">
      {/* KPI tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<AlertTriangle />} label="Critical Alerts" value={String(criticalCount)} sub="CAS ≥ 8 · current buffer" color="red" />
        <StatCard
          icon={<Activity />}
          label="Monitored Devices"
          value={wazuhConnected ? String(agents.length) : '—'}
          sub={wazuhConnected ? 'IoMT / endpoint agents' : 'Connect Wazuh SIEM'}
          color="slate"
        />
        <StatCard
          icon={<Users />}
          label="Logged In Now"
          value={presenceSummary ? String(presenceSummary.admins.online + presenceSummary.analysts.online) : '—'}
          sub={presenceSummary ? `${presenceSummary.admins.online} admin · ${presenceSummary.analysts.online} analyst` : 'Loading…'}
          color="slate"
        />
        <StatCard icon={<TrendingUp />} label="Alerts (24h)" value={String(last24h)} sub="In current buffer" color="slate" />
      </div>

      {/* Team Presence */}
      <PresenceWidget summary={presenceSummary} loading={presenceLoading} error={presenceError} />

      {/* Alert volume + severity mix */}
      <div className="grid lg:grid-cols-3 gap-5">
        <ChartCard title="Alert volume (24h)" subtitle="Stacked by severity, current buffer" height={220} empty={liveOpenAlerts.length === 0} className="lg:col-span-2">
          <AlertsTimelineChart data={timeline} />
        </ChartCard>
        <ChartCard title="Severity mix" subtitle="Current buffer" height={220} empty={liveOpenAlerts.length === 0}>
          <SeverityDonutChart data={severityDist} />
        </ChartCard>
      </div>

      {/* Top alert types + by department */}
      <div className="grid lg:grid-cols-2 gap-5">
        <ChartCard title="Top alert types" subtitle="Most frequent classifications" height={220} empty={topAlertTypes.length === 0}>
          <TopBarChart data={topAlertTypes} color="#06b6d4" />
        </ChartCard>
        <ChartCard title="Alerts by department" subtitle="Clinical context breakdown" height={220} empty={byDepartment.length === 0}>
          <TopBarChart data={byDepartment} color="#8b5cf6" />
        </ChartCard>
      </div>

      {/* Alerts Table */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="font-semibold text-slate-900 dark:text-white">Active Security Alerts</h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Sorted by Clinical Alert Score (CAS)</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
              <span className={`w-2 h-2 rounded-full ${alertsConnected ? 'bg-emerald-500' : 'bg-red-500'}`} />
              {alertsConnected ? 'Live' : 'Reconnecting…'}
            </div>
            <button
              onClick={onViewAllAlerts}
              className="px-3 py-1.5 text-xs rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-400 dark:text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-900 dark:text-white transition-colors"
            >
              View All
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <th className="py-2.5 px-4 text-left">Severity</th>
                <th className="py-2.5 px-4 text-left">Device</th>
                <th className="py-2.5 px-4 text-left">Event</th>
                <th className="py-2.5 px-4 text-left">CAS Score</th>
                <th className="py-2.5 px-4 text-left">Time</th>
                <th className="py-2.5 px-4 text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {alertsLoading && (
                <tr><td colSpan={6} className="py-6 text-center text-sm text-slate-400 dark:text-slate-500">Loading alerts…</td></tr>
              )}
              {alertsError && (
                <tr><td colSpan={6} className="py-6 text-center text-sm text-red-500 dark:text-red-400">{alertsError}</td></tr>
              )}
              {!alertsLoading && !alertsError && liveOpenAlerts.length === 0 && (
                <tr><td colSpan={6} className="py-6 text-center text-sm text-slate-400 dark:text-slate-500">No open alerts.</td></tr>
              )}
              {liveOpenAlerts.slice(0, 5).map((a) => (
                <AlertRow
                  key={a.id}
                  severity={casToSeverity(a.CAS)}
                  device={a.agent}
                  event={a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                  cas={a.CAS}
                  time={new Date(a.timestamp).toLocaleTimeString()}
                  status={actionToStatus(a.action)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <div className="text-center py-4 text-xs text-slate-500 dark:text-slate-400 dark:text-slate-700">
        MediSIEM Admin Console · R26-CS-008 · SLIIT 2026 · Logged in as {userName}
      </div>
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
  const { summary: presenceSummary, loading: presenceLoading, error: presenceError } = usePresenceSummary(token);
  const {
    alerts: liveAlerts,
    connected: alertsConnected,
    loading: alertsLoading,
    error: alertsError,
    totalCount: alertsTotalCount,
    severityTotals: alertsSeverityTotals,
  } = useLiveAlerts(token);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const goToSecuritySettings = () => {
    setShowAccountMenu(false);
    setSettingsOpen(true);
    setActiveNav('Security');
  };

  const navItems = [
    { label: 'Overview', icon: <BarChart3 className="w-4 h-4" /> },
    { label: 'Alerts', icon: <Bell className="w-4 h-4" /> },
    { label: 'Events by Device', icon: <Radio className="w-4 h-4" /> },
    { label: 'Case Status', icon: <CheckCircle className="w-4 h-4" /> },
    { label: 'Devices', icon: <Server className="w-4 h-4" /> },
    { label: 'Vulnerabilities', icon: <Bug className="w-4 h-4" /> },
    { label: 'IP Reputation', icon: <Network className="w-4 h-4" /> },
    { label: 'Detection Performance', icon: <Gauge className="w-4 h-4" /> },
    { label: 'Playbooks', icon: <Zap className="w-4 h-4" /> },
  ];

  const settingsSubItems = [
    { label: 'Users', icon: <Users className="w-3.5 h-3.5" /> },
    { label: 'Wazuh SIEM', icon: <Shield className="w-3.5 h-3.5" /> },
    { label: 'Detection Rules', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
    { label: 'Security', icon: <KeyRound className="w-3.5 h-3.5" /> },
    { label: 'Integrations', icon: <Plug className="w-3.5 h-3.5" /> },
    { label: 'CAS Weights', icon: <SlidersHorizontal className="w-3.5 h-3.5" /> },
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
    <div className="h-screen overflow-hidden bg-white dark:bg-slate-950 text-slate-900 dark:text-white flex flex-col">

      {/* ── Below-banner layout: sidebar + main ── */}
      <div className="flex flex-1 min-h-0">

        {/* Sidebar */}
        <aside
          className={`no-print fixed inset-y-0 left-0 z-40 flex flex-col w-64 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 transition-transform duration-300 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } lg:translate-x-0 lg:static lg:z-auto`}
        >
          {/* Logo */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 bg-slate-900 dark:bg-white rounded-md flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyan-400 dark:text-slate-900" strokeWidth={2.5} />
              </div>
              <span className="font-bold text-[15px] text-slate-900 dark:text-white tracking-tight">
                MediSIEM
              </span>
            </div>
            <button onClick={() => setSidebarOpen(false)} aria-label="Close sidebar" className="lg:hidden text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Role Badge */}
          <div className="flex items-center gap-1.5 px-5 py-2.5 border-b border-slate-200 dark:border-slate-800">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
            <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Admin Console</span>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            {navItems.map((item) => (
              <button
                key={item.label}
                onClick={() => setActiveNav(item.label)}
                className={`relative w-full flex items-center gap-3 pl-3.5 pr-3 py-2 rounded-md text-[13px] font-medium transition-colors text-left ${
                  activeNav === item.label
                    ? 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-cyan-500'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/40'
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
              className={`relative w-full flex items-center gap-3 pl-3.5 pr-3 py-2 rounded-md text-[13px] font-medium transition-colors text-left ${
                isComplianceActive
                  ? 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-cyan-500'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/40'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              Compliances
              <ChevronDown className={`w-3.5 h-3.5 ml-auto transition-transform ${complianceOpen || isComplianceActive ? 'rotate-180' : ''}`} />
            </button>

            {(complianceOpen || isComplianceActive) && (
              <div className="ml-3 pl-3 border-l border-slate-200 dark:border-slate-800 space-y-0.5">
                {complianceSubItems.map((item) => (
                  <button
                    key={item.label}
                    onClick={() => setActiveNav(item.label)}
                    className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] font-medium transition-colors text-left ${
                      activeNav === item.label
                        ? 'text-cyan-600 dark:text-cyan-400'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
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
              className={`relative w-full flex items-center gap-3 pl-3.5 pr-3 py-2 rounded-md text-[13px] font-medium transition-colors text-left ${
                isSettingsActive
                  ? 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-cyan-500'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/40'
              }`}
            >
              <Settings className="w-4 h-4" />
              Settings
              <ChevronDown className={`w-3.5 h-3.5 ml-auto transition-transform ${settingsOpen || isSettingsActive ? 'rotate-180' : ''}`} />
            </button>

            {(settingsOpen || isSettingsActive) && (
              <div className="ml-3 pl-3 border-l border-slate-200 dark:border-slate-800 space-y-0.5">
                {settingsSubItems.map((item) => (
                  <button
                    key={item.label}
                    onClick={() => setActiveNav(item.label)}
                    className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] font-medium transition-colors text-left ${
                      activeNav === item.label
                        ? 'text-cyan-600 dark:text-cyan-400'
                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
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
          <div className="px-4 py-3.5 border-t border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-full bg-slate-800 dark:bg-slate-700 flex items-center justify-center text-[11px] font-bold text-white flex-shrink-0">
                {user?.name?.[0]?.toUpperCase()}
              </div>
              <div className="min-w-0">
                <div className="text-[13px] font-medium text-slate-900 dark:text-white truncate">{user?.name}</div>
                <div className="text-[11px] text-slate-400 dark:text-slate-500 truncate">{user?.email}</div>
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
          <header className="no-print sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-white/90 dark:bg-slate-950/90 backdrop-blur border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-3">
              <button onClick={() => setSidebarOpen(true)} className="lg:hidden p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                <Menu className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-[13px] font-semibold text-slate-900 dark:text-white">Admin Dashboard</h1>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 hidden sm:block">R26-CS-008 · MediSIEM Platform</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="hidden sm:flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                <span className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">System active</span>
              </div>
              <button
                onClick={() => window.open('/wallboard', '_blank', 'noopener,noreferrer')}
                title="Open SOC wallboard in a new tab"
                className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 text-[12px] font-medium transition-colors"
              >
                <Tv className="w-3.5 h-3.5" /> Wallboard
              </button>
              <div className="flex items-center gap-1">
                <SoundToggle />
                <ThemeToggle />
                <NotificationCenterBell />
                <NotificationBell onViewAll={() => setActiveNav('Wazuh SIEM')} />
              </div>
              <div className="relative pl-4 border-l border-slate-200 dark:border-slate-800">
                <button
                  onClick={() => setShowAccountMenu(!showAccountMenu)}
                  className="flex items-center gap-2"
                >
                  <div className="w-7 h-7 rounded-full bg-slate-800 dark:bg-slate-700 flex items-center justify-center text-[11px] font-bold text-white">
                    {user?.name?.[0]?.toUpperCase()}
                  </div>
                  <ChevronDown className={`w-3.5 h-3.5 text-slate-400 dark:text-slate-500 transition-transform ${showAccountMenu ? 'rotate-180' : ''}`} />
                </button>

                {showAccountMenu && (
                  <AccountMenu
                    token={token}
                    userId={user?.id}
                    onClose={() => setShowAccountMenu(false)}
                    onLogout={handleLogout}
                    onOpenSecuritySettings={goToSecuritySettings}
                  />
                )}
              </div>
            </div>
          </header>

          {/* Org policy requires 2FA and this admin hasn't enrolled yet — see
              routes/auth.js's isMfaSetupRequired(). Persistent (not
              dismissible) since it reflects an actual org policy, not a tip. */}
          {user?.mfaSetupRequired && (
            <div className="no-print flex items-center justify-between gap-3 px-5 py-2 bg-amber-500/10 border-b border-amber-500/20 text-amber-700 dark:text-amber-400 text-xs">
              <span className="flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
                Two-factor authentication is required for admin accounts on this deployment.
              </span>
              <button
                onClick={goToSecuritySettings}
                className="flex-shrink-0 px-2.5 py-1 rounded-md bg-amber-500/20 hover:bg-amber-500/30 font-semibold transition-colors"
              >
                Set up now
              </button>
            </div>
          )}

          {/* A switch, not a chain of activeNav checks, so each nav item renders exactly one panel. */}
          <main className="flex-1 overflow-y-auto">
            {(() => {
              switch (activeNav) {
                case 'Wazuh SIEM':
                  return <WazuhDashboard />;
                case 'Users':
                  return <UsersPanel token={token} currentUserId={user?.id} />;
                case 'Detection Rules':
                  return <RulesPanel />;
                case 'Security':
                  return <SecuritySettingsPanel />;
                case 'Integrations':
                  return <IntegrationsSettingsPanel token={token} />;
                case 'CAS Weights':
                  return <CasWeightsSettingsPanel token={token} />;
                case 'Audit Log':
                  return <AuditLogPanel token={token} />;
                case 'Devices':
                  return <DevicesPanel />;
                case 'Alerts':
                  return (
                    <AlertsPanel
                      alerts={liveAlerts}
                      connected={alertsConnected}
                      loading={alertsLoading}
                      error={alertsError}
                      token={token}
                      totalCount={alertsTotalCount}
                      severityTotals={alertsSeverityTotals}
                    />
                  );
                case 'Events by Device':
                  return <DeviceEventsPanel />;
                case 'Case Status':
                  return (
                    <AdminCasesPanel
                      alerts={liveAlerts}
                      loading={alertsLoading}
                      error={alertsError}
                      token={token}
                    />
                  );
                case 'Vulnerabilities':
                  return <VulnerabilitiesPanel />;
                case 'Detection Performance':
                  return <DetectionPerformancePanel />;
                case 'Playbooks':
                  return <PlaybooksPanel />;
                case 'HIPAA':
                  return <CompliancePanel framework="hipaa" />;
                case 'GDPR':
                  return <CompliancePanel framework="gdpr" />;
                case 'CIS':
                  return <CompliancePanel framework="cis" />;
                default:
                  return (
                    <OverviewTab
                      userName={user?.name}
                      liveAlerts={liveAlerts}
                      alertsConnected={alertsConnected}
                      alertsLoading={alertsLoading}
                      alertsError={alertsError}
                      presenceSummary={presenceSummary}
                      presenceLoading={presenceLoading}
                      presenceError={presenceError}
                      onViewAllAlerts={() => setActiveNav('Alerts')}
                      alertsSeverityTotals={alertsSeverityTotals}
                    />
                  );
              }
            })()}
          </main>
        </div>
      </div>
    </div>
    </WazuhProvider>
  );
};

export default AdminDashboard;
