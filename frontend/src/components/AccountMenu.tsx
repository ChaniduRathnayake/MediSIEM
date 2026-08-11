import React, { useEffect, useState } from 'react';
import { X, Lock, LogOut, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { apiUpdateUser } from '../services/api';
import { apiGetPasswordPolicy } from '../services/passwordPolicyApi';
import type { PasswordPolicy } from '../services/passwordPolicyApi';
import { passwordMeetsPolicy } from '../utils/passwordPolicy';
import PasswordChecklist from './PasswordChecklist';

// ─── Account dropdown: change password + logout ────────────────────────────────
const AccountMenu: React.FC<{
  token: string | null;
  userId?: string;
  onClose: () => void;
  onLogout: () => void;
}> = ({ token, userId, onClose, onLogout }) => {
  const [view, setView] = useState<'menu' | 'password'>('menu');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy | null>(null);

  useEffect(() => {
    if (!token) return;
    apiGetPasswordPolicy(token).then((data) => setPasswordPolicy(data.policy)).catch(() => {});
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError('All fields are required.');
      return;
    }
    if (passwordPolicy && !passwordMeetsPolicy(newPassword, passwordPolicy)) {
      setError('New password does not meet the policy requirements below.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }
    if (!token || !userId) {
      setError('Your session has expired. Please sign in again.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await apiUpdateUser(token, userId, { currentPassword, password: newPassword });
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update password.');
    } finally {
      setSubmitting(false);
    }
  };

  const input =
    'w-full pl-9 pr-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white ' +
    'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

  return (
    <div className="absolute right-0 top-12 w-72 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-xl shadow-2xl overflow-hidden z-50">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
        {view === 'password' ? (
          <button
            onClick={() => { setView('menu'); setError(''); setSuccess(false); }}
            className="text-sm font-semibold text-slate-900 dark:text-white hover:text-cyan-400 transition-colors"
          >
            ← Change Password
          </button>
        ) : (
          <p className="text-sm font-semibold text-slate-900 dark:text-white">Account</p>
        )}
        <button onClick={onClose} className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {view === 'menu' ? (
        <div className="py-1.5">
          <button
            onClick={() => setView('password')}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <Lock className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Change Password
          </button>
          <button
            onClick={() => { onClose(); onLogout(); }}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Logout
          </button>
        </div>
      ) : success ? (
        <div className="px-4 py-6 flex flex-col items-center text-center gap-2">
          <CheckCircle2 className="w-6 h-6 text-emerald-400" />
          <p className="text-xs text-slate-700 dark:text-slate-300">Password updated successfully.</p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="px-4 py-4 space-y-3">
          {error && (
            <div className="flex items-start gap-1.5 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="relative">
            <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
            <input
              type="password"
              className={input}
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Current password"
              autoComplete="current-password"
            />
          </div>

          <div className="relative">
            <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
            <input
              type="password"
              className={input}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="New password"
              autoComplete="new-password"
            />
          </div>
          {newPassword && <PasswordChecklist password={newPassword} policy={passwordPolicy} />}

          <div className="relative">
            <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
            <input
              type="password"
              className={input}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              autoComplete="new-password"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 text-xs font-semibold rounded-lg transition-colors"
          >
            {submitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Updating…</> : 'Update Password'}
          </button>
        </form>
      )}
    </div>
  );
};

export default AccountMenu;
