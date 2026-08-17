import React, { useEffect, useState } from 'react';
import { X, Lock, LogOut, CheckCircle2, AlertCircle, Loader2, ShieldCheck, Copy, Settings } from 'lucide-react';
import { apiUpdateUser } from '../services/api';
import { apiGetPasswordPolicy } from '../services/passwordPolicyApi';
import type { PasswordPolicy } from '../services/passwordPolicyApi';
import { passwordMeetsPolicy } from '../utils/passwordPolicy';
import PasswordChecklist from './PasswordChecklist';
import { useAuth } from '../context/AuthContext';
import { apiMfaSetup, apiMfaConfirm, apiMfaDisable } from '../services/authExtrasApi';

// ─── Account dropdown: change password + two-factor auth + logout ─────────────
// When onOpenSecuritySettings is provided (admin usage only — AdminDashboard
// has a dedicated Settings → Security tab), the password/2FA sub-views are
// replaced by a single shortcut into that tab instead of duplicating them
// here. Non-admin dashboards have no such tab, so they omit the prop and
// keep the full self-service password + 2FA flow below.
const AccountMenu: React.FC<{
  token: string | null;
  userId?: string;
  onClose: () => void;
  onLogout: () => void;
  initialView?: 'menu' | 'mfa';
  onOpenSecuritySettings?: () => void;
}> = ({ token, userId, onClose, onLogout, initialView = 'menu', onOpenSecuritySettings }) => {
  const { user, refreshUser } = useAuth();
  const [view, setView] = useState<'menu' | 'password' | 'mfa'>(initialView);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy | null>(null);

  // ─── MFA state ────────────────────────────────────────────────────────────
  const [mfaStep, setMfaStep] = useState<'idle' | 'enrolling' | 'backupCodes' | 'disabling'>('idle');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [disablePassword, setDisablePassword] = useState('');
  const [mfaError, setMfaError] = useState('');
  const [mfaSubmitting, setMfaSubmitting] = useState(false);

  useEffect(() => {
    if (!token) return;
    apiGetPasswordPolicy(token).then((data) => setPasswordPolicy(data.policy)).catch(() => {});
  }, [token]);

  const startEnroll = async () => {
    if (!token) return;
    setMfaSubmitting(true);
    setMfaError('');
    try {
      const { secret, qrDataUrl: qr } = await apiMfaSetup(token);
      setMfaSecret(secret);
      setQrDataUrl(qr);
      setMfaStep('enrolling');
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to start two-factor setup.');
    } finally {
      setMfaSubmitting(false);
    }
  };

  const confirmEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !mfaCode) return;
    setMfaSubmitting(true);
    setMfaError('');
    try {
      const { backupCodes: codes } = await apiMfaConfirm(token, mfaCode.trim());
      setBackupCodes(codes);
      setMfaStep('backupCodes');
      setMfaCode('');
      await refreshUser();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Invalid code — check your authenticator app and try again.');
    } finally {
      setMfaSubmitting(false);
    }
  };

  const disableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !disablePassword) return;
    setMfaSubmitting(true);
    setMfaError('');
    try {
      await apiMfaDisable(token, disablePassword);
      setDisablePassword('');
      setMfaStep('idle');
      await refreshUser();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to disable two-factor authentication.');
    } finally {
      setMfaSubmitting(false);
    }
  };

  const finishEnrollment = () => {
    setMfaStep('idle');
    setBackupCodes([]);
    setQrDataUrl('');
    setMfaSecret('');
    setView('menu');
  };

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
    <div className={`absolute right-0 top-12 ${view === 'mfa' ? 'w-80' : 'w-72'} bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-xl shadow-2xl overflow-hidden z-50`}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
        {view === 'password' ? (
          <button
            onClick={() => { setView('menu'); setError(''); setSuccess(false); }}
            className="text-sm font-semibold text-slate-900 dark:text-white hover:text-cyan-400 transition-colors"
          >
            ← Change Password
          </button>
        ) : view === 'mfa' ? (
          <button
            onClick={() => { setView('menu'); setMfaStep('idle'); setMfaError(''); }}
            className="text-sm font-semibold text-slate-900 dark:text-white hover:text-cyan-400 transition-colors"
          >
            ← Two-Factor Authentication
          </button>
        ) : (
          <p className="text-sm font-semibold text-slate-900 dark:text-white">Account</p>
        )}
        <button onClick={onClose} aria-label="Close" className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors">
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {view === 'menu' ? (
        <div className="py-1.5">
          {onOpenSecuritySettings ? (
            <button
              onClick={() => { onClose(); onOpenSecuritySettings(); }}
              className="w-full flex items-center justify-between gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <span className="flex items-center gap-2.5"><Settings className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Security Settings</span>
              {user?.mfaEnabled && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium">2FA on</span>}
            </button>
          ) : (
            <>
              <button
                onClick={() => setView('password')}
                className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <Lock className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Change Password
              </button>
              <button
                onClick={() => setView('mfa')}
                className="w-full flex items-center justify-between gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <span className="flex items-center gap-2.5"><ShieldCheck className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Two-Factor Authentication</span>
                {user?.mfaEnabled && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium">On</span>}
              </button>
            </>
          )}
          <button
            onClick={() => { onClose(); onLogout(); }}
            className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-300 hover:text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="w-4 h-4 text-slate-400 dark:text-slate-500" /> Logout
          </button>
        </div>
      ) : view === 'mfa' ? (
        <div className="px-4 py-4 space-y-3">
          {mfaError && (
            <div className="flex items-start gap-1.5 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>{mfaError}</span>
            </div>
          )}

          {mfaStep === 'backupCodes' ? (
            <div className="space-y-3">
              <div className="flex items-start gap-1.5 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 text-xs">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>Save these one-time backup codes now — each works once, and this is the only time they're shown.</span>
              </div>
              <div className="grid grid-cols-2 gap-1.5 p-3 rounded-lg bg-slate-100 dark:bg-slate-800 font-mono text-xs text-slate-700 dark:text-slate-300">
                {backupCodes.map((c) => <span key={c}>{c}</span>)}
              </div>
              <button
                onClick={() => navigator.clipboard?.writeText(backupCodes.join('\n'))}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                <Copy className="w-3 h-3" /> Copy codes
              </button>
              <button
                onClick={finishEnrollment}
                className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
              >
                Done
              </button>
            </div>
          ) : user?.mfaEnabled ? (
            mfaStep === 'disabling' ? (
              <form onSubmit={disableMfa} className="space-y-3">
                <p className="text-xs text-slate-500 dark:text-slate-400">Enter your password to disable two-factor authentication.</p>
                <input
                  type="password"
                  className={input}
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  placeholder="Current password"
                  autoComplete="current-password"
                />
                <button
                  type="submit"
                  disabled={mfaSubmitting || !disablePassword}
                  className="w-full flex items-center justify-center gap-2 py-2 bg-red-500 hover:bg-red-400 disabled:opacity-60 text-white text-xs font-semibold rounded-lg transition-colors"
                >
                  {mfaSubmitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Disabling…</> : 'Disable two-factor authentication'}
                </button>
              </form>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 text-xs font-medium">
                  <ShieldCheck className="w-4 h-4" /> Two-factor authentication is on
                </div>
                <button
                  onClick={() => { setMfaStep('disabling'); setMfaError(''); }}
                  className="w-full py-2 rounded-lg border border-red-500/30 text-red-500 dark:text-red-400 text-xs font-semibold hover:bg-red-500/10 transition-colors"
                >
                  Disable
                </button>
              </div>
            )
          ) : mfaStep === 'enrolling' ? (
            <form onSubmit={confirmEnroll} className="space-y-3">
              <p className="text-xs text-slate-500 dark:text-slate-400">Scan this QR code with your authenticator app, then enter the 6-digit code it shows.</p>
              {qrDataUrl && <img src={qrDataUrl} alt="Two-factor authentication QR code" className="w-40 h-40 mx-auto rounded-lg border border-slate-200 dark:border-slate-800" />}
              <p className="text-[10px] text-center text-slate-400 dark:text-slate-600 font-mono break-all">{mfaSecret}</p>
              <input
                type="text"
                inputMode="numeric"
                autoFocus
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
                className={`${input} pl-3 text-center tracking-[0.3em]`}
              />
              <button
                type="submit"
                disabled={mfaSubmitting || !mfaCode}
                className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
              >
                {mfaSubmitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Confirming…</> : 'Confirm & enable'}
              </button>
            </form>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Add an authenticator-app code as a second step at login, on top of your password.
              </p>
              <button
                onClick={startEnroll}
                disabled={mfaSubmitting}
                className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
              >
                {mfaSubmitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Starting…</> : 'Enable two-factor authentication'}
              </button>
            </div>
          )}
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
