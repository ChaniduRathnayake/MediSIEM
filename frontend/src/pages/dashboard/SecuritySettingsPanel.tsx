// Admin Settings -> Security: where an admin manages their own 2FA/password
// plus the org-wide password policy. Per-user 2FA control for non-admins
// lives on the Users tab instead (see MfaControlModal in AdminDashboard.tsx).
import React, { useEffect, useState } from 'react';
import { Lock, ShieldCheck, AlertCircle, CheckCircle2, Loader2, Copy, KeyRound } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiUpdateUser } from '../../services/api';
import { apiGetPasswordPolicy } from '../../services/passwordPolicyApi';
import type { PasswordPolicy } from '../../services/passwordPolicyApi';
import { passwordMeetsPolicy } from '../../utils/passwordPolicy';
import PasswordChecklist from '../../components/PasswordChecklist';
import { apiMfaSetup, apiMfaConfirm, apiMfaDisable } from '../../services/authExtrasApi';
import PasswordPolicyPanel from './PasswordPolicyPanel';

const input =
  'w-full pl-9 pr-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white ' +
  'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

const SectionCard: React.FC<{ title: string; hint: string; children: React.ReactNode }> = ({ title, hint, children }) => (
  <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
    <div>
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{hint}</p>
    </div>
    {children}
  </div>
);

// ─── Change Password ─────────────────────────────────────────────────────────
const ChangePasswordSection: React.FC = () => {
  const { user, token } = useAuth();
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
    if (!token || !user?.id) {
      setError('Your session has expired. Please sign in again.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await apiUpdateUser(token, user.id, { currentPassword, password: newPassword });
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => setSuccess(false), 4000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update password.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <SectionCard title="Change Password" hint="Update your own account password">
      <form onSubmit={handleSubmit} className="space-y-3 max-w-sm">
        {error && (
          <div className="flex items-start gap-1.5 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
        {success && (
          <div className="flex items-center gap-1.5 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
            <span>Password updated successfully.</span>
          </div>
        )}

        <div className="relative">
          <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input type="password" className={input} value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" autoComplete="current-password" />
        </div>
        <div className="relative">
          <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input type="password" className={input} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password" autoComplete="new-password" />
        </div>
        {newPassword && <PasswordChecklist password={newPassword} policy={passwordPolicy} />}
        <div className="relative">
          <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input type="password" className={input} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm new password" autoComplete="new-password" />
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 text-sm font-semibold transition-colors"
        >
          {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Updating…</> : 'Update Password'}
        </button>
      </form>
    </SectionCard>
  );
};

// ─── Two-Factor Authentication (self-service) ────────────────────────────────
const TwoFactorSection: React.FC = () => {
  const { user, token, refreshUser } = useAuth();
  const [step, setStep] = useState<'idle' | 'enrolling' | 'backupCodes' | 'disabling'>('idle');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [disablePassword, setDisablePassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const startEnroll = async () => {
    if (!token) return;
    setSubmitting(true);
    setError('');
    try {
      const { secret: s, qrDataUrl: qr } = await apiMfaSetup(token);
      setSecret(s);
      setQrDataUrl(qr);
      setStep('enrolling');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start two-factor setup.');
    } finally {
      setSubmitting(false);
    }
  };

  const confirmEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !code) return;
    setSubmitting(true);
    setError('');
    try {
      const { backupCodes: codes } = await apiMfaConfirm(token, code.trim());
      setBackupCodes(codes);
      setStep('backupCodes');
      setCode('');
      await refreshUser();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid code — check your authenticator app and try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const disableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !disablePassword) return;
    setSubmitting(true);
    setError('');
    try {
      await apiMfaDisable(token, disablePassword);
      setDisablePassword('');
      setStep('idle');
      await refreshUser();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to disable two-factor authentication.');
    } finally {
      setSubmitting(false);
    }
  };

  const finishEnrollment = () => {
    setStep('idle');
    setBackupCodes([]);
    setQrDataUrl('');
    setSecret('');
  };

  return (
    <SectionCard title="Two-Factor Authentication" hint="Add an authenticator-app code as a second step at login, on top of your password">
      <div className="max-w-sm space-y-3">
        {error && (
          <div className="flex items-start gap-1.5 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {step === 'backupCodes' ? (
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
          step === 'disabling' ? (
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
              <div className="flex gap-2">
                <button type="button" onClick={() => { setStep('idle'); setError(''); }} className="flex-1 py-2 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !disablePassword}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-red-500 hover:bg-red-400 disabled:opacity-60 text-white text-xs font-semibold rounded-lg transition-colors"
                >
                  {submitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Disabling…</> : 'Disable'}
                </button>
              </div>
            </form>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 text-sm font-medium">
                <ShieldCheck className="w-4 h-4" /> Two-factor authentication is on
              </div>
              <button
                onClick={() => { setStep('disabling'); setError(''); }}
                className="py-2 px-4 rounded-lg border border-red-500/30 text-red-500 dark:text-red-400 text-xs font-semibold hover:bg-red-500/10 transition-colors"
              >
                Disable
              </button>
            </div>
          )
        ) : step === 'enrolling' ? (
          <form onSubmit={confirmEnroll} className="space-y-3">
            <p className="text-xs text-slate-500 dark:text-slate-400">Scan this QR code with your authenticator app, then enter the 6-digit code it shows.</p>
            {qrDataUrl && <img src={qrDataUrl} alt="Two-factor authentication QR code" className="w-40 h-40 mx-auto rounded-lg border border-slate-200 dark:border-slate-800" />}
            <p className="text-[10px] text-center text-slate-400 dark:text-slate-600 font-mono break-all">{secret}</p>
            <input
              type="text"
              inputMode="numeric"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              className={`${input} pl-3 text-center tracking-[0.3em]`}
            />
            <button
              type="submit"
              disabled={submitting || !code}
              className="w-full flex items-center justify-center gap-2 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 text-xs font-semibold rounded-lg transition-colors"
            >
              {submitting ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Confirming…</> : 'Confirm & enable'}
            </button>
          </form>
        ) : (
          <button
            onClick={startEnroll}
            disabled={submitting}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 text-sm font-semibold rounded-lg transition-colors"
          >
            {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting…</> : 'Enable two-factor authentication'}
          </button>
        )}
      </div>
    </SectionCard>
  );
};

const SecuritySettingsPanel: React.FC = () => {
  return (
    <div className="p-5 space-y-5 max-w-2xl">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Security</h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
          Your account's 2FA and password, plus the org-wide password policy — everything security-related lives here
        </p>
      </div>

      <TwoFactorSection />
      <ChangePasswordSection />

      <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
        <KeyRound className="w-4 h-4 text-cyan-500 dark:text-cyan-400 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-cyan-700 dark:text-cyan-300">
          To require or reset two-factor authentication for a non-admin user, use the "2FA" action on the Users tab instead — an admin's own 2FA can only be set up by that admin, here.
        </p>
      </div>

      <div className="-mx-5">
        <PasswordPolicyPanel />
      </div>
    </div>
  );
};

export default SecuritySettingsPanel;
