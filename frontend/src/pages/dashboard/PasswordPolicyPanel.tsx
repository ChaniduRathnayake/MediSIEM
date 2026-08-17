// Admin Settings panel for the org-wide password policy — enforced
// server-side via backend/utils/passwordPolicy.js, mirrored client-side for
// live feedback wherever a password is entered (PasswordChecklist).
import React, { useEffect, useState } from 'react';
import { KeyRound, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { apiGetPasswordPolicy, apiUpdatePasswordPolicy } from '../../services/passwordPolicyApi';
import type { PasswordPolicy } from '../../services/passwordPolicyApi';

const TOGGLES: { key: keyof Pick<PasswordPolicy, 'requireUppercase' | 'requireLowercase' | 'requireNumber' | 'requireSpecialChar'>; label: string; hint: string }[] = [
  { key: 'requireUppercase', label: 'Require an uppercase letter', hint: 'A-Z' },
  { key: 'requireLowercase', label: 'Require a lowercase letter', hint: 'a-z' },
  { key: 'requireNumber', label: 'Require a number', hint: '0-9' },
  { key: 'requireSpecialChar', label: 'Require a special character', hint: '!@#$%^&* …' },
];

const PasswordPolicyPanel: React.FC = () => {
  const { token } = useAuth();
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!token) { setError('Your session has expired. Please sign in again.'); setLoading(false); return; }
    apiGetPasswordPolicy(token)
      .then((data) => setPolicy(data.policy))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load password policy.'))
      .finally(() => setLoading(false));
  }, [token]);

  const handleSave = async () => {
    if (!token || !policy) return;
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const { policy: updated } = await apiUpdatePasswordPolicy(token, {
        minLength: policy.minLength,
        requireUppercase: policy.requireUppercase,
        requireLowercase: policy.requireLowercase,
        requireNumber: policy.requireNumber,
        requireSpecialChar: policy.requireSpecialChar,
      });
      setPolicy(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save password policy.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-5 space-y-5 max-w-2xl">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Password Policy</h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
          Applies to every new password — admin-created accounts and self-service password changes alike
        </p>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading policy…
        </div>
      ) : error && !policy ? (
        <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      ) : policy ? (
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Minimum length</label>
            <div className="flex items-center gap-3">
              <input
                type="number"
                min={8}
                max={128}
                value={policy.minLength}
                onChange={(e) => setPolicy({ ...policy, minLength: Number(e.target.value) })}
                className="w-24 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:outline-none focus:border-cyan-500/60"
              />
              <span className="text-xs text-slate-400 dark:text-slate-600">characters (8–128, matches the account model's own floor)</span>
            </div>
          </div>

          <div className="space-y-3">
            {TOGGLES.map((t) => (
              <label key={t.key} className="flex items-center justify-between gap-3 cursor-pointer">
                <div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">{t.label}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-600">{t.hint}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setPolicy({ ...policy, [t.key]: !policy[t.key] })}
                  className={`relative flex-shrink-0 w-10 h-5.5 rounded-full transition-colors ${policy[t.key] ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'}`}
                  aria-pressed={policy[t.key]}
                  aria-label={t.label}
                >
                  <span className={`absolute top-0.5 w-4.5 h-4.5 rounded-full bg-white shadow transition-transform ${policy[t.key] ? 'translate-x-[19px]' : 'translate-x-0.5'}`} />
                </button>
              </label>
            ))}
          </div>

          <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center gap-3">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 text-sm font-semibold transition-colors"
            >
              {saving ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : 'Save Policy'}
            </button>
            {saved && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" /> Saved
              </span>
            )}
          </div>

          <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
            <KeyRound className="w-4 h-4 text-cyan-500 dark:text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-cyan-700 dark:text-cyan-300">
              Existing passwords aren't affected retroactively — this only applies the next time someone sets or changes a password.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
};

export default PasswordPolicyPanel;
