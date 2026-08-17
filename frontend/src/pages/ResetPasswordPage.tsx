import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Shield, Lock, Eye, EyeOff, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';
import { apiResetPassword } from '../services/authExtrasApi';
import { apiGetPasswordPolicy } from '../services/passwordPolicyApi';
import type { PasswordPolicy } from '../services/passwordPolicyApi';
import { passwordMeetsPolicy } from '../utils/passwordPolicy';
import PasswordChecklist from '../components/PasswordChecklist';

// Reached from the link in a password-reset email (routes/auth.js's
// forgot-password flow) — /reset-password/:token.
const ResetPasswordPage: React.FC = () => {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);

  useEffect(() => {
    apiGetPasswordPolicy().then((d) => setPolicy(d.policy)).catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    if (policy && !passwordMeetsPolicy(password, policy)) {
      setError('Password does not meet the policy requirements below.');
      return;
    }
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await apiResetPassword(token, password);
      setDone(true);
      setTimeout(() => navigate('/login'), 2500);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset password.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950 flex items-center justify-center px-4 py-16">
      <div className="w-full max-w-md animate-fade-up">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2.5 mb-6">
            <div className="w-9 h-9 bg-cyan-500 rounded-md flex items-center justify-center">
              <Shield className="w-4.5 h-4.5 text-slate-950" strokeWidth={2.5} />
            </div>
            <span className="font-semibold text-lg text-slate-900 dark:text-white">
              Medi<span className="text-cyan-400">SIEM</span>
            </span>
          </Link>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white mb-1">Set a new password</h1>
        </div>

        <div className="p-7 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
          {done ? (
            <div className="flex flex-col items-center text-center gap-3 py-4">
              <CheckCircle2 className="w-8 h-8 text-emerald-500" />
              <p className="text-sm text-slate-700 dark:text-slate-300">Password updated. Redirecting to sign in…</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate className="space-y-5">
              {error && (
                <div className="flex items-start gap-3 p-3.5 rounded-md bg-red-500/10 border border-red-500/25 text-red-400 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">New password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
                  <input
                    id="password"
                    type={showPw ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="new-password"
                    className="w-full pl-10 pr-11 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
                  />
                  <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors">
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              {password && <PasswordChecklist password={password} policy={policy} />}

              <div>
                <label htmlFor="confirm" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Confirm new password</label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
                  <input
                    id="confirm"
                    type={showPw ? 'text' : 'password'}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    autoComplete="new-password"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting || !password || !confirm}
                className="w-full flex items-center justify-center gap-2 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-semibold rounded-md transition-colors"
              >
                {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : 'Set new password'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResetPasswordPage;
