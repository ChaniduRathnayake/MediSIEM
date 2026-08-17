import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, Loader2, LogIn, KeyRound, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { apiForgotPassword } from '../services/authExtrasApi';

const LoginPage: React.FC = () => {
  const { login, verifyMfa, isLoading } = useAuth();
  const navigate = useNavigate();

  const [form, setForm] = useState({ email: '', password: '' });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Two-factor step: once the password checks out for an MFA-enabled
  // account, the backend returns a short-lived mfaToken instead of a
  // session — this holds that token while the user enters their code.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState('');

  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSent, setForgotSent] = useState(false);
  const [forgotSubmitting, setForgotSubmitting] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm((p) => ({ ...p, [e.target.name]: e.target.value }));
    if (error) setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.email || !form.password) {
      setError('Please fill in all fields.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const result = await login(form);
      if (result.mfaRequired && result.mfaToken) {
        setMfaToken(result.mfaToken);
        return;
      }
      navigate('/dashboard');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken || !mfaCode) return;
    setSubmitting(true);
    setError('');
    try {
      await verifyMfa(mfaToken, mfaCode.trim());
      navigate('/dashboard');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Invalid code. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleForgotSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!forgotEmail) return;
    setForgotSubmitting(true);
    try {
      await apiForgotPassword(forgotEmail);
      setForgotSent(true);
    } catch {
      // Backend always returns the same generic message regardless of
      // outcome (see routes/auth.js) — a network-level failure is the only
      // way this branch is reached, so just show the same generic result.
      setForgotSent(true);
    } finally {
      setForgotSubmitting(false);
    }
  };

  const fillDemo = (role: 'admin' | 'user') => {
    if (role === 'admin') setForm({ email: 'admin@medisiem.com', password: 'Admin@1234' });
    else setForm({ email: 'user@medisiem.com', password: 'User@1234' });
    setError('');
  };

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950 flex items-center justify-center px-4 py-16">
      <div className="w-full max-w-md animate-fade-up">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2.5 mb-6">
            <div className="w-9 h-9 bg-cyan-500 rounded-md flex items-center justify-center">
              <Shield className="w-4.5 h-4.5 text-slate-950" strokeWidth={2.5} />
            </div>
            <span className="font-semibold text-lg text-slate-900 dark:text-white">
              Medi<span className="text-cyan-400">SIEM</span>
            </span>
          </Link>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white mb-1">Welcome back</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Sign in to your MediSIEM account</p>
        </div>

        {/* Demo Credentials */}
        <div className="mb-5 p-4 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-3 font-medium">Demo credentials — click to fill:</p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => fillDemo('admin')}
              className="flex-1 py-2 px-3 text-xs rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:border-slate-600 transition-colors font-medium"
            >
              Admin Login
            </button>
            <button
              type="button"
              onClick={() => fillDemo('user')}
              className="flex-1 py-2 px-3 text-xs rounded-md bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:border-slate-600 transition-colors font-medium"
            >
              User Login
            </button>
          </div>
        </div>

        {/* Card */}
        <div className="p-7 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
          {mfaToken ? (
            <form onSubmit={handleMfaSubmit} noValidate className="space-y-5">
              <div className="text-center">
                <KeyRound className="w-8 h-8 text-cyan-500 mx-auto mb-3" />
                <h2 className="text-base font-semibold text-slate-900 dark:text-white">Two-factor authentication</h2>
                <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Enter the 6-digit code from your authenticator app</p>
              </div>

              {error && (
                <div className="flex items-start gap-3 p-3.5 rounded-md bg-red-500/10 border border-red-500/25 text-red-400 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <input
                type="text"
                inputMode="numeric"
                autoFocus
                autoComplete="one-time-code"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456 or a backup code"
                className="w-full text-center tracking-[0.3em] px-4 py-3 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
              />

              <button
                type="submit"
                disabled={submitting || !mfaCode}
                className="w-full flex items-center justify-center gap-2 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-semibold rounded-md transition-colors"
              >
                {submitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Verifying…</> : 'Verify & Sign In'}
              </button>

              <button
                type="button"
                onClick={() => { setMfaToken(null); setMfaCode(''); setError(''); }}
                className="w-full text-center text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                ← Back to sign in
              </button>
            </form>
          ) : forgotOpen ? (
            <div className="space-y-5">
              <div className="text-center">
                <Mail className="w-8 h-8 text-cyan-500 mx-auto mb-3" />
                <h2 className="text-base font-semibold text-slate-900 dark:text-white">Reset your password</h2>
                <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">We'll email you a link if that address has an account</p>
              </div>

              {forgotSent ? (
                <div className="flex items-start gap-3 p-3.5 rounded-md bg-emerald-500/10 border border-emerald-500/25 text-emerald-600 dark:text-emerald-400 text-sm">
                  <CheckCircle2 className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>If an account exists for that email, a password reset link has been sent.</span>
                </div>
              ) : (
                <form onSubmit={handleForgotSubmit} className="space-y-4">
                  <input
                    type="email"
                    autoFocus
                    value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    placeholder="you@hospital.lk"
                    autoComplete="email"
                    className="w-full px-4 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
                  />
                  <button
                    type="submit"
                    disabled={forgotSubmitting || !forgotEmail}
                    className="w-full flex items-center justify-center gap-2 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-semibold rounded-md transition-colors"
                  >
                    {forgotSubmitting ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending…</> : 'Send reset link'}
                  </button>
                </form>
              )}

              <button
                type="button"
                onClick={() => { setForgotOpen(false); setForgotSent(false); setForgotEmail(''); }}
                className="w-full text-center text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                ← Back to sign in
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} noValidate className="space-y-5">
              {/* Error */}
              {error && (
                <div className="flex items-start gap-3 p-3.5 rounded-md bg-red-500/10 border border-red-500/25 text-red-400 text-sm">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              {/* Email */}
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  Email address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
                  <input
                    id="email"
                    name="email"
                    type="email"
                    value={form.email}
                    onChange={handleChange}
                    placeholder="you@hospital.lk"
                    autoComplete="email"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label htmlFor="password" className="text-sm font-medium text-slate-700 dark:text-slate-300">
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => { setForgotOpen(true); setForgotEmail(form.email); setError(''); }}
                    className="text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
                  <input
                    id="password"
                    name="password"
                    type={showPw ? 'text' : 'password'}
                    value={form.password}
                    onChange={handleChange}
                    placeholder="••••••••"
                    autoComplete="current-password"
                    className="w-full pl-10 pr-11 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors text-sm"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors"
                  >
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={submitting || isLoading}
                className="w-full flex items-center justify-center gap-2 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 font-semibold rounded-md transition-colors"
              >
                {submitting ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Signing in…</>
                ) : (
                  <><LogIn className="w-4 h-4" /> Sign In</>
                )}
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-xs text-slate-400 dark:text-slate-600 mt-6">
          R26-CS-008 · SLIIT Research Project · MediSIEM Platform
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
