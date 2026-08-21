// Admin panel for integration credentials that used to only be configurable via backend/.env.
import React, { useEffect, useState } from 'react';
import { Plug, Loader2, AlertCircle, CheckCircle2, Send, Eye, EyeOff, X } from 'lucide-react';
import { apiGetSettings, apiUpdateSettings, apiTestEmail, apiTestWebhook } from '../../services/settingsApi';
import type { SystemSettings, SystemSettingsUpdate } from '../../services/settingsApi';

const inputClass =
  'w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white ' +
  'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-colors';

const Toggle: React.FC<{ checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }> = ({ checked, onChange, label, hint }) => (
  <label className="flex items-center justify-between gap-3 cursor-pointer">
    <div>
      <p className="text-sm text-slate-700 dark:text-slate-300">{label}</p>
      {hint && <p className="text-xs text-slate-400 dark:text-slate-600">{hint}</p>}
    </div>
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative flex-shrink-0 w-10 h-5.5 rounded-full transition-colors ${checked ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'}`}
      aria-pressed={checked}
      aria-label={label}
    >
      {/* left-0 anchors the knob explicitly — buttons default to text-align:center, which otherwise pulls its auto position off-edge. */}
      <span className={`absolute left-0 top-0.5 w-4.5 h-4.5 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-[19px]' : 'translate-x-0.5'}`} />
    </button>
  </label>
);

// Compact switch+label pairing for several short toggles on one row (Toggle's label-left/
// switch-right layout only works for a single full-width row).
const ChannelToggle: React.FC<{ checked: boolean; onChange: (v: boolean) => void; label: string }> = ({ checked, onChange, label }) => (
  <button type="button" onClick={() => onChange(!checked)} aria-pressed={checked} className="flex items-center gap-2.5">
    <span className={`relative flex-shrink-0 w-9 h-5 rounded-full transition-colors ${checked ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-700'}`}>
      <span className={`absolute left-0 top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-[18px]' : 'translate-x-0.5'}`} />
    </span>
    <span className="text-sm text-slate-700 dark:text-slate-300">{label}</span>
  </button>
);

// Shows a "configured" badge when the server has a value; never displays the stored value itself.
const SecretField: React.FC<{
  label: string;
  configured: boolean;
  value: string;
  onChange: (v: string) => void;
  cleared: boolean;
  onClear: () => void;
  placeholder?: string;
}> = ({ label, configured, value, onChange, cleared, onClear, placeholder }) => {
  const [show, setShow] = useState(false);
  return (
    <div>
      <div className="flex items-center gap-2 mb-1.5">
        <label className="text-xs font-medium text-slate-500 dark:text-slate-400">{label}</label>
        {configured && !cleared && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium">Configured</span>
        )}
        {cleared && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/10 text-red-500 dark:text-red-400 font-medium">Will be cleared</span>
        )}
      </div>
      <div className="relative flex items-center gap-2">
        <div className="relative flex-1">
          <input
            type={show ? 'text' : 'password'}
            className={`${inputClass} pr-9`}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={cleared ? '' : configured ? '•••••••••••• (leave blank to keep)' : placeholder}
            disabled={cleared}
            autoComplete="off"
          />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
            aria-label={show ? `Hide ${label}` : `Show ${label}`}
          >
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        </div>
        {configured && (
          <button
            type="button"
            onClick={onClear}
            title={cleared ? 'Undo clear' : `Clear ${label}`}
            className={`flex-shrink-0 p-2 rounded-lg border text-xs transition-colors ${
              cleared
                ? 'border-cyan-500/40 text-cyan-600 dark:text-cyan-400'
                : 'border-slate-300 dark:border-slate-700 text-slate-400 dark:text-slate-500 hover:text-red-500 hover:border-red-500/40'
            }`}
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
};

interface SecretEdits {
  smtpPass: string;
  slackWebhookUrl: string;
  teamsWebhookUrl: string;
  googleApiKey: string;
  abuseIpdbApiKey: string;
}
const EMPTY_EDITS: SecretEdits = { smtpPass: '', slackWebhookUrl: '', teamsWebhookUrl: '', googleApiKey: '', abuseIpdbApiKey: '' };

const IntegrationsSettingsPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const [edits, setEdits] = useState<SecretEdits>(EMPTY_EDITS);
  const [cleared, setCleared] = useState<Record<keyof SecretEdits, boolean>>({
    smtpPass: false, slackWebhookUrl: false, teamsWebhookUrl: false, googleApiKey: false, abuseIpdbApiKey: false,
  });
  const [recipientsInput, setRecipientsInput] = useState('');

  const [testStatus, setTestStatus] = useState<Record<string, 'idle' | 'sending' | 'ok' | 'error'>>({});
  const [testError, setTestError] = useState<Record<string, string>>({});

  const load = () => {
    if (!token) { setError('Your session has expired. Please sign in again.'); setLoading(false); return; }
    setLoading(true);
    apiGetSettings(token)
      .then(({ settings: s }) => {
        setSettings(s);
        setRecipientsInput(s.notifyEmailRecipients.join(', '));
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : 'Failed to load settings.'))
      .finally(() => setLoading(false));
  };

  useEffect(load, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleClear = (field: keyof SecretEdits) => {
    setCleared((prev) => ({ ...prev, [field]: !prev[field] }));
    setEdits((prev) => ({ ...prev, [field]: '' }));
  };

  const handleSave = async () => {
    if (!token || !settings) return;
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const payload: SystemSettingsUpdate = {
        lockout: settings.lockout,
        smtp: {
          host: settings.smtp.host,
          port: settings.smtp.port,
          secure: settings.smtp.secure,
          user: settings.smtp.user,
          fromAddress: settings.smtp.fromAddress,
          ...(cleared.smtpPass ? { pass: '' } : edits.smtpPass ? { pass: edits.smtpPass } : {}),
        },
        notifyEmailRecipients: recipientsInput.split(',').map((e) => e.trim()).filter(Boolean),
        mfaRequiredForAdmin: settings.mfaRequiredForAdmin,
        notifyOnImmediateCas: settings.notifyOnImmediateCas,
        notifyChannels: settings.notifyChannels,
        ...(cleared.slackWebhookUrl ? { slackWebhookUrl: '' } : edits.slackWebhookUrl ? { slackWebhookUrl: edits.slackWebhookUrl } : {}),
        ...(cleared.teamsWebhookUrl ? { teamsWebhookUrl: '' } : edits.teamsWebhookUrl ? { teamsWebhookUrl: edits.teamsWebhookUrl } : {}),
        ...(cleared.googleApiKey ? { googleApiKey: '' } : edits.googleApiKey ? { googleApiKey: edits.googleApiKey } : {}),
        ...(cleared.abuseIpdbApiKey ? { abuseIpdbApiKey: '' } : edits.abuseIpdbApiKey ? { abuseIpdbApiKey: edits.abuseIpdbApiKey } : {}),
      };
      const { settings: updated } = await apiUpdateSettings(token, payload);
      setSettings(updated);
      setRecipientsInput(updated.notifyEmailRecipients.join(', '));
      setEdits(EMPTY_EDITS);
      setCleared({ smtpPass: false, slackWebhookUrl: false, teamsWebhookUrl: false, googleApiKey: false, abuseIpdbApiKey: false });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  const runTest = async (key: string, fn: () => Promise<{ sent: boolean }>) => {
    setTestStatus((p) => ({ ...p, [key]: 'sending' }));
    setTestError((p) => ({ ...p, [key]: '' }));
    try {
      await fn();
      setTestStatus((p) => ({ ...p, [key]: 'ok' }));
    } catch (err: unknown) {
      setTestStatus((p) => ({ ...p, [key]: 'error' }));
      setTestError((p) => ({ ...p, [key]: err instanceof Error ? err.message : 'Test failed.' }));
    } finally {
      setTimeout(() => setTestStatus((p) => ({ ...p, [key]: 'idle' })), 5000);
    }
  };

  const TestButton: React.FC<{ testKey: string; label: string; onRun: () => Promise<{ sent: boolean }> }> = ({ testKey, label, onRun }) => {
    const status = testStatus[testKey] ?? 'idle';
    return (
      <div className="flex items-center gap-2 mt-1">
        <button
          type="button"
          onClick={() => runTest(testKey, onRun)}
          disabled={status === 'sending'}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white disabled:opacity-60 transition-colors"
        >
          {status === 'sending' ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
          {label}
        </button>
        {status === 'ok' && <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Sent</span>}
        {status === 'error' && <span className="text-xs text-red-500 dark:text-red-400">{testError[testKey]}</span>}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading integrations…
      </div>
    );
  }
  if (error && !settings) {
    return (
      <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
        <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
      </div>
    );
  }
  if (!settings) return null;

  return (
    <div className="p-5 space-y-5 max-w-2xl">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <Plug className="w-4.5 h-4.5 text-cyan-500" /> Integrations
        </h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
          Notification channels and API keys for MediSIEM's own outbound features — configured here instead of
          backend/.env, so they take effect immediately without a restart.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" /> <span>{error}</span>
        </div>
      )}

      {/* ─── SMTP / Email ─────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Email (SMTP)</h3>
        <p className="text-xs text-slate-400 dark:text-slate-600 -mt-2">
          Used for Immediate-CAS alert emails and password-reset links.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Host</label>
            <input className={inputClass} value={settings.smtp.host} placeholder="smtp.example.com"
              onChange={(e) => setSettings({ ...settings, smtp: { ...settings.smtp, host: e.target.value } })} />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Port</label>
            <input type="number" className={inputClass} value={settings.smtp.port}
              onChange={(e) => setSettings({ ...settings, smtp: { ...settings.smtp, port: Number(e.target.value) } })} />
          </div>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Username</label>
          <input className={inputClass} value={settings.smtp.user} placeholder="alerts@yourhospital.org"
            onChange={(e) => setSettings({ ...settings, smtp: { ...settings.smtp, user: e.target.value } })} />
        </div>
        <SecretField
          label="Password" configured={settings.smtp.passConfigured} value={edits.smtpPass}
          onChange={(v) => setEdits({ ...edits, smtpPass: v })} cleared={cleared.smtpPass} onClear={() => toggleClear('smtpPass')}
        />
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">From address</label>
          <input className={inputClass} value={settings.smtp.fromAddress} placeholder="MediSIEM Alerts <alerts@yourhospital.org>"
            onChange={(e) => setSettings({ ...settings, smtp: { ...settings.smtp, fromAddress: e.target.value } })} />
        </div>
        <Toggle
          checked={settings.smtp.secure}
          onChange={(v) => setSettings({ ...settings, smtp: { ...settings.smtp, secure: v } })}
          label="Use TLS (port 465)" hint="Leave off for STARTTLS on 587, the common default"
        />
        <TestButton testKey="email" label="Send test email" onRun={() => apiTestEmail(token!)} />
      </div>

      {/* ─── Alert notification routing ────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Immediate-CAS notifications</h3>
        <Toggle
          checked={settings.notifyOnImmediateCas}
          onChange={(v) => setSettings({ ...settings, notifyOnImmediateCas: v })}
          label="Notify when an alert scores Immediate" hint="Sent the moment CAAP scores a live alert as Immediate"
        />
        <div className="flex flex-wrap items-center gap-x-8 gap-y-3">
          <ChannelToggle checked={settings.notifyChannels.email} onChange={(v) => setSettings({ ...settings, notifyChannels: { ...settings.notifyChannels, email: v } })} label="Email" />
          <ChannelToggle checked={settings.notifyChannels.slack} onChange={(v) => setSettings({ ...settings, notifyChannels: { ...settings.notifyChannels, slack: v } })} label="Slack" />
          <ChannelToggle checked={settings.notifyChannels.teams} onChange={(v) => setSettings({ ...settings, notifyChannels: { ...settings.notifyChannels, teams: v } })} label="Teams" />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Email recipients</label>
          <input className={inputClass} value={recipientsInput} placeholder="soc@yourhospital.org, oncall@yourhospital.org"
            onChange={(e) => setRecipientsInput(e.target.value)} />
          <p className="text-xs text-slate-400 dark:text-slate-600 mt-1">Comma-separated. Only used when the Email channel above is on.</p>
        </div>
      </div>

      {/* ─── Webhooks ───────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Chat webhooks</h3>
        <div>
          <SecretField
            label="Slack incoming webhook URL" configured={settings.slackConfigured} value={edits.slackWebhookUrl}
            onChange={(v) => setEdits({ ...edits, slackWebhookUrl: v })} cleared={cleared.slackWebhookUrl}
            onClear={() => toggleClear('slackWebhookUrl')} placeholder="https://hooks.slack.com/services/…"
          />
          <TestButton testKey="slack" label="Send test message" onRun={() => apiTestWebhook(token!, 'slack')} />
        </div>
        <div>
          <SecretField
            label="Microsoft Teams incoming webhook URL" configured={settings.teamsConfigured} value={edits.teamsWebhookUrl}
            onChange={(v) => setEdits({ ...edits, teamsWebhookUrl: v })} cleared={cleared.teamsWebhookUrl}
            onClear={() => toggleClear('teamsWebhookUrl')} placeholder="https://outlook.office.com/webhook/…"
          />
          <TestButton testKey="teams" label="Send test message" onRun={() => apiTestWebhook(token!, 'teams')} />
        </div>
      </div>

      {/* ─── API keys ───────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">API keys</h3>
        <SecretField
          label="Google Gemini API key (AI alert triage assistant)" configured={settings.googleConfigured} value={edits.googleApiKey}
          onChange={(v) => setEdits({ ...edits, googleApiKey: v })} cleared={cleared.googleApiKey}
          onClear={() => toggleClear('googleApiKey')} placeholder="Paste your Gemini API key"
        />
        <SecretField
          label="AbuseIPDB API key (IP reputation enrichment)" configured={settings.abuseIpdbConfigured} value={edits.abuseIpdbApiKey}
          onChange={(v) => setEdits({ ...edits, abuseIpdbApiKey: v })} cleared={cleared.abuseIpdbApiKey}
          onClear={() => toggleClear('abuseIpdbApiKey')} placeholder="Optional — used to score external source IPs"
        />
      </div>

      {/* ─── Security ───────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Security</h3>
        <Toggle
          checked={settings.mfaRequiredForAdmin}
          onChange={(v) => setSettings({ ...settings, mfaRequiredForAdmin: v })}
          label="Require two-factor authentication for admin accounts"
          hint="Admins without it enabled see a persistent prompt to set it up until they do — any admin can enroll from Account → Security regardless of this toggle"
        />
        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Lock account after</label>
            <div className="flex items-center gap-2">
              <input type="number" min={3} max={20} className={inputClass} value={settings.lockout.maxAttempts}
                onChange={(e) => setSettings({ ...settings, lockout: { ...settings.lockout, maxAttempts: Number(e.target.value) } })} />
              <span className="text-xs text-slate-400 dark:text-slate-600 whitespace-nowrap">failed attempts</span>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Lockout duration</label>
            <div className="flex items-center gap-2">
              <input type="number" min={1} max={1440} className={inputClass} value={settings.lockout.lockDurationMinutes}
                onChange={(e) => setSettings({ ...settings, lockout: { ...settings.lockout, lockDurationMinutes: Number(e.target.value) } })} />
              <span className="text-xs text-slate-400 dark:text-slate-600 whitespace-nowrap">minutes</span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3 sticky bottom-0 bg-white/90 dark:bg-slate-950/90 backdrop-blur py-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 text-sm font-semibold transition-colors"
        >
          {saving ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</> : 'Save Integrations'}
        </button>
        {saved && (
          <span className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" /> Saved
          </span>
        )}
      </div>
    </div>
  );
};

export default IntegrationsSettingsPanel;
