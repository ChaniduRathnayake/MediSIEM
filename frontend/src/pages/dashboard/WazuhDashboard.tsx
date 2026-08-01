// frontend/src/pages/dashboard/WazuhDashboard.tsx
import React, { useState } from 'react';
import {
  Shield, Terminal, Eye, EyeOff, Loader2, CheckCircle, XCircle,
  WifiOff, RefreshCw, Settings, Activity, Server, AlertTriangle,
  Clock, Bug, Info,
} from 'lucide-react';
import { useWazuh } from './useWazuh';
import { WazuhConfig, WAZUH_DEFAULTS } from './wazuhApi';

// ─── Config Panel ─────────────────────────────────────────────────────────────
const ConfigPanel: React.FC<{
  onSave:        (cfg: WazuhConfig) => void;
  connecting:    boolean;
  connectStep:   string | null;
  error:         string | null;
  existingConfig: WazuhConfig | null;
  onBack?:       () => void;
}> = ({ onSave, connecting, connectStep, error, existingConfig, onBack }) => {
  const def = existingConfig ?? WAZUH_DEFAULTS;
  const [host,     setHost]     = useState(def.host);
  const [port,     setPort]     = useState(def.port);
  const [username, setUsername] = useState(def.username);
  const [password, setPassword] = useState(def.password);
  const [showPw,   setShowPw]   = useState(false);
  const [showHints, setShowHints] = useState(false);

  const input =
    'w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white ' +
    'placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 ' +
    'focus:ring-cyan-500/20 transition-all';

  const dockerHints = [
    { label: 'Docker Desktop (Windows/Mac)', host: 'https://localhost' },
    { label: 'Docker on Linux (same machine)', host: 'https://127.0.0.1' },
    { label: 'Remote / static IP', host: 'https://192.168.x.x' },
  ];

  return (
    <div className="max-w-lg mx-auto">
      <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 border-b border-slate-800 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center">
            <Terminal className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex-1">
            <h2 className="text-sm font-bold text-white">Wazuh API Connection</h2>
            <p className="text-xs text-slate-500">Connect to your Wazuh manager via the backend proxy</p>
          </div>
          {onBack && (
            <button onClick={onBack} className="text-xs text-slate-400 hover:text-white transition-colors">
              ← Cancel
            </button>
          )}
        </div>

        <div className="px-6 py-5 space-y-4">
          {/* Docker hints toggle */}
          <button
            onClick={() => setShowHints(!showHints)}
            className="w-full flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            <Info className="w-3.5 h-3.5" />
            {showHints ? 'Hide' : 'Show'} Docker host hints
          </button>

          {showHints && (
            <div className="rounded-lg bg-slate-800/60 border border-slate-700 overflow-hidden">
              {dockerHints.map((hint) => (
                <button
                  key={hint.host}
                  onClick={() => setHost(hint.host)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-slate-700/60 transition-colors border-b border-slate-700/40 last:border-0 ${
                    host === hint.host ? 'text-cyan-400' : 'text-slate-300'
                  }`}
                >
                  <span>{hint.label}</span>
                  <span className="font-mono text-slate-500">{hint.host}</span>
                </button>
              ))}
            </div>
          )}

          {/* Host + Port */}
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Manager Host</label>
              <input
                className={input}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="https://localhost"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Port</label>
              <input
                className={input}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="55000"
              />
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Username</label>
            <input
              className={input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="wazuh-wui"
            />
          </div>

          {/* Password */}
          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Password</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                className={`${input} pr-10`}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) =>
                  e.key === 'Enter' && onSave({ host, port, username, password })
                }
              />
              <button
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Auth info */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
            <Shield className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-cyan-300">
              Connects via the MediSIEM backend proxy — identical to{' '}
              <code className="font-mono bg-slate-800 px-1 rounded">
                curl -k -u user:pass https://host:55000/security/user/authenticate?raw=true
              </code>.
              TLS cert verification is bypassed for self-signed certs.
            </p>
          </div>

          {/* Step indicator */}
          {connecting && connectStep === 'Loading dashboard data…' && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <p className="text-xs text-emerald-300 font-medium">
                API connection verified — loading dashboard data…
              </p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                <p className="text-xs text-red-300 break-all">{error}</p>
                {error.includes('backend') && (
                  <p className="text-xs text-red-400/70">
                    → Make sure <code className="font-mono bg-slate-800 px-1 rounded">npm run dev</code> is running in{' '}
                    <code className="font-mono bg-slate-800 px-1 rounded">/backend</code> (port 5000).
                  </p>
                )}
                {(error.includes('auth') || error.includes('401') || error.includes('403')) && (
                  <p className="text-xs text-red-400/70">
                    → Check username / password. Default Wazuh API user is{' '}
                    <code className="font-mono bg-slate-800 px-1 rounded">wazuh-wui</code>.
                  </p>
                )}
                {(error.includes('ECONNREFUSED') || error.includes('502')) && (
                  <p className="text-xs text-red-400/70">
                    → Wazuh manager is not reachable. If running Docker Desktop on Windows, try{' '}
                    <code className="font-mono bg-slate-800 px-1 rounded">https://localhost</code>.
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Connect button */}
          <button
            onClick={() => onSave({ host, port, username, password })}
            disabled={connecting || !host || !port || !username || !password}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500
              hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 text-sm font-bold transition-all"
          >
            {connecting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                {connectStep ?? 'Connecting…'}
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Connect to Wazuh
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: number | string;
  sub: string;
  color: string;
  loading?: boolean;
}> = ({ icon, label, value, sub, color, loading }) => (
  <div className={`p-4 rounded-xl bg-${color}-500/5 border border-${color}-500/20`}>
    <div className="flex items-start justify-between mb-3">
      {icon}
      {loading && <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />}
    </div>
    <div className={`text-2xl font-bold text-${color}-400 mb-0.5`}>
      {loading ? '…' : value}
    </div>
    <div className="text-xs font-medium text-white">{label}</div>
    <div className="text-xs text-slate-500 mt-0.5">{sub}</div>
  </div>
);

// ─── Agent row ────────────────────────────────────────────────────────────────
const statusDot: Record<string, string> = {
  active:           'bg-emerald-400',
  disconnected:     'bg-red-400',
  never_connected:  'bg-slate-600',
  pending:          'bg-amber-400',
};

const AgentsTable: React.FC<{ agents: ReturnType<typeof useWazuh>['agents']; loading: boolean }> = ({
  agents,
  loading,
}) => (
  <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
    <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
      <h3 className="text-sm font-semibold text-white flex items-center gap-2">
        <Server className="w-4 h-4 text-cyan-400" />
        Agents ({agents.length})
      </h3>
      {loading && <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />}
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            {['Status', 'ID', 'Name', 'IP', 'OS', 'Version', 'Last Seen'].map((h) => (
              <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-500 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {agents.map((ag) => (
            <tr key={ag.id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
              <td className="py-3 px-4">
                <span className="flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${statusDot[ag.status] ?? 'bg-slate-600'}`} />
                  <span className="text-xs text-slate-400 capitalize">{ag.status.replace('_', ' ')}</span>
                </span>
              </td>
              <td className="py-3 px-4 font-mono text-xs text-slate-500">{ag.id}</td>
              <td className="py-3 px-4 text-xs text-white font-medium">{ag.name}</td>
              <td className="py-3 px-4 font-mono text-xs text-slate-400">{ag.ip ?? '—'}</td>
              <td className="py-3 px-4 text-xs text-slate-400 whitespace-nowrap">
                {ag.os ? `${ag.os.platform} ${ag.os.version}` : '—'}
              </td>
              <td className="py-3 px-4 text-xs text-slate-500 font-mono">{ag.version ?? '—'}</td>
              <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">
                {ag.lastKeepAlive ? new Date(ag.lastKeepAlive).toLocaleString() : '—'}
              </td>
            </tr>
          ))}
          {!loading && agents.length === 0 && (
            <tr>
              <td colSpan={7} className="py-10 text-center text-sm text-slate-500">
                No agents found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

// ─── Alerts table ─────────────────────────────────────────────────────────────
const severityClass = (level: number) => {
  if (level >= 12) return { label: 'CRITICAL', cls: 'text-red-400 border-red-500/30 bg-red-500/10' };
  if (level >= 8)  return { label: 'HIGH',     cls: 'text-orange-400 border-orange-500/30 bg-orange-500/10' };
  if (level >= 5)  return { label: 'MEDIUM',   cls: 'text-amber-400 border-amber-500/30 bg-amber-500/10' };
  return                  { label: 'LOW',      cls: 'text-blue-400 border-blue-500/30 bg-blue-500/10' };
};

const AlertsTable: React.FC<{ alerts: ReturnType<typeof useWazuh>['alerts']; loading: boolean }> = ({
  alerts,
  loading,
}) => (
  <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
    <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
      <h3 className="text-sm font-semibold text-white flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-400" />
        Recent Alerts ({alerts.length})
      </h3>
      {loading && <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />}
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            {['Severity', 'Rule ID', 'Description', 'Agent', 'Timestamp'].map((h) => (
              <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-500 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map((al, i) => {
            const sev = severityClass(al.rule?.level ?? 0);
            const desc = al.rule?.description ?? al.description ?? '—';
            return (
              <tr
                key={al.id ?? i}
                className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors"
              >
                <td className="py-3 px-4">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sev.cls}`}>
                    {sev.label}
                  </span>
                </td>
                <td className="py-3 px-4 font-mono text-xs text-slate-400">{al.rule?.id ?? al.tag ?? '—'}</td>
                <td className="py-3 px-4 text-xs text-slate-300 max-w-xs truncate" title={desc}>
                  {desc}
                </td>
                <td className="py-3 px-4 text-xs text-slate-400 font-mono">{al.agent?.name ?? '—'}</td>
                <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">
                  {al.timestamp ? new Date(al.timestamp).toLocaleString() : '—'}
                </td>
              </tr>
            );
          })}
          {!loading && alerts.length === 0 && (
            <tr>
              <td colSpan={5} className="py-10 text-center text-sm text-slate-500">
                No alerts found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

// ─── Vuln bar ─────────────────────────────────────────────────────────────────
const VulnBar: React.FC<{ label: string; count: number; total: number; color: string }> = ({
  label,
  count,
  total,
  color,
}) => (
  <div>
    <div className="flex justify-between text-xs mb-1">
      <span className={`font-medium text-${color}-400`}>{label}</span>
      <span className="text-slate-400">{count}</span>
    </div>
    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
      <div
        className={`h-full bg-${color}-500 rounded-full transition-all duration-700`}
        style={{ width: total ? `${(count / total) * 100}%` : '0%' }}
      />
    </div>
  </div>
);

// ─── Main WazuhDashboard ──────────────────────────────────────────────────────
const WazuhDashboard: React.FC = () => {
  const {
    config, saveConfig, clearConfig,
    connected, connecting, connectStep, connectionError, apiVersion,
    connect,
    stats, agents, alerts,
    loadingStats, loadingAgents, loadingAlerts,
    refresh, lastRefresh,
  } = useWazuh();

  const [tab,        setTab]        = useState<'overview' | 'agents' | 'alerts'>('overview');
  const [showConfig, setShowConfig] = useState(false);

  const totalVulns = stats
    ? (stats.vulnerabilities?.critical ?? 0) +
      (stats.vulnerabilities?.high     ?? 0) +
      (stats.vulnerabilities?.medium   ?? 0) +
      (stats.vulnerabilities?.low      ?? 0)
    : 0;

  // ── Config view ──────────────────────────────────────────────────────────────
  if (!config || showConfig || (!!connectionError && !connected && !connecting)) {
    return (
      <div className="p-6">
        <div className="mb-6">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" /> Wazuh SIEM Integration
          </h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Connect to your Wazuh manager (running in Docker) to enable live security monitoring
          </p>
        </div>
        <ConfigPanel
          onSave={async (cfg) => {
            const ok = await connect(cfg);
            if (ok) { saveConfig(cfg); setShowConfig(false); }
          }}
          connecting={connecting}
          connectStep={connectStep}
          error={connectionError}
          existingConfig={config}
          onBack={(config && connected) ? () => setShowConfig(false) : undefined}
        />
      </div>
    );
  }

  // ── Connected view ────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Wazuh SIEM Live
            {apiVersion && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-normal">
                v{apiVersion}
              </span>
            )}
          </h2>
          <div className="flex flex-wrap items-center gap-3 mt-1">
            <span className={`flex items-center gap-1.5 text-xs ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
              {connected ? (
                <>
                  <CheckCircle className="w-3.5 h-3.5" />
                  {config.host}:{config.port}
                </>
              ) : (
                <>
                  <WifiOff className="w-3.5 h-3.5" />
                  Disconnected
                </>
              )}
            </span>
            {lastRefresh && (
              <span className="text-xs text-slate-600">
                · Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            disabled={!connected || loadingStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStats ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowConfig(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all"
          >
            <Settings className="w-3.5 h-3.5" />
            Settings
          </button>
          <button
            onClick={clearConfig}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20 transition-all"
          >
            <XCircle className="w-3.5 h-3.5" />
            Disconnect
          </button>
        </div>
      </div>

      {/* Connection error banner */}
      {connectionError && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/30">
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-red-300">Connection Error</p>
            <p className="text-xs text-red-400/80 mt-0.5 break-all font-mono">{connectionError}</p>
          </div>
          <button
            onClick={() => setShowConfig(true)}
            className="text-xs text-red-400 hover:text-red-300 underline whitespace-nowrap"
          >
            Reconfigure
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-slate-900 border border-slate-800 rounded-2xl w-fit">
        {[
          { id: 'overview', label: 'Overview',              icon: <Activity     className="w-3.5 h-3.5" /> },
          { id: 'agents',   label: `Agents (${agents.length})`,   icon: <Server       className="w-3.5 h-3.5" /> },
          { id: 'alerts',   label: `Alerts (${alerts.length})`,   icon: <AlertTriangle className="w-3.5 h-3.5" /> },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as typeof tab)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
              tab === t.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
              label="Total Alerts" value={stats?.totalAlerts ?? '—'} sub="All time"
              color="red" loading={loadingStats}
            />
            <StatCard
              icon={<Clock className="w-5 h-5 text-orange-400" />}
              label="Alerts (24h)" value={stats?.alertsLast24h ?? '—'} sub="Last 24 hours"
              color="orange" loading={loadingStats}
            />
            <StatCard
              icon={<CheckCircle className="w-5 h-5 text-emerald-400" />}
              label="Active Agents" value={stats?.activeAgents ?? '—'} sub={`of ${stats?.totalAgents ?? '?'} total`}
              color="emerald" loading={loadingStats}
            />
            <StatCard
              icon={<Bug className="w-5 h-5 text-violet-400" />}
              label="Vulnerabilities" value={totalVulns} sub="Across all agents"
              color="violet" loading={loadingStats}
            />
          </div>

          {/* Vuln breakdown */}
          {stats && totalVulns > 0 && (
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Bug className="w-4 h-4 text-violet-400" />
                Vulnerability Breakdown
              </h3>
              <VulnBar label="Critical" count={stats.vulnerabilities.critical} total={totalVulns} color="red" />
              <VulnBar label="High"     count={stats.vulnerabilities.high}     total={totalVulns} color="orange" />
              <VulnBar label="Medium"   count={stats.vulnerabilities.medium}   total={totalVulns} color="amber" />
              <VulnBar label="Low"      count={stats.vulnerabilities.low}      total={totalVulns} color="blue" />
            </div>
          )}

          {/* Agent status summary */}
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Agent Status Summary
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Active',          value: stats?.activeAgents,       color: 'emerald' },
                { label: 'Disconnected',    value: stats?.disconnectedAgents, color: 'red'     },
                { label: 'Total',           value: stats?.totalAgents,        color: 'cyan'    },
                { label: 'Critical Alerts', value: stats?.criticalAlerts,     color: 'orange'  },
              ].map((item) => (
                <div
                  key={item.label}
                  className={`p-3 rounded-lg bg-${item.color}-500/5 border border-${item.color}-500/20 text-center`}
                >
                  <div className={`text-xl font-bold text-${item.color}-400`}>
                    {loadingStats ? '…' : (item.value ?? 0)}
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5">{item.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Agents ── */}
      {tab === 'agents' && (
        <AgentsTable agents={agents} loading={loadingAgents} />
      )}

      {/* ── Alerts ── */}
      {tab === 'alerts' && (
        <AlertsTable alerts={alerts} loading={loadingAlerts} />
      )}
    </div>
  );
};

export default WazuhDashboard;
