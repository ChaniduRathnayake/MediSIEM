// frontend/src/pages/dashboard/WazuhDashboard.tsx
import React, { useState } from 'react';
import {
  Shield, Server, AlertTriangle, Activity, RefreshCw,
  CheckCircle, XCircle, Loader2, Eye, EyeOff,
  WifiOff, Bug, Users, Clock, Settings, Terminal,
} from 'lucide-react';
import { useWazuh } from './useWazuh';
import { WAZUH_DEFAULTS } from './wazuhApi';
import type { WazuhConfig, WazuhAgent, WazuhAlert } from './wazuhApi';

// ─── Severity helpers ─────────────────────────────────────────────────────────
const levelToSev = (level: number) => {
  if (level >= 12) return { label: 'CRITICAL', cls: 'text-red-400 bg-red-500/10 border-red-500/30' };
  if (level >= 8)  return { label: 'HIGH',     cls: 'text-orange-400 bg-orange-500/10 border-orange-500/30' };
  if (level >= 5)  return { label: 'MEDIUM',   cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30' };
  return               { label: 'LOW',      cls: 'text-blue-400 bg-blue-500/10 border-blue-500/30' };
};

const agentStatusCls: Record<string, string> = {
  active:          'text-emerald-400 bg-emerald-500/10 border border-emerald-500/30',
  disconnected:    'text-red-400    bg-red-500/10    border border-red-500/30',
  never_connected: 'text-slate-400  bg-slate-500/10  border border-slate-500/30',
  pending:         'text-amber-400  bg-amber-500/10  border border-amber-500/30',
};

// ─── Stat Card ────────────────────────────────────────────────────────────────
const StatCard: React.FC<{
  icon: React.ReactNode; label: string; value: string | number;
  sub?: string; color: string; loading?: boolean;
}> = ({ icon, label, value, sub, color, loading }) => (
  <div className={`p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-${color}-500/30 transition-all`}>
    <div className="flex items-start justify-between mb-3">
      <div className={`w-10 h-10 rounded-xl bg-${color}-500/10 flex items-center justify-center`}>{icon}</div>
      {loading && <Loader2 className="w-4 h-4 text-slate-500 animate-spin" />}
    </div>
    {loading
      ? <div className="h-8 w-16 bg-slate-800 rounded animate-pulse mb-1" />
      : <div className="text-2xl font-black text-white mb-0.5">{value}</div>}
    <div className="text-xs font-medium text-slate-300">{label}</div>
    {sub && <div className="text-xs text-slate-500 mt-0.5">{sub}</div>}
  </div>
);

// ─── Config Panel ─────────────────────────────────────────────────────────────
const ConfigPanel: React.FC<{
  onSave:          (cfg: WazuhConfig) => void;
  connecting:      boolean;
  connectStep:     string | null;
  error:           string | null;
  existingConfig?: WazuhConfig | null;
  onBack?:         () => void;
}> = ({ onSave, connecting, connectStep, error, existingConfig, onBack }) => {
  const def = existingConfig ?? WAZUH_DEFAULTS;
  const [host,     setHost]     = useState(def.host);
  const [port,     setPort]     = useState(def.port);
  const [username, setUsername] = useState(def.username);
  const [password, setPassword] = useState(def.password);
  const [showPw,   setShowPw]   = useState(false);

  const input = 'w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white ' +
    'placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';

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
            <p className="text-xs text-slate-500">Manager at 192.168.52.129:55000</p>
          </div>
          {onBack && (
            <button onClick={onBack} className="text-xs text-slate-400 hover:text-white transition-colors">
              ← Cancel
            </button>
          )}
        </div>

        <div className="px-6 py-5 space-y-4">
          {/* Host + Port */}
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Manager Host</label>
              <input className={input} value={host} onChange={(e) => setHost(e.target.value)}
                placeholder="https://192.168.52.129" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Port</label>
              <input className={input} value={port} onChange={(e) => setPort(e.target.value)}
                placeholder="55000" />
            </div>
          </div>

          {/* Username */}
          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Username</label>
            <input className={input} value={username} onChange={(e) => setUsername(e.target.value)}
              placeholder="wazuh-wui" />
          </div>

          {/* Password */}
          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Password</label>
            <div className="relative">
              <input type={showPw ? 'text' : 'password'} className={`${input} pr-10`}
                value={password} onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && onSave({ host, port, username, password })} />
              <button onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Auth info */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
            <Shield className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-cyan-300">
              Uses <code className="font-mono bg-slate-800 px-1 rounded">?raw=true</code> auth —
              identical to your curl command. TLS certificate verification is bypassed for self-signed certs.
            </p>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
              <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-red-300 break-all">{error}</p>
            </div>
          )}

          {/* API ping success indicator */}
          {connecting && connectStep === 'Loading dashboard data…' && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
              <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <p className="text-xs text-emerald-300 font-medium">API connection verified — loading dashboard data…</p>
            </div>
          )}

          {/* Connect button */}
          <button
            onClick={() => onSave({ host, port, username, password })}
            disabled={connecting || !host || !port || !username || !password}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500
              hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 text-sm font-bold transition-all"
          >
            {connecting
              ? <><Loader2 className="w-4 h-4 animate-spin" /> {connectStep ?? 'Connecting…'}</>
              : <><CheckCircle className="w-4 h-4" /> Connect to Wazuh</>}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Agents Table ─────────────────────────────────────────────────────────────
const AgentsTable: React.FC<{ agents: WazuhAgent[]; loading: boolean }> = ({ agents, loading }) => (
  <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
    <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
      <Server className="w-4 h-4 text-cyan-400" />
      <span className="text-sm font-semibold text-white">Registered Agents</span>
      {!loading && (
        <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 ml-1">{agents.length}</span>
      )}
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            {['ID', 'Name', 'IP', 'OS', 'Status', 'Last Seen'].map((h) => (
              <th key={h} className="py-2.5 px-4 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-800/60">
                  {Array.from({ length: 6 }).map((__, j) => (
                    <td key={j} className="py-3 px-4">
                      <div className="h-3 bg-slate-800 rounded animate-pulse" style={{ width: `${55 + Math.random() * 40}%` }} />
                    </td>
                  ))}
                </tr>
              ))
            : agents.map((a) => (
                <tr key={a.id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4 font-mono text-xs text-slate-400">{a.id}</td>
                  <td className="py-3 px-4 text-sm text-white font-medium">{a.name}</td>
                  <td className="py-3 px-4 font-mono text-xs text-slate-400">{a.ip ?? '—'}</td>
                  <td className="py-3 px-4 text-xs text-slate-400">
                    {a.os ? `${a.os.platform} ${a.os.version}` : '—'}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${agentStatusCls[a.status] ?? agentStatusCls.pending}`}>
                      {a.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-500">
                    {a.lastKeepAlive ? new Date(a.lastKeepAlive).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
          {!loading && agents.length === 0 && (
            <tr><td colSpan={6} className="py-10 text-center text-sm text-slate-500">No agents found</td></tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

// ─── Alerts Feed ──────────────────────────────────────────────────────────────
const AlertsFeed: React.FC<{ alerts: WazuhAlert[]; loading: boolean }> = ({ alerts, loading }) => (
  <div className="rounded-2xl bg-slate-900 border border-slate-800 overflow-hidden">
    <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
      <AlertTriangle className="w-4 h-4 text-amber-400" />
      <span className="text-sm font-semibold text-white">Recent Alerts / Logs</span>
      {!loading && (
        <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 ml-1">{alerts.length}</span>
      )}
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            {['Severity', 'Rule / Tag', 'Description', 'Agent', 'Time'].map((h) => (
              <th key={h} className="py-2.5 px-4 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-slate-800/60">
                  {Array.from({ length: 5 }).map((__, j) => (
                    <td key={j} className="py-3 px-4">
                      <div className="h-3 bg-slate-800 rounded animate-pulse" style={{ width: `${50 + Math.random() * 45}%` }} />
                    </td>
                  ))}
                </tr>
              ))
            : alerts.map((al, i) => {
                const sev = levelToSev(al.rule?.level ?? 0);
                const desc = al.rule?.description ?? al.description ?? '—';
                return (
                  <tr key={al.id ?? i} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4">
                      <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-400">{al.rule?.id ?? al.tag ?? '—'}</td>
                    <td className="py-3 px-4 text-xs text-slate-300 max-w-xs truncate" title={desc}>{desc}</td>
                    <td className="py-3 px-4 text-xs text-slate-400 font-mono">{al.agent?.name ?? '—'}</td>
                    <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">
                      {al.timestamp ? new Date(al.timestamp).toLocaleString() : '—'}
                    </td>
                  </tr>
                );
              })}
          {!loading && alerts.length === 0 && (
            <tr><td colSpan={5} className="py-10 text-center text-sm text-slate-500">No alerts found</td></tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

// ─── Vuln bar ─────────────────────────────────────────────────────────────────
const VulnBar: React.FC<{ label: string; count: number; total: number; color: string }> = ({ label, count, total, color }) => (
  <div>
    <div className="flex justify-between text-xs mb-1">
      <span className={`font-medium text-${color}-400`}>{label}</span>
      <span className="text-slate-400">{count}</span>
    </div>
    <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
      <div className={`h-full bg-${color}-500 rounded-full transition-all duration-700`}
        style={{ width: total ? `${(count / total) * 100}%` : '0%' }} />
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
    ? (stats.vulnerabilities?.critical ?? 0) + (stats.vulnerabilities?.high ?? 0) +
      (stats.vulnerabilities?.medium  ?? 0) + (stats.vulnerabilities?.low  ?? 0)
    : 0;

  // ── Config view — show when: no config, user opened settings, or connection failed ──
  if (!config || showConfig || (!!connectionError && !connected && !connecting)) {
    return (
      <div className="p-6">
        <div className="mb-6">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" /> Wazuh SIEM Integration
          </h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Connect to your Wazuh manager to enable live security monitoring
          </p>
        </div>
        <ConfigPanel
          onSave={async (cfg) => { const ok = await connect(cfg); if (ok) { saveConfig(cfg); setShowConfig(false); } }}
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
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-normal">v{apiVersion}</span>
            )}
          </h2>
          <div className="flex flex-wrap items-center gap-3 mt-1">
            <span className={`flex items-center gap-1.5 text-xs ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
              {connected
                ? <><CheckCircle className="w-3.5 h-3.5" />{config.host}:{config.port}</>
                : <><WifiOff className="w-3.5 h-3.5" />Disconnected</>}
            </span>
            {lastRefresh && (
              <span className="text-xs text-slate-600">· Updated {lastRefresh.toLocaleTimeString()}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={refresh} disabled={!connected || loadingStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all disabled:opacity-40">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStats ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={() => setShowConfig(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all">
            <Settings className="w-3.5 h-3.5" />
            Settings
          </button>
          <button onClick={clearConfig}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20 transition-all">
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
          <button onClick={() => setShowConfig(true)}
            className="text-xs text-red-400 hover:text-red-300 underline whitespace-nowrap">
            Reconfigure
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 p-1 bg-slate-900 border border-slate-800 rounded-2xl w-fit">
        {[
          { id: 'overview', label: 'Overview',  icon: <Activity className="w-3.5 h-3.5" /> },
          { id: 'agents',   label: `Agents (${agents.length})`,  icon: <Server className="w-3.5 h-3.5" /> },
          { id: 'alerts',   label: `Alerts (${alerts.length})`,  icon: <AlertTriangle className="w-3.5 h-3.5" /> },
        ].map((t) => (
          <button key={t.id} onClick={() => setTab(t.id as typeof tab)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
              tab === t.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-slate-400 hover:text-white'}`}>
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
              label="Total Alerts" value={stats?.totalAlerts ?? '—'} sub="All time" color="red" loading={loadingStats} />
            <StatCard icon={<Clock className="w-5 h-5 text-orange-400" />}
              label="Alerts (24h)" value={stats?.alertsLast24h ?? '—'} sub="Last 24 hours" color="orange" loading={loadingStats} />
            <StatCard icon={<Server className="w-5 h-5 text-cyan-400" />}
              label="Active Agents" value={stats?.activeAgents ?? '—'} sub={`${stats?.totalAgents ?? '—'} total`} color="cyan" loading={loadingStats} />
            <StatCard icon={<Bug className="w-5 h-5 text-violet-400" />}
              label="Vulnerabilities" value={totalVulns} sub={`${stats?.vulnerabilities?.critical ?? 0} critical`} color="violet" loading={loadingStats} />
          </div>

          <div className="grid lg:grid-cols-2 gap-4">
            {/* Agent health */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Users className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-semibold text-white">Agent Health</span>
              </div>
              {loadingAgents
                ? <div className="space-y-3">{[...Array(4)].map((_, i) => (
                    <div key={i} className="h-10 bg-slate-800 rounded-lg animate-pulse" />))}</div>
                : <div className="space-y-2">
                    {[
                      { status: 'active',          label: 'Active',          color: 'emerald' },
                      { status: 'disconnected',    label: 'Disconnected',    color: 'red' },
                      { status: 'pending',         label: 'Pending',         color: 'amber' },
                      { status: 'never_connected', label: 'Never Connected', color: 'slate' },
                    ].map(({ status, label, color }) => {
                      const count = agents.filter((a) => a.status === status).length;
                      return (
                        <div key={status} className={`flex items-center justify-between px-3 py-2.5 rounded-lg bg-${color}-500/5 border border-${color}-500/10`}>
                          <span className={`text-sm text-${color}-400`}>{label}</span>
                          <span className={`text-sm font-bold text-${color}-300`}>{count}</span>
                        </div>
                      );
                    })}
                  </div>}
            </div>

            {/* Vuln breakdown */}
            <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5">
              <div className="flex items-center gap-2 mb-4">
                <Bug className="w-4 h-4 text-violet-400" />
                <span className="text-sm font-semibold text-white">Vulnerability Breakdown</span>
              </div>
              {loadingStats
                ? <div className="space-y-4">{[...Array(4)].map((_, i) => (
                    <div key={i} className="h-6 bg-slate-800 rounded animate-pulse" />))}</div>
                : <div className="space-y-3">
                    <VulnBar label="Critical" count={stats?.vulnerabilities?.critical ?? 0} total={totalVulns} color="red" />
                    <VulnBar label="High"     count={stats?.vulnerabilities?.high     ?? 0} total={totalVulns} color="orange" />
                    <VulnBar label="Medium"   count={stats?.vulnerabilities?.medium   ?? 0} total={totalVulns} color="amber" />
                    <VulnBar label="Low"      count={stats?.vulnerabilities?.low      ?? 0} total={totalVulns} color="blue" />
                  </div>}
            </div>
          </div>

          <AlertsFeed alerts={alerts.slice(0, 10)} loading={loadingAlerts} />
        </div>
      )}

      {tab === 'agents' && <AgentsTable agents={agents} loading={loadingAgents} />}
      {tab === 'alerts' && <AlertsFeed alerts={alerts} loading={loadingAlerts} />}
    </div>
  );
};

export default WazuhDashboard;
