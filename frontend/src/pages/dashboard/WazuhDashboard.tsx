// frontend/src/pages/dashboard/WazuhDashboard.tsx
import React, { useState } from 'react';
import {
  Shield, Terminal, Eye, EyeOff, Loader2, CheckCircle, XCircle,
  WifiOff, RefreshCw, Settings, Activity, Server, AlertTriangle,
  Clock, Bug, Info,
} from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import type { UseWazuhReturn } from './useWazuh';
import { WazuhConfig, WAZUH_DEFAULTS, WazuhAgent, normalizeAgentStatus, formatOs } from './wazuhApi';
import { testIndexerConnection } from './complianceApi';
import AgentDetailsModal from './AgentDetailsModal';
import AlertsBrowser from './AlertsBrowser';
import ChartCard from '../../components/charts/ChartCard';
import TopBarChart from '../../components/charts/TopBarChart';
import { SEVERITY_COLORS } from '../../utils/chartData';
import StatCard from '../../components/StatCard';

// ─── Config Panel ─────────────────────────────────────────────────────────────
const ConfigPanel: React.FC<{
  onSave:        (cfg: WazuhConfig) => void;
  connecting:    boolean;
  connectStep:   string | null;
  error:         string | null;
  existingConfig: WazuhConfig | null;
  onBack?:       () => void;
  // Persists the indexer fields on their own, independent of the Wazuh API
  // connect/reconnect flow above — so testing/saving the Indexer never
  // disturbs (or depends on) the manager connection.
  onSaveIndexer?: (cfg: WazuhConfig) => void;
}> = ({ onSave, connecting, connectStep, error, existingConfig, onBack, onSaveIndexer }) => {
  const def = existingConfig ?? WAZUH_DEFAULTS;
  const [host,     setHost]     = useState(def.host);
  const [port,     setPort]     = useState(def.port);
  const [username, setUsername] = useState(def.username);
  const [password, setPassword] = useState(def.password);
  const [showPw,   setShowPw]   = useState(false);
  const [showHints, setShowHints] = useState(false);

  const [indexerHost,     setIndexerHost]     = useState(def.indexerHost ?? WAZUH_DEFAULTS.indexerHost ?? '');
  const [indexerPort,     setIndexerPort]     = useState(def.indexerPort ?? WAZUH_DEFAULTS.indexerPort ?? '');
  const [indexerUsername, setIndexerUsername] = useState(def.indexerUsername ?? WAZUH_DEFAULTS.indexerUsername ?? '');
  const [indexerPassword, setIndexerPassword] = useState(def.indexerPassword ?? WAZUH_DEFAULTS.indexerPassword ?? '');
  const [showIndexerPw, setShowIndexerPw]     = useState(false);
  const [showIndexer,   setShowIndexer]       = useState(false);

  const [indexerTesting, setIndexerTesting] = useState(false);
  const [indexerResult,  setIndexerResult]  = useState<{ ok: true; version: string | null } | { ok: false; error: string } | null>(null);

  const buildConfig = (): WazuhConfig => ({
    host, port, username, password,
    indexerHost, indexerPort, indexerUsername, indexerPassword,
  });

  const handleTestIndexer = async () => {
    setIndexerTesting(true);
    setIndexerResult(null);
    try {
      const result = await testIndexerConnection(buildConfig());
      setIndexerResult({ ok: true, version: result.version });
      onSaveIndexer?.(buildConfig()); // persist on success — no need to also hit "Connect to Wazuh API"
    } catch (err: unknown) {
      setIndexerResult({ ok: false, error: err instanceof Error ? err.message : 'Indexer connection failed' });
    } finally {
      setIndexerTesting(false);
    }
  };

  const input =
    'w-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white ' +
    'placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 ' +
    'focus:ring-cyan-500/20 transition-all';

  const dockerHints = [
    { label: 'Docker Desktop (Windows/Mac)', host: 'https://localhost' },
    { label: 'Docker on Linux (same machine)', host: 'https://127.0.0.1' },
    { label: 'Remote / static IP', host: 'https://192.168.x.x' },
  ];

  return (
    <div className="max-w-lg mx-auto">
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 flex items-center justify-center">
            <Terminal className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex-1">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white">Wazuh API Connection</h2>
            <p className="text-xs text-slate-400 dark:text-slate-500">Connect to your Wazuh manager via the backend proxy</p>
          </div>
          {onBack && (
            <button onClick={onBack} className="text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
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
            <div className="rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-300 dark:border-slate-700 overflow-hidden">
              {dockerHints.map((hint) => (
                <button
                  key={hint.host}
                  onClick={() => setHost(hint.host)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-slate-200 dark:hover:bg-slate-700/60 transition-colors border-b border-slate-700/40 last:border-0 ${
                    host === hint.host ? 'text-cyan-400' : 'text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <span>{hint.label}</span>
                  <span className="font-mono text-slate-400 dark:text-slate-500">{hint.host}</span>
                </button>
              ))}
            </div>
          )}

          {/* Host + Port */}
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Manager Host</label>
              <input
                className={input}
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="https://localhost"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Port</label>
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
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Username</label>
            <input
              className={input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="wazuh-wui"
            />
          </div>

          {/* Password */}
          <div>
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Password</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                className={`${input} pr-10`}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && onSave(buildConfig())}
              />
              <button
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors"
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Wazuh Indexer (optional — powers the HIPAA/GDPR Compliances views) */}
          <div className="pt-1 border-t border-slate-200 dark:border-slate-800">
            <button
              onClick={() => setShowIndexer(!showIndexer)}
              className="w-full flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors pt-3"
            >
              <Info className="w-3.5 h-3.5" />
              {showIndexer ? 'Hide' : 'Show'} Wazuh Indexer settings (optional — for Compliances)
            </button>

            {showIndexer && (
              <div className="space-y-4 mt-3">
                <p className="text-xs text-slate-400 dark:text-slate-500">
                  Separate service from the manager above — holds the alert history the
                  HIPAA/GDPR compliance views query. Leave blank to skip those views.
                </p>

                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2">
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Indexer Host</label>
                    <input
                      className={input}
                      value={indexerHost}
                      onChange={(e) => setIndexerHost(e.target.value)}
                      placeholder="https://localhost"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Port</label>
                    <input
                      className={input}
                      value={indexerPort}
                      onChange={(e) => setIndexerPort(e.target.value)}
                      placeholder="9200"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Indexer Username</label>
                  <input
                    className={input}
                    value={indexerUsername}
                    onChange={(e) => setIndexerUsername(e.target.value)}
                    placeholder="admin"
                  />
                </div>

                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1.5 block">Indexer Password</label>
                  <div className="relative">
                    <input
                      type={showIndexerPw ? 'text' : 'password'}
                      className={`${input} pr-10`}
                      value={indexerPassword}
                      onChange={(e) => setIndexerPassword(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleTestIndexer()}
                    />
                    <button
                      onClick={() => setShowIndexerPw(!showIndexerPw)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors"
                    >
                      {showIndexerPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {indexerResult && (
                  indexerResult.ok ? (
                    <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                      <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                      <p className="text-xs text-emerald-300">
                        Indexer connected{indexerResult.version ? ` — v${indexerResult.version}` : ''}. Saved.
                      </p>
                    </div>
                  ) : (
                    <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                      <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                      <p className="text-xs text-red-300 break-all">{indexerResult.error}</p>
                    </div>
                  )
                )}

                <button
                  onClick={handleTestIndexer}
                  disabled={indexerTesting || !indexerHost || !indexerPort || !indexerUsername || !indexerPassword}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700
                    hover:border-cyan-500/40 hover:text-slate-900 dark:hover:text-white disabled:opacity-50 disabled:cursor-not-allowed text-slate-700 dark:text-slate-300 text-sm font-semibold transition-all"
                >
                  {indexerTesting ? (
                    <><Loader2 className="w-4 h-4 animate-spin" /> Testing Indexer…</>
                  ) : (
                    <><Server className="w-4 h-4" /> Test Indexer Connection</>
                  )}
                </button>
              </div>
            )}
          </div>

          {/* Auth info */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
            <Shield className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-cyan-300">
              Connects via the MediSIEM backend proxy — identical to{' '}
              <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">
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
                    → Make sure <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">npm run dev</code> is running in{' '}
                    <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">/backend</code> (port 5000).
                  </p>
                )}
                {(error.includes('auth') || error.includes('401') || error.includes('403')) && (
                  <p className="text-xs text-red-400/70">
                    → Check username / password. Default Wazuh API user is{' '}
                    <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">wazuh-wui</code>.
                  </p>
                )}
                {(error.includes('ECONNREFUSED') || error.includes('502')) && (
                  <p className="text-xs text-red-400/70">
                    → Wazuh manager is not reachable. If running Docker Desktop on Windows, try{' '}
                    <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1 rounded">https://localhost</code>.
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Connect button */}
          <button
            onClick={() => onSave(buildConfig())}
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
                Connect to Wazuh API
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Stat Card ────────────────────────────────────────────────────────────────
// ─── Agent row ────────────────────────────────────────────────────────────────
const statusMeta: Record<ReturnType<typeof normalizeAgentStatus>, { dot: string; label: string; online: boolean }> = {
  active:          { dot: 'bg-emerald-400', label: 'Active',          online: true },
  disconnected:    { dot: 'bg-red-400',     label: 'Disconnected',    online: false },
  never_connected: { dot: 'bg-slate-600',   label: 'Never Connected', online: false },
  pending:         { dot: 'bg-amber-400',   label: 'Pending',         online: false },
};

const AgentsTable: React.FC<{ agents: UseWazuhReturn['agents']; loading: boolean; onSelect: (agent: WazuhAgent) => void }> = ({
  agents,
  loading,
  onSelect,
}) => (
  <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
    <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
      <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
        <Server className="w-4 h-4 text-cyan-400" />
        Agents ({agents.length})
      </h3>
      {loading && <Loader2 className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 animate-spin" />}
    </div>
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-800">
            {['Status', 'ID', 'Name', 'IP', 'OS', 'Version', 'Last Seen', ''].map((h) => (
              <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-400 dark:text-slate-500 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {agents.map((ag) => {
            const meta = statusMeta[normalizeAgentStatus(ag.status)];
            return (
              <tr
                key={ag.id}
                onClick={() => onSelect(ag)}
                className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors cursor-pointer"
              >
                <td className="py-3 px-4">
                  <span className="flex items-center gap-1.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                    <span className={`text-xs font-medium ${meta.online ? 'text-emerald-400' : 'text-slate-500 dark:text-slate-400'}`}>
                      {meta.label}
                    </span>
                  </span>
                </td>
                <td className="py-3 px-4 font-mono text-xs text-slate-400 dark:text-slate-500">{ag.id}</td>
                <td className="py-3 px-4 text-xs text-slate-900 dark:text-white font-medium">{ag.name}</td>
                <td className="py-3 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">{ag.ip ?? '—'}</td>
                <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{formatOs(ag.os)}</td>
                <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 font-mono">{ag.version ?? '—'}</td>
                <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                  {ag.lastKeepAlive ? new Date(ag.lastKeepAlive).toLocaleString() : '—'}
                </td>
                <td className="py-3 px-4 text-right">
                  <button
                    onClick={(e) => { e.stopPropagation(); onSelect(ag); }}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                  >
                    Details
                  </button>
                </td>
              </tr>
            );
          })}
          {!loading && agents.length === 0 && (
            <tr>
              <td colSpan={8} className="py-10 text-center text-sm text-slate-400 dark:text-slate-500">
                No agents found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

// ─── Main WazuhDashboard ──────────────────────────────────────────────────────
const WazuhDashboard: React.FC = () => {
  const {
    config, saveConfig, clearConfig,
    connected, connecting, connectStep, connectionError, apiVersion,
    connect,
    stats, agents,
    loadingStats, loadingAgents,
    refresh, lastRefresh,
  } = useWazuhContext();

  const [tab,        setTab]        = useState<'overview' | 'agents' | 'alerts'>('overview');
  const [showConfig, setShowConfig] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);

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
          <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" /> Wazuh SIEM Integration
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
            Connect to your Wazuh manager (running in Docker) to enable live security monitoring
          </p>
        </div>
        <ConfigPanel
          onSave={async (cfg) => {
            const ok = await connect(cfg);
            if (ok) { saveConfig(cfg); setShowConfig(false); }
          }}
          onSaveIndexer={(cfg) => {
            // Persists independently of the Wazuh API connect flow above —
            // but keep this screen open (rather than letting `config` turning
            // non-null jump us to the connected dashboard view mid-setup).
            saveConfig(cfg);
            setShowConfig(true);
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
          <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Wazuh SIEM Live
            {apiVersion && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-normal">
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
              <span className="text-xs text-slate-400 dark:text-slate-600">
                · Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            disabled={!connected || loadingStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStats ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowConfig(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all"
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
      <div className="flex gap-1 p-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl w-fit">
        {[
          { id: 'overview', label: 'Overview',              icon: <Activity     className="w-3.5 h-3.5" /> },
          { id: 'agents',   label: `Agents (${agents.length})`,   icon: <Server       className="w-3.5 h-3.5" /> },
          { id: 'alerts',   label: 'Alerts',   icon: <AlertTriangle className="w-3.5 h-3.5" /> },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as typeof tab)}
            className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-medium transition-all ${
              tab === t.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
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
              icon={<AlertTriangle className="w-5 h-5" />}
              label="Total Alerts" value={String(stats?.totalAlerts ?? '—')} sub="All time"
              color="red" loading={loadingStats}
            />
            <StatCard
              icon={<Clock className="w-5 h-5" />}
              label="Alerts (24h)" value={String(stats?.alertsLast24h ?? '—')} sub="Last 24 hours"
              color="orange" loading={loadingStats}
            />
            <StatCard
              icon={<CheckCircle className="w-5 h-5" />}
              label="Active Agents" value={String(stats?.activeAgents ?? '—')} sub={`of ${stats?.totalAgents ?? '?'} total`}
              color="emerald" loading={loadingStats}
            />
            <StatCard
              icon={<Bug className="w-5 h-5" />}
              label="Vulnerabilities" value={String(totalVulns)} sub="Across all agents"
              color="violet" loading={loadingStats}
            />
          </div>

          {/* Vuln breakdown + agent status */}
          <div className="grid lg:grid-cols-2 gap-5">
            <ChartCard
              title="Vulnerability breakdown"
              subtitle="Across all agents"
              height={200}
              empty={!stats || totalVulns === 0}
            >
              <TopBarChart
                data={stats ? [
                  { label: 'Critical', value: stats.vulnerabilities.critical },
                  { label: 'High', value: stats.vulnerabilities.high },
                  { label: 'Medium', value: stats.vulnerabilities.medium },
                  { label: 'Low', value: stats.vulnerabilities.low },
                ] : []}
                colorOf={(e) => ({ Critical: SEVERITY_COLORS.CRITICAL, High: SEVERITY_COLORS.HIGH, Medium: SEVERITY_COLORS.MEDIUM, Low: SEVERITY_COLORS.LOW }[e.label] ?? '#64748b')}
              />
            </ChartCard>

            <ChartCard
              title="Agent status summary"
              subtitle={`${stats?.totalAgents ?? 0} agents total`}
              height={200}
              empty={!stats || (stats.totalAgents ?? 0) === 0}
            >
              <TopBarChart
                data={[
                  { label: 'Active', value: stats?.activeAgents ?? 0 },
                  { label: 'Disconnected', value: stats?.disconnectedAgents ?? 0 },
                ]}
                colorOf={(e) => (e.label === 'Active' ? '#10b981' : '#ef4444')}
              />
            </ChartCard>
          </div>
        </div>
      )}

      {/* ── Agents ── */}
      {tab === 'agents' && (
        <AgentsTable agents={agents} loading={loadingAgents} onSelect={setSelectedAgent} />
      )}

      {/* ── Alerts ── */}
      {tab === 'alerts' && <AlertsBrowser />}

      {selectedAgent && config && (
        <AgentDetailsModal agent={selectedAgent} config={config} onClose={() => setSelectedAgent(null)} />
      )}
    </div>
  );
};

export default WazuhDashboard;
