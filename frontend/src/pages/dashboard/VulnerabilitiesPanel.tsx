// "Vulnerabilities" tab: lists devices; CVE data is only fetched on "View
// CVEs" click, via AgentDetailsModal deep-linked to its Vulnerabilities tab.
// This table itself shows no per-device CVE counts — nothing loads until asked for.
import React, { useState } from 'react';
import { Bug, Loader2, AlertCircle, ShieldAlert } from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import { WazuhAgent, normalizeAgentStatus, formatOs } from './wazuhApi';
import AgentDetailsModal from './AgentDetailsModal';
import ChartCard from '../../components/charts/ChartCard';
import TopBarChart from '../../components/charts/TopBarChart';
import { SEVERITY_COLORS } from '../../utils/chartData';

const deviceStatusDot: Record<string, string> = {
  active: 'bg-emerald-400',
  disconnected: 'bg-red-400',
  never_connected: 'bg-slate-600',
  pending: 'bg-amber-400',
};

const VulnerabilitiesPanel: React.FC = () => {
  const { config, connected, connecting, agents, loadingAgents, connectionError, refresh, lastRefresh, stats } = useWazuhContext();
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);
  const [search, setSearch] = useState('');

  const vulnBreakdown = stats
    ? [
        { label: 'Critical', value: stats.vulnerabilities.critical },
        { label: 'High', value: stats.vulnerabilities.high },
        { label: 'Medium', value: stats.vulnerabilities.medium },
        { label: 'Low', value: stats.vulnerabilities.low },
      ]
    : [];
  const vulnColors: Record<string, string> = {
    Critical: SEVERITY_COLORS.CRITICAL,
    High: SEVERITY_COLORS.HIGH,
    Medium: SEVERITY_COLORS.MEDIUM,
    Low: SEVERITY_COLORS.LOW,
  };

  const searchLower = search.trim().toLowerCase();
  const rows = searchLower
    ? agents.filter((ag) => ag.name.toLowerCase().includes(searchLower) || (ag.ip ?? '').toLowerCase().includes(searchLower))
    : agents;

  if (!config) {
    return (
      <div className="p-5">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Vulnerabilities</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">CVE detections per device</p>
        </div>
        <div className="mt-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Bug className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh SIEM is not connected</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Connect it under Settings → Wazuh SIEM to see vulnerability data here.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Vulnerabilities</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            Click "View CVEs" on a device to load its vulnerability detections
            {lastRefresh ? ` · Updated ${lastRefresh.toLocaleTimeString()}` : ''}
          </p>
        </div>
        <button
          onClick={refresh}
          disabled={!connected || loadingAgents}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Loader2 className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : 'hidden'}`} />
          Refresh
        </button>
      </div>

      {connectionError && !connected && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {connectionError}
        </div>
      )}

      <ChartCard
        title="Vulnerability severity breakdown"
        subtitle="Across all agents — from the Wazuh manager's aggregate stats"
        height={160}
        empty={vulnBreakdown.every((v) => v.value === 0)}
      >
        <TopBarChart data={vulnBreakdown} colorOf={(e) => vulnColors[e.label]} />
      </ChartCard>

      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search by device name or IP…"
        className="w-64 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
      />

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {(connecting || loadingAgents) && agents.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading devices…
          </div>
        ) : rows.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">
            {agents.length === 0 ? 'No devices found.' : 'No devices match your search.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-5 text-left">Status</th>
                  <th className="py-2.5 px-5 text-left">Name</th>
                  <th className="py-2.5 px-5 text-left">IP</th>
                  <th className="py-2.5 px-5 text-left">OS</th>
                  <th className="py-2.5 px-5 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((ag) => {
                  const normalized = normalizeAgentStatus(ag.status);
                  return (
                    <tr key={ag.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-5">
                        <span className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${deviceStatusDot[normalized] ?? 'bg-slate-600'}`} />
                          <span className="text-xs text-slate-500 dark:text-slate-400 capitalize">{normalized.replace('_', ' ')}</span>
                        </span>
                      </td>
                      <td className="py-3 px-5 text-sm text-slate-900 dark:text-white font-medium">{ag.name}</td>
                      <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400 font-mono">{ag.ip ?? '—'}</td>
                      <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{formatOs(ag.os)}</td>
                      <td className="py-3 px-5 text-right">
                        <button
                          onClick={() => setSelectedAgent(ag)}
                          className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap ml-auto"
                        >
                          <ShieldAlert className="w-3.5 h-3.5" /> View CVEs
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedAgent && config && (
        <AgentDetailsModal
          agent={selectedAgent}
          config={config}
          onlySection="vulnerabilities"
          onClose={() => setSelectedAgent(null)}
        />
      )}
    </div>
  );
};

export default VulnerabilitiesPanel;
