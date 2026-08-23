// Read-only device inventory for SOC analysts — same data as the Admin
// "Devices" tab, minus any editing (no group management, no OS override).
import React, { useMemo, useState } from 'react';
import { Server, Loader2, AlertCircle, Tag, Filter, Stethoscope } from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import { useDeviceMeta } from './useDeviceMeta';
import {
  WazuhAgent, OsCategory,
  normalizeAgentStatus, formatOs, inferOsCategory, OS_CATEGORY_LABELS,
} from './wazuhApi';
import AgentDetailsModal from './AgentDetailsModal';
import ChartCard from '../../components/charts/ChartCard';
import TopBarChart from '../../components/charts/TopBarChart';
import DonutChart from '../../components/charts/DonutChart';
import { countBy } from '../../utils/chartData';

const deviceStatusDot: Record<string, string> = {
  active: 'bg-emerald-400',
  disconnected: 'bg-red-400',
  never_connected: 'bg-slate-600',
  pending: 'bg-amber-400',
};

const osCategoryDot: Record<OsCategory, string> = {
  windows: 'bg-cyan-400',
  linux:   'bg-amber-400',
  macos:   'bg-slate-300',
  network: 'bg-violet-400',
  iot:     'bg-pink-400',
  unknown: 'bg-slate-600',
};

const OsCategoryBadge: React.FC<{ category: OsCategory }> = ({ category }) => (
  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 whitespace-nowrap">
    <span className={`w-1.5 h-1.5 rounded-full ${osCategoryDot[category]}`} />
    <span className="text-xs text-slate-700 dark:text-slate-300">{OS_CATEGORY_LABELS[category]}</span>
  </span>
);

const DevicesReadOnlyPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const { config, connected, connecting, agents, loadingAgents, connectionError, refresh, lastRefresh } = useWazuhContext();
  const { groups, deviceMeta } = useDeviceMeta(token);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);
  const [osFilter, setOsFilter] = useState<OsCategory | 'all'>('all');
  const [groupFilter, setGroupFilter] = useState<string>('all');

  const metaByAgent = useMemo(() => new Map(deviceMeta.map((m) => [m.agentId, m])), [deviceMeta]);

  const normalizedStatuses = agents.map((a) => normalizeAgentStatus(a.status));
  const counts = {
    total: agents.length,
    active: normalizedStatuses.filter((s) => s === 'active').length,
    disconnected: normalizedStatuses.filter((s) => s === 'disconnected').length,
  };
  // "Online" = actively reporting; everything else (disconnected, pending,
  // never connected) counts as "Offline" for this at-a-glance view.
  const onlineOfflineData = [
    { name: 'Online', value: counts.active, color: '#10b981' },
    { name: 'Offline', value: counts.total - counts.active, color: '#ef4444' },
  ];

  const categoryFor = (ag: WazuhAgent): OsCategory => metaByAgent.get(ag.id)?.osCategoryOverride ?? inferOsCategory(ag.os);
  const groupsFor = (ag: WazuhAgent): string[] => metaByAgent.get(ag.id)?.groups ?? [];

  const osBreakdown = useMemo(
    () => countBy(agents, (ag) => OS_CATEGORY_LABELS[categoryFor(ag)]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [agents, deviceMeta]
  );

  const filteredAgents = agents.filter((ag) => {
    if (osFilter !== 'all' && categoryFor(ag) !== osFilter) return false;
    if (groupFilter === 'ungrouped' && groupsFor(ag).length > 0) return false;
    if (groupFilter !== 'all' && groupFilter !== 'ungrouped' && !groupsFor(ag).includes(groupFilter)) return false;
    return true;
  });

  if (!config) {
    return (
      <div className="space-y-5">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Devices</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">Read-only endpoint inventory from Wazuh SIEM</p>
        </div>
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Server className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh SIEM is not connected</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Ask your administrator to connect it under Settings → Wazuh SIEM.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Devices</h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            Read-only endpoint inventory{lastRefresh ? ` · Updated ${lastRefresh.toLocaleTimeString()}` : ''}
          </p>
        </div>
        <button
          onClick={refresh}
          disabled={!connected || loadingAgents}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Loader2 className={`w-3.5 h-3.5 ${loadingAgents ? 'animate-spin' : 'hidden'}`} /> Refresh
        </button>
      </div>

      {connectionError && !connected && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {connectionError}
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-cyan-500/5 border border-cyan-500/20">
          <p className="text-2xl font-bold text-cyan-400">{counts.total}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Total Devices</p>
        </div>
        <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
          <p className="text-2xl font-bold text-emerald-400">{counts.active}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Active</p>
        </div>
        <div className="p-4 rounded-xl bg-red-500/5 border border-red-500/20">
          <p className="text-2xl font-bold text-red-400">{counts.disconnected}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Disconnected</p>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <ChartCard title="Online vs offline" subtitle="Live device inventory" height={160} empty={counts.total === 0}>
          <DonutChart data={onlineOfflineData} />
        </ChartCard>
        <ChartCard title="Fleet by OS category" subtitle="Live device inventory" height={160} empty={osBreakdown.length === 0}>
          <TopBarChart data={osBreakdown} color="#06b6d4" />
        </ChartCard>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <span className="flex items-center gap-1.5 text-xs text-slate-400 dark:text-slate-500">
          <Filter className="w-3.5 h-3.5" /> Filter
        </span>
        <select
          value={osFilter}
          onChange={(e) => setOsFilter(e.target.value as OsCategory | 'all')}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All OS types</option>
          {(Object.keys(OS_CATEGORY_LABELS) as OsCategory[]).map((c) => (
            <option key={c} value={c}>{OS_CATEGORY_LABELS[c]}</option>
          ))}
        </select>
        <select
          value={groupFilter}
          onChange={(e) => setGroupFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All groups</option>
          <option value="ungrouped">Ungrouped</option>
          {groups.map((g) => (
            <option key={g.id} value={g.name}>{g.name}</option>
          ))}
        </select>
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {(connecting || loadingAgents) && agents.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading devices…
          </div>
        ) : filteredAgents.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">
            {agents.length === 0 ? 'No devices found.' : 'No devices match the current filters.'}
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
                  <th className="py-2.5 px-5 text-left">Category</th>
                  <th className="py-2.5 px-5 text-left">Medical Device</th>
                  <th className="py-2.5 px-5 text-left">Groups</th>
                  <th className="py-2.5 px-5 text-left">Last Seen</th>
                  <th className="py-2.5 px-5 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {filteredAgents.map((ag) => {
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
                      <td className="py-3 px-5"><OsCategoryBadge category={categoryFor(ag)} /></td>
                      <td className="py-3 px-5">
                        {(() => {
                          const medicalDevice = metaByAgent.get(ag.id)?.medicalDevice;
                          return medicalDevice ? (
                            <span
                              className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs whitespace-nowrap max-w-[200px]"
                              title={`${medicalDevice.deviceType} · ${medicalDevice.department}`}
                            >
                              <Stethoscope className="w-2.5 h-2.5 flex-shrink-0" />
                              <span className="truncate">{medicalDevice.deviceName}</span>
                            </span>
                          ) : (
                            <span className="text-xs text-slate-700 dark:text-slate-700">—</span>
                          );
                        })()}
                      </td>
                      <td className="py-3 px-5">
                        {groupsFor(ag).length === 0 ? (
                          <span className="text-xs text-slate-700">—</span>
                        ) : (
                          <div className="flex items-center gap-1 flex-wrap">
                            {groupsFor(ag).map((g) => (
                              <span key={g} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs whitespace-nowrap">
                                <Tag className="w-2.5 h-2.5" /> {g}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-5 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                        {ag.lastKeepAlive ? new Date(ag.lastKeepAlive).toLocaleString() : '—'}
                      </td>
                      <td className="py-3 px-5 text-right">
                        <button
                          onClick={() => setSelectedAgent(ag)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                        >
                          Details
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
        <AgentDetailsModal agent={selectedAgent} config={config} onClose={() => setSelectedAgent(null)} />
      )}
    </div>
  );
};

export default DevicesReadOnlyPanel;
