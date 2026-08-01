// frontend/src/pages/dashboard/AlertsBrowser.tsx
// Full alert history, paginated, filterable by agent id/ip/severity. Sourced
// from the Wazuh Indexer (backend/routes/compliance.js's /alerts route), not
// the manager's /manager/logs — that's just a raw ossec.log tail with no
// structured agent/rule fields, which is why an older version of this tab
// could never actually show which agent an alert came from.
//
// Purely read-only (a search/browse view, no mutating actions), so it's
// shared as-is between the Admin's "Wazuh SIEM" tab and the SOC analyst's
// read-only "Live Alerts" tab.
import React, { useEffect, useState } from 'react';
import { Loader2, AlertCircle, AlertTriangle, Server, Network, Info } from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import { hasIndexerConfig, searchAlerts } from './complianceApi';
import type { AlertSearchResult } from './complianceApi';

const severityClass = (level: number) => {
  if (level >= 12) return { label: 'CRITICAL', cls: 'text-red-400 border-red-500/30 bg-red-500/10' };
  if (level >= 8)  return { label: 'HIGH',     cls: 'text-orange-400 border-orange-500/30 bg-orange-500/10' };
  if (level >= 5)  return { label: 'MEDIUM',   cls: 'text-amber-400 border-amber-500/30 bg-amber-500/10' };
  return                  { label: 'LOW',      cls: 'text-blue-400 border-blue-500/30 bg-blue-500/10' };
};

const severityOptions = [
  { label: 'All severities', value: '' },
  { label: 'Critical (12+)', value: '12' },
  { label: 'High (8+)',      value: '8' },
  { label: 'Medium (5+)',    value: '5' },
  { label: 'Low (1+)',       value: '1' },
];

const PAGE_SIZE = 50;

const AlertsBrowser: React.FC = () => {
  const { config } = useWazuhContext();
  const indexerReady = hasIndexerConfig(config);

  const [page, setPage] = useState(1);
  const [agentIdFilter, setAgentIdFilter] = useState('');
  const [agentIpFilter, setAgentIpFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<AlertSearchResult | null>(null);

  // Any filter change resets to page 1
  useEffect(() => { setPage(1); }, [agentIdFilter, agentIpFilter, severityFilter]);

  useEffect(() => {
    if (!config || !indexerReady) return;
    let cancelled = false;
    setLoading(true);
    setError('');
    searchAlerts(config, {
      page,
      pageSize: PAGE_SIZE,
      agentId: agentIdFilter.trim() || undefined,
      agentIp: agentIpFilter.trim() || undefined,
      severity: severityFilter ? Number(severityFilter) : undefined,
    })
      .then((r) => { if (!cancelled) setResult(r); })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load alerts.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [config, indexerReady, page, agentIdFilter, agentIpFilter, severityFilter]);

  if (!indexerReady) {
    return (
      <div className="rounded-xl bg-slate-900 border border-slate-800 p-10 text-center">
        <Info className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-300 font-medium">Wazuh Indexer is not configured</p>
        <p className="text-xs text-slate-500 mt-1">
          The full alert history — and which agent each one came from — lives in the Wazuh Indexer. Ask
          your administrator to connect it under Settings → Wazuh SIEM to browse alerts here.
        </p>
      </div>
    );
  }

  const alerts = result?.alerts ?? [];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters = !!(agentIdFilter || agentIpFilter || severityFilter);

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Server className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <input
            value={agentIdFilter}
            onChange={(e) => setAgentIdFilter(e.target.value)}
            placeholder="Filter by Agent ID…"
            className="pl-8 pr-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-44"
          />
        </div>
        <div className="relative">
          <Network className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
          <input
            value={agentIpFilter}
            onChange={(e) => setAgentIpFilter(e.target.value)}
            placeholder="Filter by Agent IP…"
            className="pl-8 pr-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-44"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          {severityOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {hasFilters && (
          <button
            onClick={() => { setAgentIdFilter(''); setAgentIpFilter(''); setSeverityFilter(''); }}
            className="text-xs text-slate-500 hover:text-white transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Alerts ({total.toLocaleString()})
          </h3>
          {loading && <Loader2 className="w-3.5 h-3.5 text-slate-600 animate-spin" />}
        </div>

        {error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  {['Severity', 'Rule ID', 'Description', 'Agent', 'Agent ID', 'IP', 'Timestamp'].map((h) => (
                    <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-500 whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((al) => {
                  const sev = severityClass(al.ruleLevel ?? 0);
                  return (
                    <tr key={al.id} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-400">{al.ruleId ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-300 max-w-xs truncate" title={al.ruleDescription ?? undefined}>
                        {al.ruleDescription ?? '—'}
                      </td>
                      <td className="py-3 px-4 text-xs text-white font-medium whitespace-nowrap">{al.agentName ?? '—'}</td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-500">{al.agentId ?? '—'}</td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-400">{al.agentIp ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-500 whitespace-nowrap">
                        {al.timestamp ? new Date(al.timestamp).toLocaleString() : '—'}
                      </td>
                    </tr>
                  );
                })}
                {!loading && alerts.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-10 text-center text-sm text-slate-500">
                      {hasFilters ? 'No alerts match these filters' : 'No alerts found'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {total > 0 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-slate-800">
            <p className="text-xs text-slate-500">
              Page {page} of {totalPages} · {total.toLocaleString()} total
            </p>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertsBrowser;
