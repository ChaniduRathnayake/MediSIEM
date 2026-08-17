// Full alert history, paginated, filterable by agent id/ip/severity. Sourced
// from the Wazuh Indexer (compliance.js's /alerts route) for structured
// agent/rule fields the manager's raw log tail doesn't have. Purely
// read-only, shared as-is between the Admin's "Wazuh SIEM" tab and the SOC
// analyst's "Live Alerts" tab.
import React, { useEffect, useMemo, useState } from 'react';
import { Loader2, AlertCircle, AlertTriangle, Server, Network, Info, MapPin, Tag, Terminal, Repeat, ShieldCheck, Maximize2 } from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import { hasIndexerConfig, searchAlerts } from './complianceApi';
import type { AlertSearchResult, WazuhAlertRow } from './complianceApi';
import ChartCard from '../../components/charts/ChartCard';
import SeverityDonutChart from '../../components/charts/SeverityDonutChart';
import { levelToSeverity, severityCounts } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';
import AlertDetailsModal from './AlertDetailsModal';
import SavedViewsBar from '../../components/SavedViewsBar';

interface AlertsBrowserFilters {
  agentIdFilter: string;
  agentIpFilter: string;
  severityFilter: string;
}

// Maps a severity name back to this page's threshold-based filter value —
// the inverse of levelToSeverity()'s own thresholds.
const SEVERITY_TO_FILTER_VALUE: Record<Severity, string> = {
  CRITICAL: '12',
  HIGH: '8',
  MEDIUM: '5',
  LOW: '1',
};

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
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detailsAlert, setDetailsAlert] = useState<WazuhAlertRow | null>(null);

  // Any filter change resets to page 1
  useEffect(() => { setPage(1); }, [agentIdFilter, agentIpFilter, severityFilter]);

  const currentFilters: AlertsBrowserFilters = { agentIdFilter, agentIpFilter, severityFilter };
  const applyFilters = (f: AlertsBrowserFilters) => {
    setAgentIdFilter(f.agentIdFilter);
    setAgentIpFilter(f.agentIpFilter);
    setSeverityFilter(f.severityFilter);
  };

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
      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
        <Info className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh Indexer is not configured</p>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
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

  const pageSeverityDist = useMemo(
    () => severityCounts(alerts, (a) => levelToSeverity(a.ruleLevel ?? 0)),
    [alerts]
  );

  return (
    <div className="space-y-3">
      {/* Per-page severity mix — the search endpoint has no aggregation route,
          so this reflects only the current page, not the full filtered result set. */}
      <ChartCard
        title="Severity mix (this page)"
        subtitle={`${alerts.length} of ${total.toLocaleString()} total alerts`}
        height={140}
        empty={alerts.length === 0}
      >
        <SeverityDonutChart
          data={pageSeverityDist}
          onSeverityClick={(severity) => setSeverityFilter(SEVERITY_TO_FILTER_VALUE[severity])}
        />
      </ChartCard>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative">
          <Server className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input
            value={agentIdFilter}
            onChange={(e) => setAgentIdFilter(e.target.value)}
            placeholder="Filter by Agent ID…"
            className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-44"
          />
        </div>
        <div className="relative">
          <Network className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input
            value={agentIpFilter}
            onChange={(e) => setAgentIpFilter(e.target.value)}
            placeholder="Filter by Agent IP…"
            className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-44"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          {severityOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {hasFilters && (
          <button
            onClick={() => { setAgentIdFilter(''); setAgentIpFilter(''); setSeverityFilter(''); }}
            className="text-xs text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            Clear filters
          </button>
        )}
        <SavedViewsBar storageKey="medisiem_alerts_browser_views" currentFilters={currentFilters} onApply={applyFilters} />
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Alerts ({total.toLocaleString()})
          </h3>
          {loading && <Loader2 className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 animate-spin" />}
        </div>

        {error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800">
                  {['Severity', 'Rule ID', 'Description', 'Agent', 'Agent ID', 'IP', 'Timestamp', 'Details'].map((h) => (
                    <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-400 dark:text-slate-500 whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((al) => {
                  const sev = severityClass(al.ruleLevel ?? 0);
                  const isExpanded = expandedId === al.id;
                  return (
                    <React.Fragment key={al.id}>
                      <tr
                        onClick={() => setExpandedId(isExpanded ? null : al.id)}
                        className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors cursor-pointer"
                      >
                        <td className="py-3 px-4">
                          <span className={`text-xs font-bold px-2 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span>
                        </td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">{al.ruleId ?? '—'}</td>
                        <td className="py-3 px-4 text-xs text-slate-700 dark:text-slate-300 max-w-xs truncate" title={al.ruleDescription ?? undefined}>
                          {al.ruleDescription ?? '—'}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-900 dark:text-white font-medium whitespace-nowrap">{al.agentName ?? '—'}</td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-400 dark:text-slate-500">{al.agentId ?? '—'}</td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">{al.agentIp ?? '—'}</td>
                        <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                          {al.timestamp ? new Date(al.timestamp).toLocaleString() : '—'}
                        </td>
                        <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setDetailsAlert(al)}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 transition-colors whitespace-nowrap"
                          >
                            <Maximize2 className="w-3 h-3" /> Details
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50 dark:bg-slate-950/50 border-b border-slate-100 dark:border-slate-800/60">
                          <td colSpan={8} className="px-4 py-4 space-y-3">
                            {/* Raw log first — what an analyst checks first to confirm the
                                rule's interpretation actually matches what happened. */}
                            <div>
                              <p className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1.5 mb-1">
                                <Terminal className="w-3 h-3" /> Raw log
                              </p>
                              <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 whitespace-pre-wrap break-all">
                                {al.fullLog ?? '— not captured for this alert —'}
                              </pre>
                            </div>

                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              <span className="text-slate-400 dark:text-slate-500">Full description: </span>
                              {al.ruleDescription ?? '—'}
                            </p>

                            {al.data && Object.keys(al.data).length > 0 && (
                              <div className="text-xs text-slate-500 dark:text-slate-400 flex items-start gap-1.5">
                                <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-slate-400 dark:text-slate-500" />
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="text-slate-400 dark:text-slate-500">Fields: </span>
                                  {Object.entries(al.data).map(([k, v]) => (
                                    <span key={k} className="px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-mono">
                                      {k}={String(v)}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            <p className="text-xs text-slate-500 dark:text-slate-400 flex items-start gap-1.5">
                              <MapPin className="w-3 h-3 mt-0.5 flex-shrink-0 text-slate-400 dark:text-slate-500" />
                              <span><span className="text-slate-400 dark:text-slate-500">Location: </span>{al.location ?? '—'}
                                {al.decoder && <span className="text-slate-400 dark:text-slate-500"> · decoder: </span>}{al.decoder}
                              </span>
                            </p>

                            <div className="text-xs text-slate-500 dark:text-slate-400 flex items-start gap-1.5">
                              <Tag className="w-3 h-3 mt-0.5 flex-shrink-0 text-slate-400 dark:text-slate-500" />
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <span className="text-slate-400 dark:text-slate-500">Rule groups: </span>
                                {al.ruleGroups.length > 0 ? (
                                  al.ruleGroups.map((g) => (
                                    <span key={g} className="px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                                      {g}
                                    </span>
                                  ))
                                ) : (
                                  <span>—</span>
                                )}
                              </div>
                            </div>

                            {(() => {
                              const complianceBadges: { label: string; values: string[] }[] = [
                                { label: 'HIPAA', values: al.compliance?.hipaa ?? [] },
                                { label: 'PCI-DSS', values: al.compliance?.pciDss ?? [] },
                                { label: 'GDPR', values: al.compliance?.gdpr ?? [] },
                                { label: 'NIST 800-53', values: al.compliance?.nist80053 ?? [] },
                                { label: 'TSC', values: al.compliance?.tsc ?? [] },
                                { label: 'GPG13', values: al.compliance?.gpg13 ?? [] },
                              ].filter((c) => c.values.length > 0);
                              if (complianceBadges.length === 0) return null;
                              return (
                                <div className="text-xs text-slate-500 dark:text-slate-400 flex items-start gap-1.5">
                                  <ShieldCheck className="w-3 h-3 mt-0.5 flex-shrink-0 text-slate-400 dark:text-slate-500" />
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    <span className="text-slate-400 dark:text-slate-500">Compliance: </span>
                                    {complianceBadges.map((c) => (
                                      <span
                                        key={c.label}
                                        title={c.values.join(', ')}
                                        className="px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400"
                                      >
                                        {c.label} ({c.values.length})
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              );
                            })()}

                            <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-4">
                              <span><span className="text-slate-400 dark:text-slate-500">Rule level: </span>{al.ruleLevel ?? '—'}</span>
                              {al.ruleFiredTimes !== null && (
                                <span className="flex items-center gap-1">
                                  <Repeat className="w-3 h-3" />
                                  <span className="text-slate-400 dark:text-slate-500">Fired: </span>{al.ruleFiredTimes}x recently
                                </span>
                              )}
                              <span><span className="text-slate-400 dark:text-slate-500">Alert ID: </span><span className="font-mono">{al.id}</span></span>
                            </p>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
                {!loading && alerts.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-10 text-center text-sm text-slate-400 dark:text-slate-500">
                      {hasFilters ? 'No alerts match these filters' : 'No alerts found'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {total > 0 && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 dark:border-slate-800">
            <p className="text-xs text-slate-400 dark:text-slate-500">
              Page {page} of {totalPages} · {total.toLocaleString()} total
            </p>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                className="px-3 py-1.5 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
      {detailsAlert && <AlertDetailsModal kind="wazuh" alert={detailsAlert} onClose={() => setDetailsAlert(null)} />}
    </div>
  );
};

export default AlertsBrowser;
