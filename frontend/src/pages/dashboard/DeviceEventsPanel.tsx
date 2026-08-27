// The full raw Wazuh SIEM alert stream — every rule that fired, not just the subset
// CAAP's ML pipeline scores with a CAS value (AlertsPanel/liveAlerts). Sourced from
// the Wazuh Indexer via the same searchAlerts() AlertsBrowser.tsx already uses, so
// "Events by Device" reflects everything Wazuh itself detected. Two views behind one
// toggle: "All" (flat, chronological, paginated) and "By Device" (grouped master/detail,
// most-recent 200 alerts — the search endpoint has no per-agent aggregation route, so
// like AlertsBrowser's own severity donut, this reflects a recent window, not the
// all-time total per device).
import React, { useEffect, useState } from 'react';
import { Radio, Search, Server, Loader2, AlertCircle, Info, ChevronRight, Maximize2, List, LayoutGrid } from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import { hasIndexerConfig, searchAlerts, getDeviceSummary } from './complianceApi';
import type { WazuhAlertRow, AlertSearchResult, DeviceSummaryRow } from './complianceApi';
import AlertDetailsModal from './AlertDetailsModal';

const DEVICE_PAGE_SIZE = 200; // max the backend allows — the aggregation "window" for By-Device mode
const ALL_PAGE_SIZE = 50;

const severityClass = (level: number | null) => {
  const lvl = level ?? 0;
  if (lvl >= 12) return { label: 'CRITICAL', cls: 'text-red-400 border-red-500/30 bg-red-500/10' };
  if (lvl >= 8) return { label: 'HIGH', cls: 'text-orange-400 border-orange-500/30 bg-orange-500/10' };
  if (lvl >= 5) return { label: 'MEDIUM', cls: 'text-amber-400 border-amber-500/30 bg-amber-500/10' };
  return { label: 'LOW', cls: 'text-blue-400 border-blue-500/30 bg-blue-500/10' };
};

const severityOptions = [
  { label: 'All severities', value: '' },
  { label: 'Critical (12+)', value: '12' },
  { label: 'High (8+)', value: '8' },
  { label: 'Medium (5+)', value: '5' },
  { label: 'Low (1+)', value: '1' },
];

const DeviceEventsPanel: React.FC = () => {
  const { config } = useWazuhContext();
  const indexerReady = hasIndexerConfig(config);

  const [viewMode, setViewMode] = useState<'device' | 'all'>('device');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(1);
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null); // agent.id
  const [detailsAlert, setDetailsAlert] = useState<WazuhAlertRow | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<AlertSearchResult | null>(null);

  // The device list — every device that has ever alerted, via a real
  // aggregation (GET /alerts/devices), independent of whatever's in the
  // paginated alert fetch below. Previously "By Device" derived its device
  // list by grouping the same capped, most-recent-N-alerts fetch used for
  // the "All at once" tab — so a handful of chatty devices (e.g. a live
  // attack run) could fill that window and silently push every other
  // device out of the list entirely, even ones with real history.
  const [devices, setDevices] = useState<DeviceSummaryRow[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [devicesError, setDevicesError] = useState('');

  const activeDevice = selectedDevice && devices.some((d) => d.agentId === selectedDevice) ? selectedDevice : devices[0]?.agentId ?? null;
  const pageSize = viewMode === 'device' ? DEVICE_PAGE_SIZE : ALL_PAGE_SIZE;

  // Any filter, mode, or selected-device change resets pagination — a stale
  // page number from "All" mode, or from a previously selected device with
  // more pages, would just 404-empty against the newly filtered set.
  useEffect(() => { setPage(1); }, [search, severityFilter, viewMode, activeDevice]);

  useEffect(() => {
    if (!config || !indexerReady || viewMode !== 'device') return;
    let cancelled = false;
    setDevicesLoading(true);
    setDevicesError('');
    getDeviceSummary(config, {
      severity: severityFilter ? Number(severityFilter) : undefined,
      q: search.trim() || undefined,
    })
      .then((r) => { if (!cancelled) setDevices(r.devices); })
      .catch((err: unknown) => { if (!cancelled) setDevicesError(err instanceof Error ? err.message : 'Failed to load devices.'); })
      .finally(() => { if (!cancelled) setDevicesLoading(false); });
    return () => { cancelled = true; };
  }, [config, indexerReady, viewMode, severityFilter, search]);

  useEffect(() => {
    if (!config || !indexerReady) return;
    if (viewMode === 'device' && !activeDevice) { setResult(null); return; }
    let cancelled = false;
    setLoading(true);
    setError('');
    searchAlerts(config, {
      page,
      pageSize,
      agentId: viewMode === 'device' ? activeDevice ?? undefined : undefined,
      severity: severityFilter ? Number(severityFilter) : undefined,
      q: search.trim() || undefined,
    })
      .then((r) => { if (!cancelled) setResult(r); })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load alerts.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [config, indexerReady, viewMode, activeDevice, page, pageSize, severityFilter, search]);

  const alerts = result?.alerts ?? [];
  const total = result?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / ALL_PAGE_SIZE));

  const deviceEvents = alerts;
  const activeSummary = devices.find((d) => d.agentId === activeDevice) ?? null;

  if (!indexerReady) {
    return (
      <div className="p-5">
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Info className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh Indexer is not configured</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
            Device events are read from the Wazuh Indexer's full alert history — the same source the Alerts browser
            uses. Ask your administrator to connect it under Settings → Wazuh SIEM.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-5 h-full flex flex-col">
      <div className="mb-4 flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Radio className="w-4.5 h-4.5 text-cyan-500" /> Events by Device
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            Every alert Wazuh SIEM has raised — {total.toLocaleString()} total{severityFilter || search ? ' matching the current filters' : ''}.
          </p>
        </div>
        <div className="flex items-center rounded-lg border border-slate-300 dark:border-slate-700 overflow-hidden text-xs font-medium">
          <button
            type="button"
            onClick={() => setViewMode('device')}
            className={`flex items-center gap-1.5 px-3 py-1.5 transition-colors ${
              viewMode === 'device' ? 'bg-cyan-500 text-white' : 'bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5" /> By device
          </button>
          <button
            type="button"
            onClick={() => setViewMode('all')}
            className={`flex items-center gap-1.5 px-3 py-1.5 border-l border-slate-300 dark:border-slate-700 transition-colors ${
              viewMode === 'all' ? 'bg-cyan-500 text-white' : 'bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <List className="w-3.5 h-3.5" /> All at once
          </button>
        </div>
      </div>

      {/* Shared filters */}
      <div className="flex items-center gap-2 flex-wrap mb-4">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rule description…"
            className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-56"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          {severityOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {(loading || devicesLoading) && <Loader2 className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 animate-spin" />}
      </div>

      {(error || devicesError) && (
        <div className="flex items-center gap-2 px-4 py-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error || devicesError}
        </div>
      )}

      {viewMode === 'device' ? (
        devices.length === 0 && !devicesLoading ? (
          <p className="text-sm text-slate-500 text-center py-14">No device activity matches these filters.</p>
        ) : (
          <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-4">
            {/* ─── Device list ──────────────────────────────────────────── */}
            <div className="flex flex-col rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
              <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800 text-[11px] text-slate-400 dark:text-slate-500">
                {devices.length} device{devices.length === 1 ? '' : 's'} with matching alerts
              </div>
              <div className="flex-1 overflow-y-auto">
                {devices.map((d) => {
                  const sev = severityClass(d.maxLevel);
                  const active = d.agentId === activeDevice;
                  return (
                    <button
                      key={d.agentId}
                      type="button"
                      onClick={() => setSelectedDevice(d.agentId)}
                      className={`w-full flex items-center gap-2.5 px-3 py-2.5 border-b border-slate-100 dark:border-slate-800/60 text-left transition-colors ${
                        active ? 'bg-cyan-500/10' : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                      }`}
                    >
                      <Server className="w-3.5 h-3.5 flex-shrink-0 text-slate-400" />
                      <div className="flex-1 min-w-0">
                        <span className="text-xs font-mono text-slate-800 dark:text-slate-200 truncate block">{d.agentName || d.agentId}</span>
                        <div className="flex items-center gap-2 mt-0.5">
                          {d.agentIp && <span className="text-[11px] font-mono text-slate-400 dark:text-slate-600">{d.agentIp}</span>}
                          <span className="text-[11px] text-slate-400 dark:text-slate-600">{d.count} event{d.count === 1 ? '' : 's'}</span>
                        </div>
                      </div>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-300 dark:text-slate-700 flex-shrink-0" />
                    </button>
                  );
                })}
              </div>
            </div>

            {/* ─── Selected device's events ─────────────────────────────── */}
            <div className="flex flex-col rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
              {activeSummary ? (
                <>
                  <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between flex-wrap gap-2">
                    <div>
                      <h3 className="text-sm font-semibold text-slate-900 dark:text-white font-mono">{activeSummary.agentName || activeSummary.agentId}</h3>
                      <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
                        {activeSummary.agentId ? `Agent ID ${activeSummary.agentId}` : 'Agent ID unknown'}
                        {activeSummary.agentIp ? ` · ${activeSummary.agentIp}` : ''}
                      </p>
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-white dark:bg-slate-900">
                        <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                          <th className="py-2 px-4 text-left">Severity</th>
                          <th className="py-2 px-4 text-left">Rule</th>
                          <th className="py-2 px-4 text-left">Detected</th>
                          <th className="py-2 px-4 text-left"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {deviceEvents.map((a) => {
                          const sev = severityClass(a.ruleLevel);
                          return (
                            <tr
                              key={a.id}
                              onClick={() => setDetailsAlert(a)}
                              className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 cursor-pointer transition-colors"
                            >
                              <td className="py-2.5 px-4"><span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span></td>
                              <td className="py-2.5 px-4 text-slate-700 dark:text-slate-300 max-w-sm truncate" title={a.ruleDescription ?? undefined}>{a.ruleDescription ?? '—'}</td>
                              <td className="py-2.5 px-4 text-xs text-slate-400 dark:text-slate-500 tabular-nums whitespace-nowrap">
                                {a.timestamp ? new Date(a.timestamp).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: true }) : '—'}
                              </td>
                              <td className="py-2.5 px-4"><Maximize2 className="w-3 h-3 text-slate-300 dark:text-slate-700" /></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  {total > pageSize && (
                    <div className="flex items-center justify-between px-4 py-2.5 border-t border-slate-200 dark:border-slate-800 flex-shrink-0">
                      <p className="text-xs text-slate-400 dark:text-slate-500">Page {page} of {Math.max(1, Math.ceil(total / pageSize))} · {total.toLocaleString()} events</p>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => setPage((p) => Math.max(1, p - 1))}
                          disabled={page <= 1 || loading}
                          className="px-2.5 py-1 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          Previous
                        </button>
                        <button
                          onClick={() => setPage((p) => Math.min(Math.ceil(total / pageSize), p + 1))}
                          disabled={page >= Math.ceil(total / pageSize) || loading}
                          className="px-2.5 py-1 rounded-lg text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-slate-500 text-center py-14">Select a device to see its event history.</p>
              )}
            </div>
          </div>
        )
      ) : (
        /* ─── "All at once" — flat, chronological, paginated ──────────────── */
        <div className="flex-1 min-h-0 flex flex-col rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800">
                  {['Severity', 'Rule', 'Description', 'Device', 'IP', 'Detected', ''].map((h) => (
                    <th key={h} className="py-2.5 px-4 text-left text-xs font-medium text-slate-400 dark:text-slate-500 whitespace-nowrap sticky top-0 bg-white dark:bg-slate-900">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => {
                  const sev = severityClass(a.ruleLevel);
                  return (
                    <tr
                      key={a.id}
                      onClick={() => setDetailsAlert(a)}
                      className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4"><span className={`text-xs font-bold px-2 py-0.5 rounded border ${sev.cls}`}>{sev.label}</span></td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">{a.ruleId ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-700 dark:text-slate-300 max-w-xs truncate" title={a.ruleDescription ?? undefined}>{a.ruleDescription ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-900 dark:text-white font-medium whitespace-nowrap">{a.agentName ?? '—'}</td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">{a.agentIp ?? '—'}</td>
                      <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                        {a.timestamp ? new Date(a.timestamp).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: true }) : '—'}
                      </td>
                      <td className="py-3 px-4"><Maximize2 className="w-3 h-3 text-slate-300 dark:text-slate-700" /></td>
                    </tr>
                  );
                })}
                {!loading && alerts.length === 0 && (
                  <tr><td colSpan={7} className="py-10 text-center text-sm text-slate-400 dark:text-slate-500">No alerts match these filters</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {total > 0 && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-slate-200 dark:border-slate-800 flex-shrink-0">
              <p className="text-xs text-slate-400 dark:text-slate-500">Page {page} of {totalPages} · {total.toLocaleString()} total</p>
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
      )}

      {detailsAlert && <AlertDetailsModal kind="wazuh" alert={detailsAlert} onClose={() => setDetailsAlert(null)} />}
    </div>
  );
};

export default DeviceEventsPanel;
