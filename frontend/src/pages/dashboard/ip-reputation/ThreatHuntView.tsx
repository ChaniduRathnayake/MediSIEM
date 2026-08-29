// Port of components/ThreatHuntPage.jsx — search live Wazuh/Suricata evidence
// and pivot suspicious IPs into the Investigate tab via onInvestigate.
import React, { useState } from 'react';
import { threatHunt } from './ipReputationApi';
import type { ThreatHuntFilters, ThreatHuntResult } from './ipReputationApi';
import { SectionCard, MetricTile, DataRow, Badge, EmptyNotice, ErrorBanner, fmtDateTime, toneOf } from './shared';

const DEFAULT_FILTERS: ThreatHuntFilters = {
  hours: '168',
  ip: '',
  src_ip: '',
  dest_ip: '',
  min_level: '',
  rule_id: '',
  signature: '',
  signature_id: '',
  protocol: '',
  app_proto: '',
  direction: '',
};

const inputCls = 'w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60';

const HuntField: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <label className="block">
    <span className="block text-xs text-slate-500 dark:text-slate-400 mb-1">{label}</span>
    {children}
  </label>
);

const ThreatHuntView: React.FC<{ onInvestigate: (ip: string) => void }> = ({ onInvestigate }) => {
  const [filters, setFilters] = useState<ThreatHuntFilters>(DEFAULT_FILTERS);
  const [result, setResult] = useState<ThreatHuntResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const updateFilter = (name: keyof ThreatHuntFilters, value: string) => {
    setFilters((current) => ({ ...current, [name]: value }));
  };

  const resetFilters = () => {
    setFilters(DEFAULT_FILTERS);
    setResult(null);
    setError('');
  };

  const runHunt = async (event?: React.FormEvent) => {
    event?.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await threatHunt(filters, 100);
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to execute Threat Hunt.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <form onSubmit={runHunt}>
        <SectionCard eyebrow="WAZUH / SURICATA HUNT" title="Hunt Filters" subtitle="Combine filters to narrow indexed security alerts.">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
            <HuntField label="Time Range">
              <select value={filters.hours} onChange={(e) => updateFilter('hours', e.target.value)} className={inputCls}>
                <option value="1">Last 1 hour</option>
                <option value="6">Last 6 hours</option>
                <option value="24">Last 24 hours</option>
                <option value="72">Last 3 days</option>
                <option value="168">Last 7 days</option>
                <option value="720">Last 30 days</option>
              </select>
            </HuntField>

            <HuntField label="Any IP">
              <input placeholder="e.g. 104.21.40.220" value={filters.ip} onChange={(e) => updateFilter('ip', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Source IP">
              <input placeholder="Source address" value={filters.src_ip} onChange={(e) => updateFilter('src_ip', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Destination IP">
              <input placeholder="Destination address" value={filters.dest_ip} onChange={(e) => updateFilter('dest_ip', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Minimum Wazuh Level">
              <select value={filters.min_level} onChange={(e) => updateFilter('min_level', e.target.value)} className={inputCls}>
                <option value="">Any level</option>
                <option value="3">Level 3+</option>
                <option value="5">Level 5+</option>
                <option value="8">Level 8+</option>
                <option value="10">Level 10+</option>
                <option value="12">Level 12+</option>
              </select>
            </HuntField>

            <HuntField label="Wazuh Rule ID">
              <input placeholder="e.g. 86601" value={filters.rule_id} onChange={(e) => updateFilter('rule_id', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Suricata Signature">
              <input placeholder="Signature text" value={filters.signature} onChange={(e) => updateFilter('signature', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Signature ID">
              <input placeholder="e.g. 2210054" value={filters.signature_id} onChange={(e) => updateFilter('signature_id', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Protocol">
              <input placeholder="TCP / UDP" value={filters.protocol} onChange={(e) => updateFilter('protocol', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Application Protocol">
              <input placeholder="tls / http / dns" value={filters.app_proto} onChange={(e) => updateFilter('app_proto', e.target.value)} className={inputCls} />
            </HuntField>

            <HuntField label="Direction">
              <select value={filters.direction} onChange={(e) => updateFilter('direction', e.target.value)} className={inputCls}>
                <option value="">Any direction</option>
                <option value="to_client">To client</option>
                <option value="to_server">To server</option>
              </select>
            </HuntField>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-cyan-500 hover:bg-cyan-400 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Running Hunt…' : 'Run Hunt'}
            </button>
            <button
              type="button"
              onClick={resetFilters}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors"
            >
              Reset
            </button>
          </div>
        </SectionCard>
      </form>

      {error && <ErrorBanner message={error} />}

      {result && (
        <>
          <SectionCard eyebrow="HUNT SUMMARY" title="Search Results" subtitle="Raw Wazuh alert documents matching the selected hunt conditions." right={<Badge>{result.status}</Badge>}>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              <MetricTile label="Total Matches" value={result.total_matches ?? 0} />
              <MetricTile label="Returned" value={result.returned_count ?? 0} />
              <MetricTile label="Suricata Alerts" value={result.suricata_alert_count ?? 0} />
              <MetricTile label="Highest Level" value={result.highest_rule_level ?? '—'} />
              <MetricTile label="Unique Sources" value={result.unique_source_ips ?? 0} />
              <MetricTile label="Unique Destinations" value={result.unique_destination_ips ?? 0} />
            </div>
          </SectionCard>

          <SectionCard>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Top Wazuh Rules</p>
                {result.top_rules?.length ? (
                  result.top_rules.map((rule, index) => <DataRow key={`${rule.description}-${index}`} label={rule.description} value={rule.count} />)
                ) : (
                  <p className="text-sm text-slate-400 dark:text-slate-500">No Wazuh rule summary.</p>
                )}
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Top Suricata Signatures</p>
                {result.top_signatures?.length ? (
                  result.top_signatures.map((sig, index) => <DataRow key={`${sig.signature}-${index}`} label={sig.signature} value={sig.count} />)
                ) : (
                  <p className="text-sm text-slate-400 dark:text-slate-500">No Suricata signature summary.</p>
                )}
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Hunt Evidence" subtitle="Investigate either side of a flow directly in IP Reputation Intelligence.">
            {(() => {
              // MedShield is IPv4-only. The backend already excludes IPv6
              // hits from these results; this is a defense-in-depth filter
              // matching the same pattern used in the Live Feed/Overview
              // tabs, in case an older or misconfigured backend still
              // returns one. An alert with no IP at all (e.g. a
              // non-network Wazuh decoder) is kept — only an address that
              // is explicitly IPv6 is excluded.
              const hasIpv6 = (ip?: string | null) => !!ip && ip.includes(':');
              const ipv4Alerts = (result.alerts || []).filter(
                (alert) => !hasIpv6(alert.src_ip) && !hasIpv6(alert.dest_ip)
              );

              return !ipv4Alerts.length ? (
                <EmptyNotice>No alerts matched this hunt.</EmptyNotice>
              ) : (
                <div className="overflow-x-auto -mx-1">
                  <table className="w-full min-w-[880px]">
                    <thead>
                      <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                        <th className="py-2 px-2 text-left">Time</th>
                        <th className="py-2 px-2 text-left">Flow</th>
                        <th className="py-2 px-2 text-left">Rule</th>
                        <th className="py-2 px-2 text-left">Signature</th>
                        <th className="py-2 px-2 text-left">Severity</th>
                        <th className="py-2 px-2 text-left">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ipv4Alerts.map((alert) => (
                        <tr key={alert.document_id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                          <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(alert.timestamp)}</td>
                          <td className="py-2 px-2">
                            <span className="font-medium text-slate-900 dark:text-white">
                              {alert.src_ip || '—'}{alert.src_port ? `:${alert.src_port}` : ''}
                            </span>
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">
                              → {alert.dest_ip || '—'}{alert.dest_port ? `:${alert.dest_port}` : ''} • {alert.app_proto || alert.protocol || 'unknown'}
                            </span>
                          </td>
                          <td className="py-2 px-2">
                            <span className="font-medium text-slate-900 dark:text-white">{alert.wazuh_rule?.id || '—'}</span>
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">Level {alert.wazuh_rule?.level ?? '—'}</span>
                          </td>
                          <td className="py-2 px-2">
                            {alert.suricata_alert?.signature || alert.wazuh_rule?.description || '—'}
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">{alert.suricata_alert?.signature_id || '—'}</span>
                          </td>
                          <td className="py-2 px-2">
                            <Badge tone={toneOf(String(alert.suricata_alert?.severity ?? ''))}>{alert.suricata_alert?.severity ?? '—'}</Badge>
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">{alert.direction || '—'}</span>
                          </td>
                          <td className="py-2 px-2">
                            <div className="flex flex-col gap-1">
                              {alert.src_ip && (
                                <button
                                  type="button"
                                  onClick={() => onInvestigate(alert.src_ip as string)}
                                  className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-medium text-left"
                                >
                                  Investigate Src
                                </button>
                              )}
                              {alert.dest_ip && (
                                <button
                                  type="button"
                                  onClick={() => onInvestigate(alert.dest_ip as string)}
                                  className="text-xs text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 font-medium text-left"
                                >
                                  Investigate Dst
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </SectionCard>
        </>
      )}
    </div>
  );
};

export default ThreatHuntView;
