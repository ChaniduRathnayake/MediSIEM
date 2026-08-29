// Port of components/OverviewPage.jsx — live summary derived from observed IP
// intelligence profiles, internal lists and recent analyst activity.
import React, { useCallback, useEffect, useState } from 'react';
import { getIntelligenceProfiles, getAllLists, getAuditEvents } from './ipReputationApi';
import type { IntelligenceProfile, ListEntry, AuditEvent } from './ipReputationApi';
import { SectionCard, MetricTile, DataRow, Badge, EmptyNotice, ErrorBanner, LoadingBlock, RefreshButton, fmtDateTime, toneOf, formatLabel, isIPv4 } from './shared';

const RISK_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Minimal'];

const OverviewView: React.FC = () => {
  const [profiles, setProfiles] = useState<IntelligenceProfile[]>([]);
  const [lists, setLists] = useState<ListEntry[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadOverview = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [intelligenceData, listData, auditData] = await Promise.all([
        getIntelligenceProfiles(500),
        getAllLists(),
        getAuditEvents(10),
      ]);
      // IPv6 noise dominates the raw feed and buries the IPv4 activity
      // analysts actually care about here — filter to IPv4-only, same as
      // LiveDashboardView's live feed.
      setProfiles((intelligenceData.profiles || []).filter((p) => isIPv4(p.ip)));
      setLists(listData.items || []);
      setAudit(auditData.events || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to load MedShield intelligence overview.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  const publicCount = profiles.filter((p) => p.classification?.category === 'public').length;
  const privateCount = profiles.filter((p) => p.classification?.category === 'private').length;
  const riskCount = (risk: string) => profiles.filter((p) => p.current_risk_level === risk).length;
  const totalObservations = profiles.reduce((total, p) => total + (p.observation_count || 0), 0);
  const watchCount = lists.filter((i) => i.list_type === 'watch').length;
  const blockCount = lists.filter((i) => i.list_type === 'block').length;
  const allowCount = lists.filter((i) => i.list_type === 'allow').length;
  const flaggedProfiles = profiles.filter((p) => ['Medium', 'High', 'Critical'].includes(p.current_risk_level || ''));

  if (loading && profiles.length === 0) {
    return <LoadingBlock label="Loading MedShield intelligence overview…" />;
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <span className="text-[10px] font-semibold tracking-wider text-cyan-600 dark:text-cyan-400 uppercase">MedShield Security Intelligence</span>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mt-0.5">Security Overview</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
            Live summary derived from MedShield reputation intelligence, internal lists and analyst activity.
          </p>
        </div>
        <RefreshButton onClick={() => void loadOverview()} loading={loading} />
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <MetricTile label="Observed IPs" value={profiles.length} />
        <MetricTile label="Public IPs" value={publicCount} />
        <MetricTile label="Private IPs" value={privateCount} />
        <MetricTile label="Observations" value={totalObservations} />
        <MetricTile label="Medium Risk" value={riskCount('Medium')} tone="warn" />
        <MetricTile label="High Risk" value={riskCount('High')} tone="bad" />
        <MetricTile label="Critical Risk" value={riskCount('Critical')} tone="bad" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <SectionCard title="Reputation Risk Distribution">
          {RISK_LEVELS.map((level) => (
            <DataRow key={level} label={level} value={riskCount(level)} />
          ))}
          <DataRow label="No external assessment" value={profiles.filter((p) => !p.current_risk_level).length} />
        </SectionCard>

        <SectionCard title="Internal Intelligence">
          <DataRow label="Allow" value={allowCount} />
          <DataRow label="Watch" value={watchCount} />
          <DataRow label="Block" value={blockCount} />
          <DataRow label="Managed entries" value={lists.length} />
        </SectionCard>
      </div>

      <SectionCard
        title="Observed IP Intelligence"
        subtitle="Addresses investigated or observed by the MedShield reputation subsystem."
        right={<Badge>{profiles.length} profiles</Badge>}
      >
        {profiles.length === 0 ? (
          <EmptyNotice>No IP intelligence has been recorded.</EmptyNotice>
        ) : (
          <div className="overflow-x-auto -mx-1">
            <table className="w-full min-w-[720px]">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2 px-2 text-left">IP Address</th>
                  <th className="py-2 px-2 text-left">Type</th>
                  <th className="py-2 px-2 text-left">Risk</th>
                  <th className="py-2 px-2 text-left">Score</th>
                  <th className="py-2 px-2 text-left">Observations</th>
                  <th className="py-2 px-2 text-left">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {profiles.slice(0, 20).map((p) => (
                  <tr key={p._id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                    <td className="py-2 px-2 font-medium text-slate-900 dark:text-white">{p.ip}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{p.classification?.category || 'unknown'}</td>
                    <td className="py-2 px-2">
                      <Badge tone={toneOf(p.current_risk_level)}>{p.current_risk_level || 'Context only'}</Badge>
                    </td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{p.current_score == null ? '—' : `${p.current_score}/100`}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{p.observation_count || 0}</td>
                    <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(p.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <SectionCard title="Risk Requiring Attention">
          {flaggedProfiles.length === 0 ? (
            <EmptyNotice>No Medium, High or Critical external reputation profiles.</EmptyNotice>
          ) : (
            <div className="space-y-2">
              {flaggedProfiles.map((p) => (
                <div key={p._id} className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 dark:border-slate-800/60 last:border-0">
                  <div>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">{p.ip}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500">{p.latest_reputation_analysis?.decision || 'Reputation assessment'}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge tone={toneOf(p.current_risk_level)}>{p.current_risk_level}</Badge>
                    <span className="text-sm font-bold text-slate-900 dark:text-white">{p.current_score ?? '—'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Recent Analyst Activity">
          {audit.length === 0 ? (
            <EmptyNotice>No analyst activity recorded.</EmptyNotice>
          ) : (
            <div className="space-y-2">
              {audit.slice(0, 6).map((event) => (
                <div key={event._id} className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 dark:border-slate-800/60 last:border-0">
                  <div>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">{formatLabel(event.action)}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500">{event.subject || '—'}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-500 dark:text-slate-400">{event.actor || 'system'}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500">{fmtDateTime(event.created_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      </div>
    </div>
  );
};

export default OverviewView;
