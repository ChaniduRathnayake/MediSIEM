// Port of components/LogSourcesPage.jsx — real-time health/telemetry
// visibility for data sources connected to MedShield.
import React, { useCallback, useEffect, useState } from 'react';
import { getLogSources } from './ipReputationApi';
import type { LogSourcesResult } from './ipReputationApi';
import { SectionCard, MetricTile, DataRow, Badge, ErrorBanner, LoadingBlock, RefreshButton, fmtDateTime, toneOf, formatLabel } from './shared';

const LogSourcesView: React.FC = () => {
  const [data, setData] = useState<LogSourcesResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadSources = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await getLogSources();
      setData(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unable to load source health.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSources();
  }, [loadSources]);

  if (loading && !data) {
    return <LoadingBlock label="Checking MedShield source health…" />;
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <span className="text-[10px] font-semibold tracking-wider text-cyan-600 dark:text-cyan-400 uppercase">MedShield Telemetry</span>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white mt-0.5">Log Sources</h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Real-time health and telemetry visibility for data sources connected to MedShield.</p>
        </div>
        <RefreshButton onClick={() => void loadSources()} loading={loading} />
      </div>

      {error && <ErrorBanner message={error} />}

      {data && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetricTile label="Configured Sources" value={data.count ?? 0} />
            <MetricTile label="Healthy" value={data.healthy ?? 0} tone="good" />
            <MetricTile label="Degraded" value={data.degraded ?? 0} tone="warn" />
            <MetricTile label="Unavailable" value={data.unavailable ?? 0} tone="bad" />
          </div>

          {data.sources?.map((source) => (
            <SectionCard
              key={source.id}
              eyebrow={source.type}
              title={source.name}
              subtitle={source.message}
              right={<Badge tone={toneOf(source.status)}>{formatLabel(source.status)}</Badge>}
            >
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <MetricTile label="Telemetry Records" value={source.records_available ?? 0} />
                <MetricTile label="ML Fusion" value={source.ml_fusion_observed ? 'Observed' : 'Not observed'} tone={source.ml_fusion_observed ? 'good' : 'neutral'} />
                <MetricTile label="Feature Coverage" value={source.average_feature_coverage == null ? '—' : `${source.average_feature_coverage}%`} />
                <MetricTile label="HTTP Status" value={source.http_status ?? '—'} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
                <div>
                  <DataRow label="Reachable" value={source.reachable ? 'Yes' : 'No'} />
                  <DataRow label="Source type" value={source.type} />
                  <DataRow label="Source identifier" value={source.id} />
                </div>
                <div>
                  <DataRow label="Latest telemetry" value={source.latest_event_timestamp ? fmtDateTime(source.latest_event_timestamp) : 'No telemetry timestamp'} />
                  <DataRow label="Last health check" value={fmtDateTime(source.checked_at)} />
                  <DataRow label="Endpoint" value={source.endpoint || '—'} />
                </div>
              </div>

              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Evidence</p>
              <p className="text-xs text-slate-400 dark:text-slate-500">
                This health state is derived from an actual request to the configured MedShield telemetry source. A healthy
                state requires the source to be reachable and to return telemetry records.
              </p>
            </SectionCard>
          ))}
        </>
      )}
    </div>
  );
};

export default LogSourcesView;
