// frontend/src/pages/dashboard/DetectionPerformancePanel.tsx
// Live analog of the offline evaluation in ai_server/src/hospital_scenarios.py
// (alert_ranking_accuracy / mean_time_to_critical / false_positive_rate_top_n)
// — same rank-based definitions, computed against the current live alert
// buffer via GET /api/detection-performance instead of the labeled synthetic
// scenario dataset. See detectionMetrics.js for the exact methodology.
import React, { useEffect, useState } from 'react';
import { Gauge, Target, Clock, ShieldAlert, Info, Loader2, AlertCircle, ShieldCheck, ShieldX, Users } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import StatCard from '../../components/StatCard';
import {
  apiGetDetectionPerformance, apiGetKevStatus,
  DetectionPerformance, KevStatus,
} from '../../services/detectionPerformanceApi';

const REFRESH_MS = 20_000;

const fmt = (v: number | null | undefined, digits = 1, suffix = '') =>
  typeof v === 'number' ? `${v.toFixed(digits)}${suffix}` : '—';

const ComparisonBar: React.FC<{ label: string; caap: number | null; ruleLevel: number | null; higherIsBetter: boolean; suffix?: string }> = ({
  label, caap, ruleLevel, higherIsBetter, suffix = '%',
}) => {
  const max = Math.max(caap ?? 0, ruleLevel ?? 0, 1);
  const caapBetter = caap !== null && ruleLevel !== null && (higherIsBetter ? caap >= ruleLevel : caap <= ruleLevel);
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-slate-500 dark:text-slate-400">{label}</span>
        <span className="text-slate-400 dark:text-slate-600">{higherIsBetter ? 'higher is better' : 'lower is better'}</span>
      </div>
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="w-16 text-[11px] text-cyan-600 dark:text-cyan-400 font-medium flex-shrink-0">CAS</span>
          <div className="flex-1 bg-slate-100 dark:bg-slate-800 rounded-full h-2">
            <div className="h-2 rounded-full bg-cyan-500" style={{ width: caap === null ? 0 : `${Math.max(4, (caap / max) * 100)}%` }} />
          </div>
          <span className={`w-16 text-right text-[11px] font-mono flex-shrink-0 ${caapBetter ? 'text-emerald-500 dark:text-emerald-400 font-semibold' : 'text-slate-500 dark:text-slate-400'}`}>
            {fmt(caap, 1, suffix)}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-16 text-[11px] text-slate-400 dark:text-slate-500 font-medium flex-shrink-0">rule.level</span>
          <div className="flex-1 bg-slate-100 dark:bg-slate-800 rounded-full h-2">
            <div className="h-2 rounded-full bg-slate-400 dark:bg-slate-600" style={{ width: ruleLevel === null ? 0 : `${Math.max(4, (ruleLevel / max) * 100)}%` }} />
          </div>
          <span className={`w-16 text-right text-[11px] font-mono flex-shrink-0 ${!caapBetter && caap !== null && ruleLevel !== null ? 'text-emerald-500 dark:text-emerald-400 font-semibold' : 'text-slate-500 dark:text-slate-400'}`}>
            {fmt(ruleLevel, 1, suffix)}
          </span>
        </div>
      </div>
    </div>
  );
};

const KevStatusChip: React.FC<{ status: KevStatus | null }> = ({ status }) => {
  if (!status) return null;
  if (status.loaded) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs font-medium">
        <ShieldCheck className="w-3.5 h-3.5" />
        CISA KEV loaded — {status.count.toLocaleString()} known-exploited CVEs
        {status.lastUpdated && ` · updated ${new Date(status.lastUpdated).toLocaleString()}`}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400 text-xs font-medium"
      title={status.lastError ?? undefined}
    >
      <ShieldX className="w-3.5 h-3.5" />
      CISA KEV not loaded — AE scoring is using the MITRE-technique fallback
    </span>
  );
};

const DetectionPerformancePanel: React.FC = () => {
  const { token } = useAuth();
  const [data, setData] = useState<DetectionPerformance | null>(null);
  const [kev, setKev] = useState<KevStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    const load = () => {
      Promise.all([apiGetDetectionPerformance(token), apiGetKevStatus(token)])
        .then(([perf, kevStatus]) => {
          if (cancelled) return;
          setData(perf);
          setKev(kevStatus);
          setError('');
        })
        .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load detection performance.'); })
        .finally(() => { if (!cancelled) setLoading(false); });
    };

    load();
    const interval = setInterval(load, REFRESH_MS);
    return () => { cancelled = true; clearInterval(interval); };
  }, [token]);

  const ara10Caap = data?.caap.alertRankingAccuracy?.['10'] ?? null;
  const ara10Rule = data?.ruleLevelOnly.alertRankingAccuracy?.['10'] ?? null;

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Gauge className="w-4.5 h-4.5 text-cyan-500 dark:text-cyan-400" />
            Detection Performance
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            CAS ranking quality vs. a severity-only baseline — live analog of the offline evaluation in{' '}
            <code className="text-[11px] font-mono text-cyan-600 dark:text-cyan-400">ai_server/src/hospital_scenarios.py</code>
          </p>
        </div>
        {loading && <Loader2 className="w-4 h-4 text-slate-400 dark:text-slate-600 animate-spin" />}
      </div>

      <KevStatusChip status={kev} />

      {data && data.analystFeedback.totalJudged > 0 && (
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Users className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
            Analyst-judged accuracy
          </h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 mb-4">
            Real ground truth from closed cases (all-time, not the live buffer) — the only place this system's accuracy is measured against an actual human judgment rather than a proxy.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <div>
              <div className="text-2xl font-bold tabular-nums text-slate-900 dark:text-white">{fmt(data.analystFeedback.falsePositiveRate, 0, '%')}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">False positive rate</div>
            </div>
            <div>
              <div className="text-2xl font-bold tabular-nums text-slate-900 dark:text-white">{data.analystFeedback.totalJudged}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Cases judged</div>
            </div>
            <div>
              <div className="text-lg font-semibold tabular-nums text-red-600 dark:text-red-400">{data.analystFeedback.counts.true_positive}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">True positive</div>
            </div>
            <div>
              <div className="text-lg font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">{data.analystFeedback.counts.false_positive}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">False positive</div>
            </div>
            <div>
              <div className="text-lg font-semibold tabular-nums text-slate-500 dark:text-slate-400">{data.analystFeedback.counts.benign + data.analystFeedback.counts.uncertain}</div>
              <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">Benign / uncertain</div>
            </div>
          </div>
        </div>
      )}

      {error ? (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      ) : !data || data.sampleSize === 0 ? (
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Gauge className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">No alerts in the buffer yet</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">These metrics need live alerts to compute against — start the pipeline and this fills in automatically.</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={<Target className="w-5 h-5" />}
              label="Alert Ranking Accuracy (top 10)"
              value={fmt(ara10Caap, 0, '%')}
              sub={`vs. ${fmt(ara10Rule, 0, '%')} for rule.level alone`}
              color="cyan"
            />
            <StatCard
              icon={<Clock className="w-5 h-5" />}
              label="Mean Time to Critical"
              value={fmt(data.caap.meanTimeToCritical, 1)}
              sub="Avg. queue rank of life-critical alerts — lower is better"
              color="violet"
            />
            <StatCard
              icon={<ShieldAlert className="w-5 h-5" />}
              label="False Positive Rate (top 10)"
              value={fmt(data.caap.falsePositiveRateTop10, 0, '%')}
              sub="Low-criticality alerts crowding the top 10"
              color="amber"
            />
            <StatCard
              icon={<Gauge className="w-5 h-5" />}
              label="Sample"
              value={String(data.sampleSize)}
              sub={`${data.lifeCriticalCount} against life-critical devices`}
              color="slate"
            />
          </div>

          <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5 space-y-5">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">CAS vs. severity-only ranking</h3>
            <div className="grid sm:grid-cols-2 gap-x-8 gap-y-5">
              <ComparisonBar
                label="Alert Ranking Accuracy — top 5"
                caap={data.caap.alertRankingAccuracy['5']}
                ruleLevel={data.ruleLevelOnly.alertRankingAccuracy['5']}
                higherIsBetter
              />
              <ComparisonBar
                label="Alert Ranking Accuracy — top 10"
                caap={data.caap.alertRankingAccuracy['10']}
                ruleLevel={data.ruleLevelOnly.alertRankingAccuracy['10']}
                higherIsBetter
              />
              <ComparisonBar
                label="Alert Ranking Accuracy — top 20"
                caap={data.caap.alertRankingAccuracy['20']}
                ruleLevel={data.ruleLevelOnly.alertRankingAccuracy['20']}
                higherIsBetter
              />
              <ComparisonBar
                label="False Positive Rate — top 10"
                caap={data.caap.falsePositiveRateTop10}
                ruleLevel={data.ruleLevelOnly.falsePositiveRateTop10}
                higherIsBetter={false}
              />
            </div>
          </div>
        </>
      )}

      <div className="flex items-start gap-2 px-1">
        <Info className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-slate-400 dark:text-slate-600">
          {data?.methodology ??
            'Rank-based metrics computed against the current in-memory alert buffer, using medical device inventory ' +
            'criticality as the "how clinically important is this" signal. Not a substitute for a full offline evaluation.'}
        </p>
      </div>
    </div>
  );
};

export default DetectionPerformancePanel;
