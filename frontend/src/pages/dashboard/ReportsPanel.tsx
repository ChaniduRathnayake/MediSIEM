// Real report generation, backed by AlertClosure/AlertAssignment/AlertLog, or for
// compliance, the Wazuh Indexer via the same connection CompliancePanel.tsx uses.
import React, { useMemo, useState } from 'react';
import {
  FileText, Loader2, AlertCircle, Download, Printer, Calendar, Inbox, ClipboardList, Clock, Moon,
  Server, TrendingUp, ShieldCheck, ChevronRight, Wand2,
} from 'lucide-react';
import { downloadCsv } from '../../utils/csv';
import { apiGetMyCaseHistory } from '../../services/alertsApi';
import type { MyHistoryClosure } from '../../services/alertsApi';
import {
  apiGetDetectionAccuracyReport, apiGetEscalationBacklogReport, apiGetOffHoursReport,
  apiGetDeviceRiskReport, apiGetThreatSummaryReport, apiGenerateThreatNarrative, apiGenerateComplianceNarrative,
} from '../../services/reportsApi';
import type {
  DetectionAccuracyReport, EscalationBacklogReport, OffHoursReport, DeviceRiskReport, ThreatSummaryReport,
} from '../../services/reportsApi';
import { useWazuhContext } from './WazuhContext';
import { hasIndexerConfig, getComplianceSummary } from './complianceApi';
import type { ComplianceSummary, ComplianceFramework } from './complianceApi';
import StatCard from '../../components/StatCard';

type ReportId =
  | 'my-case-history' | 'detection-accuracy' | 'escalation-backlog'
  | 'off-hours' | 'device-risk' | 'threat-summary' | 'compliance-evidence';

const REPORT_TYPES: { id: ReportId; label: string; description: string; icon: React.ReactNode }[] = [
  { id: 'my-case-history', label: 'My Case History', description: 'Cases you closed in the selected range — verdict, reason, evidence, time to resolve.', icon: <Inbox className="w-4 h-4" /> },
  { id: 'detection-accuracy', label: 'Detection Accuracy', description: 'Verdict breakdown by alert type — where your own judgment agreed or disagreed with the model.', icon: <ClipboardList className="w-4 h-4" /> },
  { id: 'escalation-backlog', label: 'Escalation Backlog', description: 'How long your CAS-critical claims sat before you picked them up.', icon: <Clock className="w-4 h-4" /> },
  { id: 'off-hours', label: 'Off-Hours Activity', description: 'Alerts detected outside business hours (before 06:00 or after 22:00).', icon: <Moon className="w-4 h-4" /> },
  { id: 'device-risk', label: 'Device Risk', description: 'Which devices generated the most (and most severe) alerts in the range.', icon: <Server className="w-4 h-4" /> },
  { id: 'threat-summary', label: 'Threat Summary', description: 'Volume by severity/department, top alert types, busiest devices.', icon: <TrendingUp className="w-4 h-4" /> },
  { id: 'compliance-evidence', label: 'Compliance Evidence', description: 'HIPAA/GDPR control activity per device — requires the Wazuh Indexer connection.', icon: <ShieldCheck className="w-4 h-4" /> },
];

function isoDate(d: Date): string { return d.toISOString().slice(0, 10); }
function startOfDay(d: Date): Date { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; }
function daysAgo(n: number): Date { return startOfDay(new Date(Date.now() - n * 24 * 60 * 60 * 1000)); }

const PRESETS: { label: string; from: () => Date; to: () => Date }[] = [
  { label: 'Today', from: () => startOfDay(new Date()), to: () => new Date() },
  { label: 'This week', from: () => daysAgo(7), to: () => new Date() },
  { label: 'This month', from: () => daysAgo(30), to: () => new Date() },
  { label: 'Last 90 days', from: () => daysAgo(90), to: () => new Date() },
];

const DateRangePicker: React.FC<{ from: string; to: string; onChange: (from: string, to: string) => void }> = ({ from, to, onChange }) => (
  <div className="flex items-center gap-2 flex-wrap no-print">
    <span className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
      <Calendar className="w-3.5 h-3.5" /> Range
    </span>
    <input type="date" value={from} onChange={(e) => onChange(e.target.value, to)} className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60" />
    <span className="text-xs text-slate-400">to</span>
    <input type="date" value={to} onChange={(e) => onChange(from, e.target.value)} className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60" />
    <div className="flex items-center gap-1 ml-1">
      {PRESETS.map((p) => (
        <button
          key={p.label}
          onClick={() => onChange(isoDate(p.from()), isoDate(p.to()))}
          className="px-2 py-1 rounded-md text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        >
          {p.label}
        </button>
      ))}
    </div>
  </div>
);

const ReportActions: React.FC<{ onCsv?: () => void }> = ({ onCsv }) => (
  <div className="flex items-center gap-2 no-print">
    {onCsv && (
      <button onClick={onCsv} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors">
        <Download className="w-3.5 h-3.5" /> CSV
      </button>
    )}
    <button onClick={() => window.print()} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors">
      <Printer className="w-3.5 h-3.5" /> Print
    </button>
  </div>
);

const ReportCard: React.FC<{ label: string; hint?: string }> = ({ label, hint }) => (
  <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
    <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
    <div className="text-sm font-mono text-slate-900 dark:text-white mt-0.5">{hint}</div>
  </div>
);

const SimpleTable: React.FC<{ headers: string[]; rows: React.ReactNode[][]; empty: string }> = ({ headers, rows, empty }) =>
  rows.length === 0 ? (
    <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">{empty}</p>
  ) : (
    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
            {headers.map((h) => <th key={h} className="py-2 px-3 text-left whitespace-nowrap">{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className={i % 2 === 0 ? '' : 'bg-slate-50 dark:bg-slate-900/40'}>
              {row.map((cell, j) => <td key={j} className="py-2 px-3 text-slate-700 dark:text-slate-300 whitespace-nowrap">{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

const ReportsPanel: React.FC<{ token: string | null }> = ({ token }) => {
  const { config } = useWazuhContext();
  const [selected, setSelected] = useState<ReportId>('my-case-history');
  const [from, setFrom] = useState(isoDate(daysAgo(30)));
  const [to, setTo] = useState(isoDate(new Date()));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [caseHistory, setCaseHistory] = useState<MyHistoryClosure[] | null>(null);
  const [accuracy, setAccuracy] = useState<DetectionAccuracyReport | null>(null);
  const [backlog, setBacklog] = useState<EscalationBacklogReport | null>(null);
  const [offHours, setOffHours] = useState<OffHoursReport | null>(null);
  const [deviceRisk, setDeviceRisk] = useState<DeviceRiskReport | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummaryReport | null>(null);
  const [complianceFramework, setComplianceFramework] = useState<ComplianceFramework>('hipaa');
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);

  const range = useMemo(() => ({ from: new Date(from).toISOString(), to: new Date(`${to}T23:59:59`).toISOString() }), [from, to]);
  const rangeDays = useMemo(() => Math.max(1, Math.round((new Date(to).getTime() - new Date(from).getTime()) / 86400000) + 1), [from, to]);

  const generate = async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      switch (selected) {
        case 'my-case-history': {
          const { closures } = await apiGetMyCaseHistory(token, { from: range.from, to: range.to, limit: 500 });
          setCaseHistory(closures);
          break;
        }
        case 'detection-accuracy':
          setAccuracy(await apiGetDetectionAccuracyReport(token, range));
          break;
        case 'escalation-backlog':
          setBacklog(await apiGetEscalationBacklogReport(token, range));
          break;
        case 'off-hours':
          setOffHours(await apiGetOffHoursReport(token, range));
          break;
        case 'device-risk':
          setDeviceRisk(await apiGetDeviceRiskReport(token, range));
          break;
        case 'threat-summary':
          setThreatSummary(await apiGetThreatSummaryReport(token, range));
          break;
        case 'compliance-evidence': {
          if (!hasIndexerConfig(config)) { setError('Connect the Wazuh Indexer first — see Settings → Wazuh SIEM (or ask an admin).'); break; }
          setCompliance(await getComplianceSummary(config!, complianceFramework, rangeDays));
          break;
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report.');
    } finally {
      setLoading(false);
    }
  };

  const activeType = REPORT_TYPES.find((r) => r.id === selected)!;

  return (
    <div className="p-5 space-y-5">
      <div className="no-print">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Reports</h2>
        <p className="text-xs text-slate-500 mt-0.5">Generate a report from real case, alert, and compliance data — pick a type and a date range.</p>
      </div>

      {/* ─── Report type picker ─────────────────────────────────────────────── */}
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 no-print">
        {REPORT_TYPES.map((r) => (
          <button
            key={r.id}
            onClick={() => setSelected(r.id)}
            className={`text-left p-4 rounded-xl border transition-colors ${
              selected === r.id
                ? 'bg-cyan-500/5 border-cyan-500/40 ring-1 ring-cyan-500/20'
                : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
            }`}
          >
            <div className={`flex items-center gap-2 text-sm font-semibold ${selected === r.id ? 'text-cyan-700 dark:text-cyan-300' : 'text-slate-900 dark:text-white'}`}>
              {r.icon} {r.label}
            </div>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1.5 leading-relaxed">{r.description}</p>
          </button>
        ))}
      </div>

      {/* ─── Range + generate ───────────────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-3 flex-wrap p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 no-print">
        <DateRangePicker from={from} to={to} onChange={(f, t) => { setFrom(f); setTo(t); }} />
        {selected === 'compliance-evidence' && (
          <select value={complianceFramework} onChange={(e) => setComplianceFramework(e.target.value as ComplianceFramework)} className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60">
            <option value="hipaa">HIPAA</option>
            <option value="gdpr">GDPR</option>
          </select>
        )}
        <button
          onClick={generate}
          disabled={loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 disabled:cursor-not-allowed text-slate-950 transition-colors"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
          Generate
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 dark:text-red-400 text-sm no-print">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {/* ─── Results ─────────────────────────────────────────────────────────── */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">{activeType.icon} {activeType.label}</h3>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{from} to {to}</p>
          </div>
        </div>

        {selected === 'my-case-history' && (
          <MyCaseHistoryResult data={caseHistory} onCsv={() => caseHistory && downloadCsv(
            `medisiem-case-history-${from}-to-${to}.csv`,
            ['Closed At', 'Device', 'Department', 'Label', 'CAS', 'Verdict', 'Reason', 'Evidence'],
            caseHistory.map((c) => [new Date(c.createdAt).toLocaleString(), c.alertSnapshot?.agent ?? '', c.alertSnapshot?.department ?? '', c.alertSnapshot?.label ?? '', c.alertSnapshot?.CAS ?? '', c.verdict ?? '', c.reason, c.evidence])
          )} />
        )}
        {selected === 'detection-accuracy' && (
          <DetectionAccuracyResult data={accuracy} onCsv={() => accuracy && downloadCsv(
            `medisiem-detection-accuracy-${from}-to-${to}.csv`,
            ['Label', 'Total', 'True Positive', 'False Positive', 'Benign', 'Uncertain', 'Unset', 'FP Rate %'],
            accuracy.byLabel.map((r) => [r.label, r.total, r.true_positive, r.false_positive, r.benign, r.uncertain, r.unset, r.falsePositiveRate ?? ''])
          )} />
        )}
        {selected === 'escalation-backlog' && (
          <EscalationBacklogResult data={backlog} onCsv={() => backlog && downloadCsv(
            `medisiem-escalation-backlog-${from}-to-${to}.csv`,
            ['Detected At', 'Claimed At', 'Minutes To Claim', 'Label', 'Device', 'Department', 'CAS'],
            backlog.rows.map((r) => [new Date(r.detectedAt).toLocaleString(), new Date(r.claimedAt).toLocaleString(), r.minutesToClaim, r.label, r.agent ?? '', r.department ?? '', r.CAS ?? ''])
          )} />
        )}
        {selected === 'off-hours' && (
          <OffHoursResult data={offHours} onCsv={() => offHours && downloadCsv(
            `medisiem-off-hours-${from}-to-${to}.csv`,
            ['Timestamp', 'Severity', 'CAS', 'Device', 'Department', 'Label'],
            offHours.rows.map((r) => [new Date(r.timestamp).toLocaleString(), r.severity ?? '', r.CAS ?? '', r.agent ?? '', r.department ?? '', r.label ?? ''])
          )} />
        )}
        {selected === 'device-risk' && (
          <DeviceRiskResult data={deviceRisk} onCsv={() => deviceRisk && downloadCsv(
            `medisiem-device-risk-${from}-to-${to}.csv`,
            ['Device', 'Department', 'Type', 'Criticality', 'Alert Count', 'Avg CAS', 'Critical Count'],
            deviceRisk.devices.map((d) => [d.agent, d.department ?? '', d.deviceType ?? '', d.deviceCriticality ?? '', d.alertCount, d.avgCAS, d.criticalCount])
          )} />
        )}
        {selected === 'threat-summary' && <ThreatSummaryResult data={threatSummary} token={token} />}
        {selected === 'compliance-evidence' && <ComplianceEvidenceResult data={compliance} framework={complianceFramework} indexerReady={hasIndexerConfig(config)} token={token} />}
      </div>
    </div>
  );
};

const MyCaseHistoryResult: React.FC<{ data: MyHistoryClosure[] | null; onCsv: () => void }> = ({ data, onCsv }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  const verdictCounts = data.reduce<Record<string, number>>((acc, c) => { const v = c.verdict ?? 'unset'; acc[v] = (acc[v] ?? 0) + 1; return acc; }, {});
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between"><span className="text-xs text-slate-500">{data.length} case{data.length === 1 ? '' : 's'} closed in range</span><ReportActions onCsv={onCsv} /></div>
      <SimpleTable
        headers={['Closed', 'Device', 'Department', 'Event', 'CAS', 'Verdict', 'Reason']}
        empty="No cases closed in this range."
        rows={data.map((c) => [
          new Date(c.createdAt).toLocaleString(),
          c.alertSnapshot?.agent ?? '—',
          c.alertSnapshot?.department ?? '—',
          c.alertSnapshot?.label ?? c.alertSnapshot?.ruleDescription ?? '—',
          c.alertSnapshot?.CAS?.toFixed(1) ?? '—',
          c.verdict?.replace('_', ' ') ?? '—',
          <span key="r" className="max-w-xs truncate block" title={c.reason}>{c.reason}</span>,
        ])}
      />
      {Object.keys(verdictCounts).length > 0 && (
        <p className="text-xs text-slate-400 dark:text-slate-500">
          {Object.entries(verdictCounts).map(([v, n]) => `${v.replace('_', ' ')}: ${n}`).join(' · ')}
        </p>
      )}
    </div>
  );
};

const DetectionAccuracyResult: React.FC<{ data: DetectionAccuracyReport | null; onCsv: () => void }> = ({ data, onCsv }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  const overallFpRate = data.overall.true_positive + data.overall.false_positive > 0
    ? Math.round((data.overall.false_positive / (data.overall.true_positive + data.overall.false_positive)) * 1000) / 10
    : null;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <ReportCard label="Cases Closed" hint={String(data.totalClosed)} />
        <ReportCard label="True Positive" hint={String(data.overall.true_positive)} />
        <ReportCard label="False Positive Rate" hint={overallFpRate !== null ? `${overallFpRate}%` : '—'} />
      </div>
      <div className="flex justify-end"><ReportActions onCsv={onCsv} /></div>
      <SimpleTable
        headers={['Alert Type', 'Total', 'True Pos', 'False Pos', 'Benign', 'Uncertain', 'FP Rate']}
        empty="No closed cases in this range."
        rows={data.byLabel.map((r) => [r.label, r.total, r.true_positive, r.false_positive, r.benign, r.uncertain, r.falsePositiveRate !== null ? `${r.falsePositiveRate}%` : '—'])}
      />
    </div>
  );
};

const EscalationBacklogResult: React.FC<{ data: EscalationBacklogReport | null; onCsv: () => void }> = ({ data, onCsv }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <ReportCard label="Critical Claims" hint={String(data.count)} />
        <ReportCard label="Avg. Minutes To Claim" hint={data.avgMinutesToClaim !== null ? `${data.avgMinutesToClaim}m` : '—'} />
      </div>
      <div className="flex justify-end"><ReportActions onCsv={onCsv} /></div>
      <SimpleTable
        headers={['Detected', 'Claimed', 'Minutes To Claim', 'Event', 'Device', 'CAS']}
        empty="No CAS-critical claims in this range."
        rows={data.rows.map((r) => [new Date(r.detectedAt).toLocaleString(), new Date(r.claimedAt).toLocaleString(), r.minutesToClaim, r.label, r.agent ?? '—', r.CAS?.toFixed(1) ?? '—'])}
      />
    </div>
  );
};

const OffHoursResult: React.FC<{ data: OffHoursReport | null; onCsv: () => void }> = ({ data, onCsv }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <ReportCard label="Off-Hours Alerts" hint={String(data.offHoursCount)} />
        <ReportCard label="Share Of Range" hint={`${data.offHoursPercentage}%`} />
        <ReportCard label="Critical Off-Hours" hint={String(data.bySeverity.CRITICAL)} />
      </div>
      <div className="flex justify-end"><ReportActions onCsv={onCsv} /></div>
      <SimpleTable
        headers={['Time', 'Severity', 'CAS', 'Device', 'Department', 'Event']}
        empty="No off-hours alerts in this range."
        rows={data.rows.map((r) => [new Date(r.timestamp).toLocaleString(), r.severity ?? '—', r.CAS?.toFixed(1) ?? '—', r.agent ?? '—', r.department ?? '—', r.label ?? '—'])}
      />
    </div>
  );
};

const DeviceRiskResult: React.FC<{ data: DeviceRiskReport | null; onCsv: () => void }> = ({ data, onCsv }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  return (
    <div className="space-y-3">
      <div className="flex justify-end"><ReportActions onCsv={onCsv} /></div>
      <SimpleTable
        headers={['Device', 'Department', 'Type', 'Criticality', 'Alerts', 'Avg CAS', 'Critical']}
        empty="No alert activity in this range."
        rows={data.devices.map((d) => [
          d.agent, d.department ?? '—', d.deviceType ?? '—',
          <span key="c" className={d.deviceCriticality === 'critical' ? 'text-red-500 dark:text-red-400 font-semibold' : ''}>{d.deviceCriticality ?? '—'}</span>,
          d.alertCount, d.avgCAS.toFixed(1), d.criticalCount,
        ])}
      />
    </div>
  );
};

// Fired on demand (spends the configured Gemini key per click) — turns an
// already-fetched report object into a short plain-English narrative. The
// button is no-print; the resulting narrative text prints along with the
// rest of the report.
const NarrativeSection: React.FC<{ token: string | null; generate: () => Promise<{ narrative: string }> }> = ({ token, generate }) => {
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [narrative, setNarrative] = useState('');
  const [error, setError] = useState('');

  const run = async () => {
    if (!token) return;
    setState('loading');
    setError('');
    try {
      const { narrative: n } = await generate();
      setNarrative(n);
      setState('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI assistant request failed.');
      setState('error');
    }
  };

  if (!token) return null;

  return (
    <div>
      {state === 'idle' && (
        <button
          onClick={run}
          className="no-print flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400 hover:bg-violet-500/20 transition-colors"
        >
          <Wand2 className="w-3.5 h-3.5" /> Generate narrative
        </button>
      )}
      {state === 'loading' && (
        <div className="no-print flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating…
        </div>
      )}
      {state === 'error' && (
        <div className="no-print">
          <p className="text-xs text-red-500 dark:text-red-400">{error}</p>
          <button onClick={run} className="mt-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">Retry</button>
        </div>
      )}
      {state === 'done' && (
        <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-violet-500/5 border border-violet-500/20 rounded-lg px-3 py-2.5">
          {narrative}
        </p>
      )}
    </div>
  );
};

const ThreatSummaryResult: React.FC<{ data: ThreatSummaryReport | null; token: string | null }> = ({ data, token }) => {
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  return (
    <div className="space-y-4">
      <div className="flex justify-end no-print"><ReportActions /></div>
      <NarrativeSection token={token} generate={() => apiGenerateThreatNarrative(token!, data)} />
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard icon={<TrendingUp />} label="Total Alerts" value={String(data.totalAlerts)} sub="In range" color="slate" />
        <StatCard icon={<AlertCircle />} label="Critical" value={String(data.bySeverity.CRITICAL)} sub="CAS ≥ 8" color="red" />
        <StatCard icon={<Clock />} label="High" value={String(data.bySeverity.HIGH)} sub="CAS 6–8" color="orange" />
        <StatCard icon={<ChevronRight />} label="Immediate Action" value={String(data.byAction.Immediate)} sub="Action = Immediate" color="amber" />
      </div>
      <div className="grid sm:grid-cols-2 gap-4">
        <div>
          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Top alert types</p>
          <SimpleTable headers={['Label', 'Count']} empty="No data." rows={data.topLabels.map((l) => [l.label, l.count])} />
        </div>
        <div>
          <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Busiest devices</p>
          <SimpleTable headers={['Device', 'Count']} empty="No data." rows={data.topDevices.map((d) => [d.agent, d.count])} />
        </div>
      </div>
      <div>
        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">By department</p>
        <SimpleTable headers={['Department', 'Count']} empty="No data." rows={data.byDepartment.map((d) => [d.department, d.count])} />
      </div>
    </div>
  );
};

const ComplianceEvidenceResult: React.FC<{ data: ComplianceSummary | null; framework: ComplianceFramework; indexerReady: boolean; token: string | null }> = ({ data, framework, indexerReady, token }) => {
  if (!indexerReady) {
    return (
      <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">
        The Wazuh Indexer isn't connected on this browser — set it up under Settings → Wazuh SIEM, then come back here.
      </p>
    );
  }
  if (!data) return <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">Pick a range and click Generate.</p>;
  const onCsv = () => downloadCsv(
    `medisiem-compliance-${framework}-${data.days}d.csv`,
    ['Agent', 'Alert Count', 'Max Rule Level', 'Violated Controls'],
    data.agents.map((a) => [a.agentId, a.alertCount, a.maxLevel ?? '', a.violatedControls.join('; ')])
  );
  return (
    <div className="space-y-3">
      <p className="text-xs text-amber-600 dark:text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
        "Compliant" here means no alert fired against a rule mapped to this control in the window — this is observed activity, not a certified compliance audit.
      </p>
      <NarrativeSection token={token} generate={() => apiGenerateComplianceNarrative(token!, data, framework)} />
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-500">{data.observedControls.length} distinct {framework.toUpperCase()} control{data.observedControls.length === 1 ? '' : 's'} observed across {data.agents.length} device{data.agents.length === 1 ? '' : 's'}</span>
        <ReportActions onCsv={onCsv} />
      </div>
      <SimpleTable
        headers={['Device (Agent ID)', 'Alert Count', 'Max Rule Level', 'Violated Controls']}
        empty="No compliance-tagged activity in this window."
        rows={data.agents.map((a) => [a.agentId, a.alertCount, a.maxLevel ?? '—', <span key="v" className="max-w-md truncate block" title={a.violatedControls.join(', ')}>{a.violatedControls.join(', ') || '—'}</span>])}
      />
    </div>
  );
};

export default ReportsPanel;
