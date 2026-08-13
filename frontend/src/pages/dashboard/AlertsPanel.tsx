// frontend/src/pages/dashboard/AlertsPanel.tsx
// Full-fledged, real-data SIEM alerts view: CAS-ranked live feed (via
// useLiveAlerts), a timeline + severity-donut chart header, filters, and
// (for roles allowed to see the analyst directory) assignment. Shared by
// both the Admin console and the SOC Analyst dashboard so there's exactly
// one "what does an alert row look like" implementation.
import React, { useEffect, useMemo, useState } from 'react';
import {
  Bell, AlertTriangle, Zap, BarChart3, Filter, ChevronsUpDown, AlertCircle, Loader2, Brain, ShieldAlert, Maximize2,
} from 'lucide-react';
import type { EnrichedAlert, AssignedAnalyst } from '../../services/alertsApi';
import { apiAssignAlert } from '../../services/alertsApi';
import { apiGetAllUsers } from '../../services/api';
import type { User as MediUser } from '../../types';
import StatCard from '../../components/StatCard';
import ChartCard from '../../components/charts/ChartCard';
import AlertsTimelineChart from '../../components/charts/AlertsTimelineChart';
import SeverityDonutChart from '../../components/charts/SeverityDonutChart';
import AlertDetailsModal from './AlertDetailsModal';
import { casToSeverity, severityCounts, bucketAlertsByHour, SEVERITY_ORDER, SEVERITY_COLORS } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';
import { LifeCriticalBadge, MitreBadge, isLifeCriticalDevice } from '../../components/AlertBadges';
import SeverityBadge from '../../components/SeverityBadge';

// ─── Department badge ──────────────────────────────────────────────────────────
const DEPARTMENT_DOT: Record<string, string> = {
  ICU: 'bg-red-400',
  Cardiology: 'bg-pink-400',
  Radiology: 'bg-violet-400',
  Emergency: 'bg-orange-400',
  'General Ward': 'bg-cyan-400',
  General: 'bg-slate-500',
};

const DepartmentBadge: React.FC<{ department: string }> = ({ department }) => (
  <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${DEPARTMENT_DOT[department] ?? 'bg-slate-600'}`} />
    <span className="text-xs text-slate-600 dark:text-slate-300">{department}</span>
  </span>
);

// Small score chip used in the expanded row — TR/CC/TS/AE/TC each feed CAS
// (0.25 TR + 0.30 CC + 0.25 TS + 0.10 AE + 0.10 TC), so surfacing them
// individually is what makes an alert's clinical context legible instead of
// just a single opaque number.
const ScoreChip: React.FC<{ label: string; value: number | null | undefined; hint: string }> = ({ label, value, hint }) => (
  <div className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800" title={hint}>
    <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
    <div className="text-sm font-mono text-slate-900 dark:text-white mt-0.5">{typeof value === 'number' ? value.toFixed(1) : '—'}</div>
  </div>
);

type SortBy = 'cas' | 'time';
type DetectionFilter = 'all' | 'ml' | 'rules' | 'combined';

const isMlDetection = (a: EnrichedAlert) => typeof a.confidence === 'number';
const isRuleDetection = (a: EnrichedAlert) => !!a.matchedRules && a.matchedRules.length > 0;
// Mutually exclusive so the three tabs actually partition the alert set —
// "ML Detections" means ML *and nothing else*, "Rule Detections" means a
// custom rule fired *without* an ML score, "Combined" means both fired on
// the same alert. Without this, "ML Detections" and "All" look identical
// any time (as here) virtually every alert carries a real confidence score.
const isMlOnly = (a: EnrichedAlert) => isMlDetection(a) && !isRuleDetection(a);
const isRulesOnly = (a: EnrichedAlert) => isRuleDetection(a) && !isMlDetection(a);
const isCombinedDetection = (a: EnrichedAlert) => isMlDetection(a) && isRuleDetection(a);

// ─── Detection source badges ────────────────────────────────────────────────────
// Capped at one rule badge + an overflow count instead of one pill per
// matched rule — an alert that trips three rules doesn't need three
// same-weight chips fighting for attention in a table cell; the count
// still says "three rules fired", and the full list is one click away in
// the row's own expanded detail (which already lists every matched rule).
const DetectionBadges: React.FC<{ alert: EnrichedAlert }> = ({ alert }) => {
  const ml = isMlDetection(alert);
  const rules = alert.matchedRules ?? [];
  if (!ml && rules.length === 0 && !alert.mitre?.id?.length) {
    return <span className="text-xs text-slate-300 dark:text-slate-700">—</span>;
  }
  return (
    <div className="flex items-center gap-1 flex-wrap">
      {ml && (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-violet-600 dark:text-violet-400 text-[10px] font-semibold whitespace-nowrap" title="Real RF/Isolation Forest/K-Means classification">
          <Brain className="w-2.5 h-2.5" /> ML
        </span>
      )}
      {rules.length > 0 && (
        <span
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-amber-600 dark:text-amber-400 text-[10px] font-semibold whitespace-nowrap"
          title={rules.map((r) => r.name).join(', ')}
        >
          <ShieldAlert className="w-2.5 h-2.5" /> {rules[0].name}{rules.length > 1 && ` +${rules.length - 1}`}
        </span>
      )}
      <MitreBadge mitre={alert.mitre} />
    </div>
  );
};

const AlertsPanel: React.FC<{
  alerts: EnrichedAlert[];
  connected: boolean;
  loading: boolean;
  error: string | null;
  token: string | null;
  canAssign?: boolean;
  // Cumulative counts since the backend process started — unlike `alerts`
  // (capped at MAX_ALERTS for the list/table), these never shrink. Falls
  // back to buffer-derived counts if omitted, so older callers still work.
  totalCount?: number;
  severityTotals?: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
}> = ({ alerts, connected, loading, error, token, canAssign = true, totalCount, severityTotals }) => {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [departmentFilter, setDepartmentFilter] = useState<string>('all');
  const [actionFilter, setActionFilter] = useState<EnrichedAlert['action'] | 'all'>('all');
  const [detectionFilter, setDetectionFilter] = useState<DetectionFilter>('all');
  const [sortBy, setSortBy] = useState<SortBy>('cas');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detailsAlert, setDetailsAlert] = useState<EnrichedAlert | null>(null);

  const [analysts, setAnalysts] = useState<MediUser[]>([]);
  // Overlay on top of the `alerts` prop: apiGetAlerts already returns
  // assignedTo for each alert, but new alerts pushed over Socket.IO don't
  // carry it, and we want an assignment to reflect immediately after the
  // PATCH resolves without waiting on the next poll. Keyed by alert id;
  // `undefined` means "use whatever the alert prop says", not "unassigned".
  const [assignmentOverrides, setAssignmentOverrides] = useState<Record<string, AssignedAnalyst | null>>({});
  const [assigningId, setAssigningId] = useState<string | null>(null);

  // Closed cases have their own dedicated views (My Alerts / Case Status) —
  // this dashboard is the "what's still live" monitoring view, so anything
  // already closed (reason + evidence recorded) is excluded everywhere below:
  // table rows, filters, stat cards, and charts alike.
  const openAlerts = useMemo(() => alerts.filter((a) => !a.closure), [alerts]);

  useEffect(() => {
    // GET /api/users is admin-only — SOC analysts get a read-only assigned
    // badge instead of the picker (see canAssign below), so skip the fetch
    // (and the guaranteed 403) entirely for them.
    if (!token || !canAssign) return;
    apiGetAllUsers(token)
      .then((data) => setAnalysts(data.users.filter((u) => u.role === 'user'))) // SOC analysts only — admins triage, they don't get assigned
      .catch(() => {});
  }, [token, canAssign]);

  const assignedToFor = (a: EnrichedAlert): AssignedAnalyst | null =>
    a.id in assignmentOverrides ? assignmentOverrides[a.id] : (a.assignedTo ?? null);

  const handleAssign = async (alertId: string, analystId: string) => {
    if (!token) return;
    setAssigningId(alertId);
    try {
      const { assignedTo } = await apiAssignAlert(token, alertId, analystId || null);
      setAssignmentOverrides((prev) => ({ ...prev, [alertId]: assignedTo }));
    } catch (err) {
      console.error('Failed to assign alert', err);
    } finally {
      setAssigningId(null);
    }
  };

  const departments = useMemo(
    () => Array.from(new Set(openAlerts.map((a) => a.department))).sort(),
    [openAlerts]
  );

  const filtered = useMemo(() => {
    const list = openAlerts
      .filter((a) => severityFilter === 'all' || casToSeverity(a.CAS) === severityFilter)
      .filter((a) => departmentFilter === 'all' || a.department === departmentFilter)
      .filter((a) => actionFilter === 'all' || a.action === actionFilter)
      .filter((a) => {
        if (detectionFilter === 'all') return true;
        if (detectionFilter === 'ml') return isMlOnly(a);
        if (detectionFilter === 'rules') return isRulesOnly(a);
        return isCombinedDetection(a);
      });
    return sortBy === 'time'
      ? list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      : list.sort((a, b) => b.CAS - a.CAS);
  }, [openAlerts, severityFilter, departmentFilter, actionFilter, detectionFilter, sortBy]);

  const stats = useMemo(() => {
    const critical = severityTotals?.CRITICAL ?? openAlerts.filter((a) => casToSeverity(a.CAS) === 'CRITICAL').length;
    const immediate = openAlerts.filter((a) => a.action === 'Immediate').length;
    const avgCas = openAlerts.length ? openAlerts.reduce((sum, a) => sum + a.CAS, 0) / openAlerts.length : 0;
    return { total: totalCount ?? openAlerts.length, critical, immediate, avgCas };
  }, [openAlerts, totalCount, severityTotals]);

  const detectionCounts = useMemo(
    () => ({
      all: openAlerts.length,
      ml: openAlerts.filter(isMlOnly).length,
      rules: openAlerts.filter(isRulesOnly).length,
      combined: openAlerts.filter(isCombinedDetection).length,
    }),
    [openAlerts]
  );

  const timeline = useMemo(
    () => bucketAlertsByHour(openAlerts, (a) => a.timestamp, (a) => casToSeverity(a.CAS), 24),
    [openAlerts]
  );
  const severityDist = useMemo(() => {
    if (severityTotals) {
      return SEVERITY_ORDER.map((name) => ({ name, value: severityTotals[name], color: SEVERITY_COLORS[name] }));
    }
    return severityCounts(openAlerts, (a) => casToSeverity(a.CAS));
  }, [openAlerts, severityTotals]);

  // Same weight-drops-with-urgency logic as SeverityBadge: Immediate is the
  // one that should stop the eye, Monitor should barely register.
  const actionColor: Record<EnrichedAlert['action'], string> = {
    Immediate: 'bg-red-600 text-white font-bold',
    Investigate: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30 font-semibold',
    Monitor: 'text-emerald-600 dark:text-emerald-500 font-medium',
  };

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Alerts</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real RF / Isolation Forest / K-Means classifications, ranked by Clinical Alert Score
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-500' : 'bg-red-500'}`} />
          {connected ? 'Live' : 'Reconnecting…'}
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<Bell />} label="Total Alerts" value={String(stats.total)} sub={totalCount !== undefined ? 'All-time' : 'In current buffer'} color="slate" />
        <StatCard icon={<AlertTriangle />} label="Critical" value={String(stats.critical)} sub="CAS ≥ 8" color="red" />
        <StatCard icon={<Zap />} label="Immediate Action" value={String(stats.immediate)} sub="Needs response now" color="red" />
        <StatCard icon={<BarChart3 />} label="Average CAS" value={stats.avgCas.toFixed(1)} sub="Across all alerts" color="slate" />
      </div>

      {/* Chart header — makes this a real SIEM alerts page, not just a table */}
      <div className="grid lg:grid-cols-3 gap-4">
        <ChartCard
          title="Alert volume (24h)"
          subtitle="Stacked by severity, current buffer"
          height={200}
          empty={stats.total === 0}
          className="lg:col-span-2"
        >
          <AlertsTimelineChart data={timeline} />
        </ChartCard>
        <ChartCard title="Severity mix" subtitle={totalCount !== undefined ? 'All-time' : 'Current buffer'} height={200} empty={stats.total === 0}>
          <SeverityDonutChart data={severityDist} onSeverityClick={setSeverityFilter} />
        </ChartCard>
      </div>

      {/* Detection source — ML pipeline vs custom rules vs combined */}
      <div className="flex items-center gap-2.5 flex-wrap">
        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl w-fit">
          {([
            { id: 'all', label: 'All', icon: <BarChart3 className="w-3.5 h-3.5" /> },
            { id: 'ml', label: `ML Detections (${detectionCounts.ml})`, icon: <Brain className="w-3.5 h-3.5" /> },
            { id: 'rules', label: `Rule Detections (${detectionCounts.rules})`, icon: <ShieldAlert className="w-3.5 h-3.5" /> },
            {
              id: 'combined',
              label: `Combined (${detectionCounts.combined})`,
              icon: (
                <span className="flex items-center -space-x-1">
                  <Brain className="w-3.5 h-3.5" />
                  <ShieldAlert className="w-3.5 h-3.5" />
                </span>
              ),
            },
          ] as { id: DetectionFilter; label: string; icon: React.ReactNode }[]).map((t) => (
            <button
              key={t.id}
              onClick={() => setDetectionFilter(t.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                detectionFilter === t.id
                  ? 'bg-white dark:bg-slate-800 text-cyan-600 dark:text-cyan-400 shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
        {/* Right next to the toggle, not buried in the filter row below — the
            table's top rows (sorted by CAS) can look identical between "All"
            and a narrower filter when the highest-scoring alerts happen to
            satisfy both, so the count is the only visible proof anything
            changed. */}
        {detectionFilter !== 'all' && (
          <span className="text-xs text-slate-500">{filtered.length} of {openAlerts.length} alerts match</span>
        )}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <span className="flex items-center gap-1.5 text-xs text-slate-500">
          <Filter className="w-3.5 h-3.5" /> Filter
        </span>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All severities</option>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={departmentFilter}
          onChange={(e) => setDepartmentFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All departments</option>
          {departments.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value as EnrichedAlert['action'] | 'all')}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All actions</option>
          <option value="Immediate">Immediate</option>
          <option value="Investigate">Investigate</option>
          <option value="Monitor">Monitor</option>
        </select>

        <span className="flex items-center gap-1.5 text-xs text-slate-500 ml-2">
          <ChevronsUpDown className="w-3.5 h-3.5" /> Sort
        </span>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as SortBy)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="cas">Clinical Alert Score</option>
          <option value="time">Most recent</option>
        </select>

        {(severityFilter !== 'all' || departmentFilter !== 'all' || actionFilter !== 'all' || detectionFilter !== 'all') && (
          <span className="text-xs text-slate-500">{filtered.length} of {openAlerts.length} shown</span>
        )}
      </div>

      <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading alerts…
          </div>
        ) : error && openAlerts.length === 0 ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : filtered.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-14">
            {openAlerts.length === 0 ? 'No open alerts — everything in the current buffer has been closed.' : 'No alerts match the current filters.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-4 text-left">Severity</th>
                  <th className="py-2.5 px-4 text-left">Device</th>
                  <th className="py-2.5 px-4 text-left">Department</th>
                  <th className="py-2.5 px-4 text-left">Event</th>
                  <th className="py-2.5 px-4 text-left">Cluster</th>
                  <th className="py-2.5 px-4 text-left">CAS</th>
                  <th className="py-2.5 px-4 text-left">Action</th>
                  <th className="py-2.5 px-4 text-left">Detection</th>
                  <th className="py-2.5 px-4 text-left">Time</th>
                  {canAssign && <th className="py-2.5 px-4 text-left">Assigned</th>}
                  <th className="py-2.5 px-4 text-left">Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => {
                  const severity = casToSeverity(a.CAS);
                  const isExpanded = expandedId === a.id;
                  const assignedTo = assignedToFor(a);
                  return (
                    <React.Fragment key={a.id}>
                      <tr
                        onClick={() => setExpandedId(isExpanded ? null : a.id)}
                        className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors cursor-pointer"
                      >
                        <td className="py-3 px-4">
                          <SeverityBadge severity={severity} />
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-700 dark:text-slate-300 font-mono">
                          <span className="flex items-center gap-1.5 flex-wrap">
                            {a.agent}
                            {isLifeCriticalDevice(a) && <LifeCriticalBadge />}
                          </span>
                        </td>
                        <td className="py-3 px-4"><DepartmentBadge department={a.department} /></td>
                        <td className="py-3 px-4 text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate">
                          {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-500 capitalize">{a.cluster}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-slate-200 dark:bg-slate-800 rounded-full h-1 w-14">
                              <div
                                className={`h-1 rounded-full ${a.CAS >= 8 ? 'bg-red-500' : a.CAS >= 6 ? 'bg-orange-500' : a.CAS >= 4 ? 'bg-amber-500' : 'bg-blue-500'}`}
                                style={{ width: `${(a.CAS / 10) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono tabular-nums text-slate-500 dark:text-slate-400">{a.CAS.toFixed(1)}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`inline-flex text-[11px] px-1.5 py-0.5 rounded ${actionColor[a.action]}`}>{a.action}</span>
                        </td>
                        <td className="py-3 px-4"><DetectionBadges alert={a} /></td>
                        <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 tabular-nums whitespace-nowrap">{new Date(a.timestamp).toLocaleTimeString()}</td>
                        {canAssign && (
                          <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                            <select
                              value={assignedTo?.id ?? ''}
                              disabled={assigningId === a.id}
                              onChange={(e) => handleAssign(a.id, e.target.value)}
                              className={`px-2 py-1 bg-slate-100 dark:bg-slate-800 border rounded-md text-xs focus:outline-none focus:border-cyan-500/60 disabled:opacity-50 ${
                                assignedTo ? 'border-cyan-500/30 text-cyan-600 dark:text-cyan-400' : 'border-slate-200 dark:border-slate-700 text-slate-500'
                              }`}
                            >
                              <option value="">Unassigned</option>
                              {analysts.map((u) => (
                                <option key={u.id} value={u.id}>{u.name}</option>
                              ))}
                            </select>
                          </td>
                        )}
                        <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setDetailsAlert(a)}
                            className="flex items-center gap-1 text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors"
                          >
                            <Maximize2 className="w-3 h-3" /> Details
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50 dark:bg-slate-950/50 border-b border-slate-100 dark:border-slate-800/60">
                          <td colSpan={canAssign ? 11 : 10} className="px-4 py-4">
                            <div className="grid sm:grid-cols-5 gap-2 mb-3">
                              <ScoreChip label="TR" value={a.TR_score} hint="Threat Risk — RF classification confidence" />
                              <ScoreChip label="CC" value={a.CC_score} hint="Clinical Criticality — how life-critical this device is" />
                              <ScoreChip label="TS" value={a.TS_score} hint="Time Sensitivity — Isolation Forest anomaly + time of day" />
                              <ScoreChip label="AE" value={a.AE_score} hint="Active Exploitation — known-exploited CVE match" />
                              <ScoreChip label="TC" value={a.TC_score} hint="Temporal Context — shift-based rule" />
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400">
                              <span className="text-slate-400 dark:text-slate-500">Confidence: </span>
                              {typeof a.confidence === 'number' ? `${(a.confidence * 100).toFixed(1)}%` : 'n/a (rule.level fallback, not a real ML classification)'}
                            </p>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                              <span className="text-slate-400 dark:text-slate-500">Explanation: </span>{a.explanation}
                            </p>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                              <span className="text-slate-400 dark:text-slate-500">Matched rules: </span>
                              {a.matchedRules && a.matchedRules.length > 0 ? a.matchedRules.map((r) => r.name).join(', ') : 'None'}
                            </p>
                            {a.ruleLevel !== null && (
                              <p className="text-xs text-slate-500 mt-1">Wazuh rule.level: {a.ruleLevel}</p>
                            )}
                            {a.deviceType && (
                              <p className="text-xs text-slate-500 mt-1">
                                Device type: {a.deviceType}
                                {a.deviceCriticality && ` · inventory criticality: ${a.deviceCriticality}`}
                              </p>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {detailsAlert && <AlertDetailsModal kind="ml" alert={detailsAlert} onClose={() => setDetailsAlert(null)} />}
    </div>
  );
};

export default AlertsPanel;
