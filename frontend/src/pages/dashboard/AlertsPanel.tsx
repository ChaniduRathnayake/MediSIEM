// Full-fledged SIEM alerts view — CAS-ranked live feed, charts, filters, assignment.
// Shared by the Admin console and SOC Analyst dashboard.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bell, AlertTriangle, Zap, BarChart3, Filter, ChevronsUpDown, ChevronUp, ChevronDown, AlertCircle, Loader2, Brain, ShieldAlert, Maximize2,
  Search, CheckSquare, Square, Users, X, Keyboard, Hand, BellOff, Eye, EyeOff, Clock3, Rows3, Rows4, Wand2,
} from 'lucide-react';
import type { EnrichedAlert, AssignedAnalyst, AlertSnoozeInfo } from '../../services/alertsApi';
import { apiAssignAlert, apiSnoozeAlert, apiParseAlertQuery } from '../../services/alertsApi';
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
import SavedViewsBar from '../../components/SavedViewsBar';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';

const DEPARTMENT_DOT: Record<string, string> = {
  ICU: 'bg-red-400',
  Cardiology: 'bg-pink-400',
  Radiology: 'bg-violet-400',
  Emergency: 'bg-orange-400',
  'General Ward': 'bg-cyan-400',
  General: 'bg-slate-500',
};

export const DepartmentBadge: React.FC<{ department: string }> = ({ department }) => (
  <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${DEPARTMENT_DOT[department] ?? 'bg-slate-600'}`} />
    <span className="text-xs text-slate-600 dark:text-slate-300">{department}</span>
  </span>
);

// TR/CC/TS/AE/TC each feed CAS — surfacing them individually makes the clinical context legible.
const ScoreChip: React.FC<{ label: string; value: number | null | undefined; hint: string }> = ({ label, value, hint }) => (
  <div className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800" title={hint}>
    <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
    <div className="text-sm font-mono text-slate-900 dark:text-white mt-0.5">{typeof value === 'number' ? value.toFixed(1) : '—'}</div>
  </div>
);

const SNOOZE_PRESETS: { label: string; minutes: number }[] = [
  { label: '15 minutes', minutes: 15 },
  { label: '1 hour', minutes: 60 },
  { label: '4 hours', minutes: 240 },
  { label: 'Until tomorrow', minutes: 24 * 60 },
];

const BulkSnoozeControl: React.FC<{ count: number; busy: boolean; open: boolean; onToggle: () => void; onPick: (minutes: number) => void }> = ({
  count, busy, open, onToggle, onPick,
}) => (
  <div className="relative">
    <button
      onClick={onToggle}
      disabled={busy || count === 0}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
    >
      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Clock3 className="w-3.5 h-3.5" />}
      Snooze
    </button>
    {open && (
      <div className="absolute left-0 top-full mt-1 z-20 w-40 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-xl overflow-hidden">
        {SNOOZE_PRESETS.map((p) => (
          <button
            key={p.minutes}
            onClick={() => onPick(p.minutes)}
            className="w-full text-left px-3 py-2 text-xs text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            {p.label}
          </button>
        ))}
      </div>
    )}
  </div>
);

type SortBy = 'cas' | 'time';
type DetectionFilter = 'all' | 'ml' | 'rules' | 'combined';
// Every column with a genuine single sortable value — Detection (multi-badge) and
// Details (pure action column, no data) are left unsortable.
type SortColumn = 'severity' | 'agent' | 'department' | 'label' | 'cluster' | 'CAS' | 'CVSS' | 'action' | 'timestamp' | 'assigned';
const ACTION_RANK: Record<EnrichedAlert['action'], number> = { Immediate: 3, Investigate: 2, Monitor: 1 };
// String columns default to A→Z on first click; numeric/date columns default to
// highest/most-recent first, since that's what an analyst almost always wants first.
const SORT_ASC_FIRST: SortColumn[] = ['agent', 'department', 'label', 'cluster', 'assigned'];

interface AlertsPanelFilters {
  severityFilter: Severity | 'all';
  departmentFilter: string;
  actionFilter: EnrichedAlert['action'] | 'all';
  detectionFilter: DetectionFilter;
  sortBy: SortBy;
  search: string;
}

const isMlDetection = (a: EnrichedAlert) => typeof a.confidence === 'number';
const isRuleDetection = (a: EnrichedAlert) => !!a.matchedRules && a.matchedRules.length > 0;
// Mutually exclusive so the three tabs actually partition the alert set.
const isMlOnly = (a: EnrichedAlert) => isMlDetection(a) && !isRuleDetection(a);
const isRulesOnly = (a: EnrichedAlert) => isRuleDetection(a) && !isMlDetection(a);
const isCombinedDetection = (a: EnrichedAlert) => isMlDetection(a) && isRuleDetection(a);

// Capped at one rule badge + an overflow count — the full list is one click away in the row's expanded detail.
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
  // Enables "Claim" (self-assign) — omitted by admin call sites, since alerts can only be assigned to role 'user'.
  currentUserId?: string;
  // Cumulative since the backend started, unlike `alerts` (capped) — never shrinks.
  totalCount?: number;
  severityTotals?: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
}> = ({ alerts, connected, loading, error, token, canAssign = true, currentUserId, totalCount, severityTotals }) => {
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [departmentFilter, setDepartmentFilter] = useState<string>('all');
  const [actionFilter, setActionFilter] = useState<EnrichedAlert['action'] | 'all'>('all');
  const [detectionFilter, setDetectionFilter] = useState<DetectionFilter>('all');
  const [sortColumn, setSortColumn] = useState<SortColumn>('CAS');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  // Derived, not stateful — 'sortBy' only exists so saved views / the AI natural-language
  // search (ParsedAlertQuery) can still express "roughly CAS-sorted" or "roughly
  // time-sorted" without knowing about every clickable column.
  const sortBy: SortBy = sortColumn === 'timestamp' ? 'time' : 'cas';
  // Separate from `sortBy` above: the "Sort by" dropdown must never claim "Clinical
  // Alert Score" is active while a column header (e.g. Department) is actually driving
  // the order — sortBy's cas/time collapse would otherwise silently mislabel every
  // other column as "cas".
  const sortSelectValue = sortColumn === 'timestamp' ? 'time' : sortColumn === 'CAS' ? 'cas' : 'other';
  const toggleSort = (column: SortColumn) => {
    if (sortColumn === column) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortColumn(column);
      setSortDir(SORT_ASC_FIRST.includes(column) ? 'asc' : 'desc');
    }
  };
  const sortIndicator = (column: SortColumn) =>
    sortColumn === column
      ? sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
      : <ChevronsUpDown className="w-3 h-3 opacity-30" />;
  // Single definition of the sortable-<th> markup — used for all 9 sortable columns
  // (the 7 always-shown ones plus Detected/Assigned) so a future tweak (aria-sort,
  // hover styling, the icon) only has to change in one place.
  const sortableTh = (column: SortColumn, label: string) => (
    <th key={column} className="py-2.5 px-4 text-left" aria-sort={sortColumn === column ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => toggleSort(column)}
        className={`flex items-center gap-1 hover:text-slate-900 dark:hover:text-white transition-colors ${sortColumn === column ? 'text-slate-900 dark:text-white' : ''}`}
      >
        {label} {sortIndicator(column)}
      </button>
    </th>
  );
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [detailsAlert, setDetailsAlert] = useState<EnrichedAlert | null>(null);

  const [focusedIndex, setFocusedIndex] = useState<number>(-1);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkAssignId, setBulkAssignId] = useState('');
  const [bulkAssigning, setBulkAssigning] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [showAiSearch, setShowAiSearch] = useState(false);
  const [aiQuery, setAiQuery] = useState('');
  const [aiSearching, setAiSearching] = useState(false);
  const [aiSearchError, setAiSearchError] = useState('');

  const [analysts, setAnalysts] = useState<MediUser[]>([]);
  // Overlay on the `alerts` prop so a just-applied assign reflects immediately, not just after the next poll.
  const [assignmentOverrides, setAssignmentOverrides] = useState<Record<string, AssignedAnalyst | null>>({});
  const [assigningId, setAssigningId] = useState<string | null>(null);
  const [claimingId, setClaimingId] = useState<string | null>(null);
  const [bulkClaiming, setBulkClaiming] = useState(false);

  const [snoozeOverrides, setSnoozeOverrides] = useState<Record<string, AlertSnoozeInfo | null>>({});
  const [snoozingId, setSnoozingId] = useState<string | null>(null);
  const [bulkSnoozing, setBulkSnoozing] = useState(false);
  const [snoozeFormId, setSnoozeFormId] = useState<string | null>(null);
  const [showBulkSnoozeMenu, setShowBulkSnoozeMenu] = useState(false);
  const [showSnoozed, setShowSnoozed] = useState(false);

  const [compact, setCompact] = useState(() => {
    try { return localStorage.getItem('medisiem_alerts_density') === 'compact'; } catch { return false; }
  });
  useEffect(() => {
    try { localStorage.setItem('medisiem_alerts_density', compact ? 'compact' : 'comfortable'); } catch { /* ignore */ }
  }, [compact]);

  const snoozedFor = (a: EnrichedAlert): AlertSnoozeInfo | null =>
    a.id in snoozeOverrides ? snoozeOverrides[a.id] : (a.snoozed ?? null);
  const isActivelySnoozed = (a: EnrichedAlert) => {
    const s = snoozedFor(a);
    return !!s && new Date(s.snoozedUntil).getTime() > Date.now();
  };

  // This dashboard is the "what's still live" view — closed and (by default) snoozed cases are excluded.
  const openAlerts = useMemo(
    () => alerts.filter((a) => !a.closure && (showSnoozed || !isActivelySnoozed(a))),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, showSnoozed, snoozeOverrides]
  );
  const snoozedCount = useMemo(() => alerts.filter((a) => !a.closure && isActivelySnoozed(a)).length, [alerts, snoozeOverrides]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    // GET /api/users is admin-only — skip the fetch entirely for SOC analysts.
    if (!token || !canAssign) return;
    apiGetAllUsers(token)
      .then((data) => setAnalysts(data.users.filter((u) => u.role === 'user')))
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

  const handleClaim = async (alertId: string) => {
    if (!token || !currentUserId) return;
    setClaimingId(alertId);
    try {
      const { assignedTo } = await apiAssignAlert(token, alertId, currentUserId);
      setAssignmentOverrides((prev) => ({ ...prev, [alertId]: assignedTo }));
    } catch (err) {
      console.error('Failed to claim alert', err);
    } finally {
      setClaimingId(null);
    }
  };

  // Claims the highest-priority unassigned, unsnoozed alert in the current sort/filter.
  const handleClaimNext = () => {
    const next = filtered.find((a) => !assignedToFor(a) && !isActivelySnoozed(a));
    if (next) handleClaim(next.id);
  };

  const handleSnooze = async (alertId: string, minutes: number | null, reason?: string) => {
    if (!token) return;
    setSnoozingId(alertId);
    try {
      const { snoozed } = await apiSnoozeAlert(token, alertId, minutes, reason);
      setSnoozeOverrides((prev) => ({ ...prev, [alertId]: snoozed }));
      setSnoozeFormId(null);
    } catch (err) {
      console.error('Failed to snooze alert', err);
    } finally {
      setSnoozingId(null);
    }
  };

  const handleBulkClaim = async () => {
    if (!token || !currentUserId || selectedIds.size === 0) return;
    setBulkClaiming(true);
    try {
      const targets = [...selectedIds].filter((id) => {
        const a = filtered.find((x) => x.id === id);
        return a && !assignedToFor(a);
      });
      const results = await Promise.all(
        targets.map((id) => apiAssignAlert(token, id, currentUserId).then((r) => [id, r.assignedTo] as const))
      );
      setAssignmentOverrides((prev) => {
        const next = { ...prev };
        for (const [id, assignedTo] of results) next[id] = assignedTo;
        return next;
      });
      setSelectedIds(new Set());
    } catch (err) {
      console.error('Bulk claim failed', err);
    } finally {
      setBulkClaiming(false);
    }
  };

  const handleBulkSnooze = async (minutes: number) => {
    if (!token || selectedIds.size === 0) return;
    setBulkSnoozing(true);
    setShowBulkSnoozeMenu(false);
    try {
      const ids = [...selectedIds];
      const results = await Promise.all(
        ids.map((id) => apiSnoozeAlert(token, id, minutes).then((r) => [id, r.snoozed] as const))
      );
      setSnoozeOverrides((prev) => {
        const next = { ...prev };
        for (const [id, snoozed] of results) next[id] = snoozed;
        return next;
      });
      setSelectedIds(new Set());
    } catch (err) {
      console.error('Bulk snooze failed', err);
    } finally {
      setBulkSnoozing(false);
    }
  };

  const departments = useMemo(
    () => Array.from(new Set(openAlerts.map((a) => a.department))).sort(),
    [openAlerts]
  );

  const searchLower = search.trim().toLowerCase();
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
      })
      .filter((a) => {
        if (!searchLower) return true;
        const haystack = `${a.agent} ${a.label} ${a.ruleDescription} ${a.department} ${a.deviceType ?? ''}`.toLowerCase();
        return haystack.includes(searchLower);
      });
    const sortValue = (a: EnrichedAlert): number | string => {
      switch (sortColumn) {
        case 'severity':
        case 'CAS': return a.CAS;
        case 'CVSS': return a.CVSS ?? -1;
        case 'timestamp': return new Date(a.timestamp).getTime();
        case 'action': return ACTION_RANK[a.action] ?? 0;
        case 'agent': return a.agent.toLowerCase();
        case 'department': return a.department.toLowerCase();
        case 'label': return (a.label !== 'Unclassified' ? a.label : a.ruleDescription).toLowerCase();
        case 'cluster': return a.cluster.toLowerCase();
        case 'assigned': return (assignedToFor(a)?.name ?? '').toLowerCase();
        default: return 0;
      }
    };
    list.sort((a, b) => {
      const va = sortValue(a);
      const vb = sortValue(b);
      const cmp = typeof va === 'number' && typeof vb === 'number' ? va - vb : String(va).localeCompare(String(vb));
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
    // assignmentOverrides: sortValue()'s 'assigned' case reads it via assignedToFor() —
    // without it here, sorting by Assigned goes stale the moment a claim/assign happens,
    // since neither touches any of the other dependencies below.
  }, [openAlerts, severityFilter, departmentFilter, actionFilter, detectionFilter, sortColumn, sortDir, searchLower, assignmentOverrides]);

  // Clamp focusedIndex once filters/search narrow the list, rather than let it dangle.
  useEffect(() => {
    if (focusedIndex >= filtered.length) setFocusedIndex(filtered.length > 0 ? filtered.length - 1 : -1);
  }, [filtered.length, focusedIndex]);

  const currentFilters: AlertsPanelFilters = { severityFilter, departmentFilter, actionFilter, detectionFilter, sortBy, search };
  const applyFilters = (f: AlertsPanelFilters) => {
    setSeverityFilter(f.severityFilter);
    setDepartmentFilter(f.departmentFilter);
    setActionFilter(f.actionFilter);
    setDetectionFilter(f.detectionFilter);
    setSortColumn(f.sortBy === 'time' ? 'timestamp' : 'CAS');
    setSortDir('desc');
    setSearch(f.search);
  };

  const handleAiSearch = async () => {
    if (!token || !aiQuery.trim()) return;
    setAiSearching(true);
    setAiSearchError('');
    try {
      const { filters } = await apiParseAlertQuery(token, aiQuery.trim(), departments);
      applyFilters(filters);
      setShowAiSearch(false);
      setAiQuery('');
    } catch (err: unknown) {
      setAiSearchError(err instanceof Error ? err.message : 'AI assistant request failed.');
    } finally {
      setAiSearching(false);
    }
  };

  const toggleSelected = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  useKeyboardShortcuts({
    j: () => setFocusedIndex((i) => Math.min(filtered.length - 1, i + 1)),
    k: () => setFocusedIndex((i) => Math.max(0, i === -1 ? 0 : i - 1)),
    Enter: () => { if (focusedIndex >= 0 && filtered[focusedIndex]) setDetailsAlert(filtered[focusedIndex]); },
    x: () => { if (focusedIndex >= 0 && filtered[focusedIndex]) toggleSelected(filtered[focusedIndex].id); },
    '/': () => searchInputRef.current?.focus(),
    Escape: () => { setFocusedIndex(-1); setSelectedIds(new Set()); searchInputRef.current?.blur(); },
  });

  const handleBulkAssign = async () => {
    if (!token || !bulkAssignId || selectedIds.size === 0) return;
    setBulkAssigning(true);
    try {
      const results = await Promise.all(
        [...selectedIds].map((id) => apiAssignAlert(token, id, bulkAssignId).then((r) => [id, r.assignedTo] as const))
      );
      setAssignmentOverrides((prev) => {
        const next = { ...prev };
        for (const [id, assignedTo] of results) next[id] = assignedTo;
        return next;
      });
      setSelectedIds(new Set());
      setBulkAssignId('');
    } catch (err) {
      console.error('Bulk assign failed', err);
    } finally {
      setBulkAssigning(false);
    }
  };

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
        {detectionFilter !== 'all' && (
          <span className="text-xs text-slate-500">{filtered.length} of {openAlerts.length} alerts match</span>
        )}
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
          <input
            ref={searchInputRef}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search device, event, department… ( / )"
            className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-56"
          />
        </div>
        {token && (
          showAiSearch ? (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-1.5">
                <input
                  autoFocus
                  value={aiQuery}
                  onChange={(e) => setAiQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleAiSearch(); if (e.key === 'Escape') setShowAiSearch(false); }}
                  placeholder="e.g. critical alerts in ICU from the last shift"
                  className="pl-3 pr-3 py-1.5 bg-violet-500/5 border border-violet-500/30 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-violet-500/60 w-64"
                />
                <button
                  onClick={handleAiSearch}
                  disabled={aiSearching || !aiQuery.trim()}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-violet-500 hover:bg-violet-400 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
                >
                  {aiSearching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wand2 className="w-3.5 h-3.5" />}
                </button>
                <button onClick={() => { setShowAiSearch(false); setAiSearchError(''); }} className="p-1.5 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
              {aiSearchError && <p className="text-[11px] text-red-500 dark:text-red-400">{aiSearchError}</p>}
            </div>
          ) : (
            <button
              onClick={() => setShowAiSearch(true)}
              title="Search in plain English, powered by the AI assistant"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-violet-500/30 bg-violet-500/5 text-violet-600 dark:text-violet-400 hover:bg-violet-500/15 transition-colors"
            >
              <Wand2 className="w-3.5 h-3.5" /> Ask in plain English
            </button>
          )
        )}
        {!canAssign && currentUserId && (
          <button
            onClick={handleClaimNext}
            disabled={!filtered.some((a) => !assignedToFor(a) && !isActivelySnoozed(a))}
            title="Self-assign the top alert in the current sort/filter"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 disabled:cursor-not-allowed text-slate-950 transition-colors"
          >
            <Hand className="w-3.5 h-3.5" /> Claim next
          </button>
        )}
        {snoozedCount > 0 && (
          <button
            onClick={() => setShowSnoozed((v) => !v)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              showSnoozed
                ? 'bg-violet-500/10 border-violet-500/30 text-violet-600 dark:text-violet-400'
                : 'bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            {showSnoozed ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
            {showSnoozed ? 'Hide' : 'Show'} snoozed ({snoozedCount})
          </button>
        )}
        <SavedViewsBar storageKey="medisiem_alerts_panel_views" currentFilters={currentFilters} onApply={applyFilters} />
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
          value={sortSelectValue}
          onChange={(e) => {
            const v = e.target.value as SortBy;
            setSortColumn(v === 'time' ? 'timestamp' : 'CAS');
            setSortDir('desc');
          }}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="cas">Clinical Alert Score</option>
          <option value="time">Most recent</option>
          {sortSelectValue === 'other' && <option value="other" disabled>Custom (click a column header)</option>}
        </select>

        {(severityFilter !== 'all' || departmentFilter !== 'all' || actionFilter !== 'all' || detectionFilter !== 'all' || searchLower) && (
          <span className="text-xs text-slate-500">{filtered.length} of {openAlerts.length} shown</span>
        )}
        <button
          onClick={() => setCompact((v) => !v)}
          title={compact ? 'Switch to comfortable row spacing' : 'Switch to compact row spacing — more rows on screen'}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors ml-2"
        >
          {compact ? <Rows4 className="w-3.5 h-3.5" /> : <Rows3 className="w-3.5 h-3.5" />}
          {compact ? 'Compact' : 'Comfortable'}
        </button>
        <span
          className="flex items-center gap-1 text-xs text-slate-400 dark:text-slate-600 ml-auto"
          title="j/k — move focus · Enter — open details · x — select · / — search · Esc — clear"
        >
          <Keyboard className="w-3.5 h-3.5" /> Shortcuts
        </span>
      </div>

      {selectedIds.size > 0 && canAssign && (
        <div className="flex items-center gap-2.5 px-3.5 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex-wrap">
          <span className="text-xs font-medium text-cyan-700 dark:text-cyan-300 flex items-center gap-1.5">
            <CheckSquare className="w-3.5 h-3.5" /> {selectedIds.size} selected
          </span>
          <select
            value={bulkAssignId}
            onChange={(e) => setBulkAssignId(e.target.value)}
            className="px-2.5 py-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
          >
            <option value="">Assign to…</option>
            {analysts.map((u) => (
              <option key={u.id} value={u.id}>{u.name}</option>
            ))}
          </select>
          <button
            onClick={handleBulkAssign}
            disabled={!bulkAssignId || bulkAssigning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 transition-colors"
          >
            {bulkAssigning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Users className="w-3.5 h-3.5" />}
            Assign
          </button>
          <BulkSnoozeControl
            count={selectedIds.size}
            busy={bulkSnoozing}
            open={showBulkSnoozeMenu}
            onToggle={() => setShowBulkSnoozeMenu((v) => !v)}
            onPick={handleBulkSnooze}
          />
          <button
            onClick={() => setSelectedIds(new Set())}
            className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            <X className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      )}

      {selectedIds.size > 0 && !canAssign && (
        <div className="flex items-center gap-2.5 px-3.5 py-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex-wrap">
          <span className="text-xs font-medium text-cyan-700 dark:text-cyan-300 flex items-center gap-1.5">
            <CheckSquare className="w-3.5 h-3.5" /> {selectedIds.size} selected
          </span>
          {currentUserId && (
            <button
              onClick={handleBulkClaim}
              disabled={bulkClaiming}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 transition-colors"
            >
              {bulkClaiming ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Hand className="w-3.5 h-3.5" />}
              Claim unassigned
            </button>
          )}
          <BulkSnoozeControl
            count={selectedIds.size}
            busy={bulkSnoozing}
            open={showBulkSnoozeMenu}
            onToggle={() => setShowBulkSnoozeMenu((v) => !v)}
            onPick={handleBulkSnooze}
          />
          <button
            onClick={() => setSelectedIds(new Set())}
            className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            <X className="w-3.5 h-3.5" /> Clear
          </button>
        </div>
      )}

      <div className={`rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden ${compact ? 'density-compact' : ''}`}>
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
                  <th className="py-2.5 px-4 text-left w-8">
                    <button
                      onClick={() =>
                        setSelectedIds((prev) => (prev.size === filtered.length ? new Set() : new Set(filtered.map((a) => a.id))))
                      }
                      title={selectedIds.size === filtered.length ? 'Deselect all' : 'Select all'}
                      className="text-slate-400 dark:text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                      {filtered.length > 0 && selectedIds.size === filtered.length ? <CheckSquare className="w-3.5 h-3.5" /> : <Square className="w-3.5 h-3.5" />}
                    </button>
                  </th>
                  {(
                    [
                      ['severity', 'Severity'],
                      ['agent', 'Device'],
                      ['department', 'Department'],
                      ['label', 'Event'],
                      ['cluster', 'Cluster'],
                      ['CAS', 'CAS'],
                      ['CVSS', 'CVSS'],
                      ['action', 'Action'],
                    ] as [SortColumn, string][]
                  ).map(([col, label]) => sortableTh(col, label))}
                  <th className="py-2.5 px-4 text-left">Detection</th>
                  {sortableTh('timestamp', 'Detected')}
                  {canAssign && sortableTh('assigned', 'Assigned')}
                  <th className="py-2.5 px-4 text-left">Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, rowIndex) => {
                  const severity = casToSeverity(a.CAS);
                  const isExpanded = expandedId === a.id;
                  const assignedTo = assignedToFor(a);
                  const isFocused = rowIndex === focusedIndex;
                  const isSelected = selectedIds.has(a.id);
                  return (
                    <React.Fragment key={a.id}>
                      <tr
                        onClick={() => { setExpandedId(isExpanded ? null : a.id); setFocusedIndex(rowIndex); }}
                        className={`border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors cursor-pointer ${
                          isFocused ? 'bg-cyan-500/5 ring-1 ring-inset ring-cyan-500/30' : ''
                        }`}
                      >
                        <td className="py-3 px-4" onClick={(e) => e.stopPropagation()}>
                          <button onClick={() => toggleSelected(a.id)} className="text-slate-400 dark:text-slate-500 hover:text-cyan-500 transition-colors" aria-label={isSelected ? 'Deselect row' : 'Select row'}>
                            {isSelected ? <CheckSquare className="w-3.5 h-3.5 text-cyan-500" /> : <Square className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                        <td className="py-3 px-4">
                          <span className="flex items-center gap-1.5 flex-wrap">
                            <SeverityBadge severity={severity} />
                            {isActivelySnoozed(a) && (
                              <span
                                title={`Snoozed until ${new Date(snoozedFor(a)!.snoozedUntil).toLocaleString()}${snoozedFor(a)!.reason ? ` — ${snoozedFor(a)!.reason}` : ''}`}
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-600 dark:text-violet-400 border border-violet-500/30 text-[10px] font-semibold"
                              >
                                <BellOff className="w-2.5 h-2.5" /> Snoozed
                              </span>
                            )}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-700 dark:text-slate-300 font-mono">
                          <span className="flex items-center gap-1.5 flex-wrap">
                            {a.agent}
                            {isLifeCriticalDevice(a) && <LifeCriticalBadge />}
                          </span>
                        </td>
                        <td className="py-3 px-4"><DepartmentBadge department={a.department} /></td>
                        <td className="py-3 px-4 text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate">
                          <span className="inline-flex items-center gap-1.5">
                            {a.label !== 'Unclassified' ? a.label : a.ruleDescription}
                            {(a.duplicateCount ?? 1) > 1 && (
                              <span
                                title={`Repeated ${a.duplicateCount}× within a short window — collapsed into one row`}
                                className="flex-shrink-0 text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
                              >
                                ×{a.duplicateCount}
                              </span>
                            )}
                          </span>
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
                        <td className="py-3 px-4" title="CVSS-equivalent baseline — clinically blind by design: depends only on attack type, never device or time. Shown for comparison against CAS.">
                          {typeof a.CVSS === 'number' ? (
                            <div className="flex items-center gap-2">
                              <div className="flex-1 bg-slate-200 dark:bg-slate-800 rounded-full h-1 w-14">
                                <div className="h-1 rounded-full bg-slate-400 dark:bg-slate-600" style={{ width: `${(a.CVSS / 10) * 100}%` }} />
                              </div>
                              <span className="text-xs font-mono tabular-nums text-slate-400 dark:text-slate-500">{a.CVSS.toFixed(1)}</span>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-300 dark:text-slate-700">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`inline-flex text-[11px] px-1.5 py-0.5 rounded ${actionColor[a.action]}`}>{a.action}</span>
                        </td>
                        <td className="py-3 px-4"><DetectionBadges alert={a} /></td>
                        <td className="py-3 px-4 text-xs text-slate-400 dark:text-slate-500 tabular-nums whitespace-nowrap">
                          {new Date(a.timestamp).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: true })}
                        </td>
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
                          <div className="flex items-center gap-3">
                            <button
                              onClick={() => setDetailsAlert(a)}
                              className="flex items-center gap-1 text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors"
                            >
                              <Maximize2 className="w-3 h-3" /> Details
                            </button>
                            {!canAssign && currentUserId && !assignedTo && (
                              <button
                                onClick={() => handleClaim(a.id)}
                                disabled={claimingId === a.id}
                                className="flex items-center gap-1 text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:text-emerald-700 dark:hover:text-emerald-300 disabled:opacity-50 transition-colors"
                              >
                                {claimingId === a.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Hand className="w-3 h-3" />} Claim
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-50 dark:bg-slate-950/50 border-b border-slate-100 dark:border-slate-800/60">
                          <td colSpan={canAssign ? 12 : 11} className="px-4 py-4">
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

                            <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800">
                              {isActivelySnoozed(a) ? (
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-xs text-violet-600 dark:text-violet-400 flex items-center gap-1.5">
                                    <BellOff className="w-3.5 h-3.5" />
                                    Snoozed until {new Date(snoozedFor(a)!.snoozedUntil).toLocaleString()}
                                    {snoozedFor(a)!.reason && ` — ${snoozedFor(a)!.reason}`}
                                  </span>
                                  <button
                                    onClick={() => handleSnooze(a.id, null)}
                                    disabled={snoozingId === a.id}
                                    className="text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:underline disabled:opacity-50"
                                  >
                                    {snoozingId === a.id ? 'Working…' : 'Unsnooze'}
                                  </button>
                                </div>
                              ) : snoozeFormId === a.id ? (
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  {SNOOZE_PRESETS.map((p) => (
                                    <button
                                      key={p.minutes}
                                      onClick={() => handleSnooze(a.id, p.minutes)}
                                      disabled={snoozingId === a.id}
                                      className="px-2.5 py-1 rounded-full text-[11px] font-medium border border-violet-500/30 bg-violet-500/5 text-violet-700 dark:text-violet-400 hover:bg-violet-500/15 disabled:opacity-50 transition-colors"
                                    >
                                      {p.label}
                                    </button>
                                  ))}
                                  <button onClick={() => setSnoozeFormId(null)} className="text-xs text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">
                                    Cancel
                                  </button>
                                </div>
                              ) : (
                                <button
                                  onClick={() => setSnoozeFormId(a.id)}
                                  className="flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-violet-600 dark:hover:text-violet-400 transition-colors"
                                >
                                  <Clock3 className="w-3.5 h-3.5" /> Snooze this case
                                </button>
                              )}
                            </div>
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
      {detailsAlert && <AlertDetailsModal kind="ml" alert={detailsAlert} onClose={() => setDetailsAlert(null)} token={token} allAlerts={alerts} />}
    </div>
  );
};

export default AlertsPanel;
