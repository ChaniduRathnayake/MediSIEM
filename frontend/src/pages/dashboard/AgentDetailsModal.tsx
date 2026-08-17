// Comprehensive per-agent details — everything the Wazuh API exposes about one
// agent: core metadata, syscollector inventory (hardware/OS/network/software/
// processes/ports), and security state (vulnerabilities/SCA/FIM).
import React, { useEffect, useState } from 'react';
import {
  X, Loader2, AlertCircle, Info, Server, Cpu, Network, Package,
  Activity, ShieldAlert, ClipboardCheck, FileSearch,
} from 'lucide-react';
import {
  WazuhAgent, WazuhAgentDetails, WazuhConfig, AgentDetailsSection,
  normalizeAgentStatus, formatOs, getAgentDetails, getAgentDetailsSection,
} from './wazuhApi';
import type { WazuhVulnerability, WazuhListSection } from './wazuhApi';
import { hasIndexerConfig, getFimHistory } from './complianceApi';
import type { FimEvent } from './complianceApi';

type SectionKey = 'overview' | 'hardware' | 'network' | 'software' | 'processes' | 'vulnerabilities' | 'sca' | 'fim';

// Last line of defense: this modal renders whatever shape the live Wazuh API
// happens to return, which varies by OS/version in ways no static type can fully
// pin down. If a section still hits something unrenderable, fail that section
// only — never take the whole dashboard down to a white screen.
class SectionErrorBoundary extends React.Component<
  { resetKey: string; children: React.ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-start gap-2 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span>Couldn't render this section — the data returned an unexpected shape. ({this.state.error.message})</span>
        </div>
      );
    }
    return this.props.children;
  }
}

const statusMeta: Record<ReturnType<typeof normalizeAgentStatus>, { dot: string; label: string; online: boolean }> = {
  active:          { dot: 'bg-emerald-400', label: 'Active',          online: true },
  disconnected:    { dot: 'bg-red-400',     label: 'Disconnected',    online: false },
  never_connected: { dot: 'bg-slate-600',   label: 'Never Connected', online: false },
  pending:         { dot: 'bg-amber-400',   label: 'Pending',         online: false },
};

const formatKB = (kb?: number): string => {
  if (kb === undefined || kb === null) return '—';
  if (kb >= 1024 * 1024) return `${(kb / (1024 * 1024)).toFixed(1)} GB`;
  if (kb >= 1024) return `${(kb / 1024).toFixed(1)} MB`;
  return `${kb} KB`;
};

const formatDate = (v?: string): string => {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString();
};

// Real Wazuh responses vary by OS/version in ways our types can't fully pin down
// (e.g. Windows FIM entries return `perm` as a nested ACL object instead of a
// string). Rendering an object directly as a React child crashes to a white
// screen, so every raw field goes through this before hitting JSX.
function safe(v: unknown): React.ReactNode {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'string' || typeof v === 'number') return v;
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) return v.length === 0 ? '—' : v.map(safe).join(', ');
  if (typeof v === 'object') {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}

// ─── Small building blocks ───────────────────────────────────────────────────────
const SectionUnavailable: React.FC<{ message?: string }> = ({ message }) => (
  <div className="flex items-start gap-2 p-4 rounded-lg bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-slate-400 dark:text-slate-500 text-xs">
    <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
    <span>{message || 'Not available — this module may not be enabled on the manager, or no data has been collected yet for this agent.'}</span>
  </div>
);

const SimpleTable: React.FC<{
  columns: string[];
  rows: React.ReactNode[][];
  empty?: string;
  shownCount?: number;
  totalCount?: number;
  onLoadMore?: () => void;
  loadingMore?: boolean;
}> = ({ columns, rows, empty = 'No data', shownCount, totalCount, onLoadMore, loadingMore }) => (
  <div>
    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-800/40">
            {columns.map((c) => (
              <th key={c} className="py-2 px-3 text-left font-medium text-slate-400 dark:text-slate-500 whitespace-nowrap">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length} className="py-8 text-center text-slate-400 dark:text-slate-500">{empty}</td></tr>
          ) : rows.map((r, i) => (
            <tr key={i} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
              {r.map((cell, j) => <td key={j} className="py-2 px-3 text-slate-700 dark:text-slate-300 whitespace-nowrap">{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    {totalCount !== undefined && shownCount !== undefined && totalCount > shownCount && (
      <div className="flex items-center gap-3 mt-2">
        <p className="text-xs text-slate-400 dark:text-slate-600">Showing {shownCount} of {totalCount}</p>
        {onLoadMore && (
          <button
            onClick={onLoadMore}
            disabled={loadingMore}
            className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium disabled:opacity-50 transition-colors"
          >
            {loadingMore ? <><Loader2 className="w-3 h-3 animate-spin" /> Loading…</> : `Load ${Math.min(totalCount - shownCount, 300)} more`}
          </button>
        )}
      </div>
    )}
  </div>
);

const KeyValueGrid: React.FC<{ rows: [string, React.ReactNode][] }> = ({ rows }) => (
  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
    {rows.map(([label, value]) => (
      <div key={label} className="flex items-center justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-800/60 text-sm">
        <dt className="text-slate-400 dark:text-slate-500 flex-shrink-0">{label}</dt>
        <dd className="text-slate-900 dark:text-white text-right break-all">{value}</dd>
      </div>
    ))}
  </dl>
);

const severityBadgeClass = (severity?: string): string => {
  const s = String(severity ?? '').toLowerCase();
  if (s === 'critical') return 'text-red-400 bg-red-500/10 border-red-500/30';
  if (s === 'high') return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
  if (s === 'medium') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
  return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
};

const vulnFilterBtnClass = (active: boolean) =>
  `px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
    active ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
  }`;

type VulnSeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

// Vulnerabilities section with a severity filter + CVE/package search — the
// data itself is whatever's already been fetched (up to 500 items, more via
// Load More), filtered client-side.
const VulnerabilitiesSection: React.FC<{
  section: WazuhListSection<WazuhVulnerability>;
  onLoadMore: () => void;
  loadingMore: boolean;
}> = ({ section, onLoadMore, loadingMore }) => {
  const [severity, setSeverity] = useState<VulnSeverityFilter>('all');
  const [search, setSearch] = useState('');

  if (!section.ok) return <SectionUnavailable message={section.error} />;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of section.items) {
    const s = String(v.severity ?? '').toLowerCase();
    if (s === 'critical') counts.critical++;
    else if (s === 'high') counts.high++;
    else if (s === 'medium') counts.medium++;
    else counts.low++;
  }

  const searchLower = search.trim().toLowerCase();
  const filtered = section.items.filter((v) => {
    if (severity !== 'all' && String(v.severity ?? '').toLowerCase() !== severity) return false;
    if (searchLower) {
      const hay = `${v.cve ?? ''} ${v.package?.name ?? ''}`.toLowerCase();
      if (!hay.includes(searchLower)) return false;
    }
    return true;
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={() => setSeverity('all')} className={vulnFilterBtnClass(severity === 'all')}>All ({section.items.length})</button>
        <button onClick={() => setSeverity('critical')} className={vulnFilterBtnClass(severity === 'critical')}>Critical ({counts.critical})</button>
        <button onClick={() => setSeverity('high')} className={vulnFilterBtnClass(severity === 'high')}>High ({counts.high})</button>
        <button onClick={() => setSeverity('medium')} className={vulnFilterBtnClass(severity === 'medium')}>Medium ({counts.medium})</button>
        <button onClick={() => setSeverity('low')} className={vulnFilterBtnClass(severity === 'low')}>Low ({counts.low})</button>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search CVE or package…"
          className="ml-auto px-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-56"
        />
      </div>

      <SimpleTable
        columns={['CVE', 'Severity', 'Package', 'Version']}
        rows={filtered.map((v) => [
          safe(v.cve),
          <span key="s" className={`text-xs font-bold px-2 py-0.5 rounded border ${severityBadgeClass(v.severity)}`}>
            {String(v.severity ?? '—').toUpperCase()}
          </span>,
          safe(v.package?.name), safe(v.package?.version),
        ])}
        empty={section.items.length === 0 ? 'No vulnerabilities found for this agent' : 'No CVEs match this filter'}
        shownCount={section.items.length}
        totalCount={section.total}
        onLoadMore={onLoadMore}
        loadingMore={loadingMore}
      />
    </div>
  );
};

// ─── FIM change-history helpers ─────────────────────────────────────────────
const FIM_FIELD_LABELS: Record<string, string> = {
  size: 'Size',
  md5sum: 'MD5', md5: 'MD5',
  sha1sum: 'SHA1', sha1: 'SHA1',
  sha256sum: 'SHA256', sha256: 'SHA256',
  perm: 'Permissions',
  uid: 'UID', gid: 'GID',
  uname: 'Owner', gname: 'Group',
  mtime: 'Modified', inode: 'Inode',
};

const humanizeFimKey = (key: string): string =>
  FIM_FIELD_LABELS[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

const formatFimValue = (key: string, v: unknown): string => {
  if (v === null || v === undefined || v === '') return '—';
  if (key === 'mtime' && (typeof v === 'string' || typeof v === 'number')) {
    const d = new Date(typeof v === 'number' ? v * 1000 : v);
    if (!isNaN(d.getTime())) return d.toLocaleString();
  }
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return String(v); } }
  const s = String(v);
  return s.length > 24 && /^[a-f0-9]+$/i.test(s) ? `${s.slice(0, 16)}…` : s;
};

interface FimDiffPair { key: string; label: string; before: string; after: string }

// Wazuh's FIM alerts carry paired `<attr>_before` / `<attr>_after` fields for
// whatever actually changed (size, hashes, permissions, owner, mtime, ...).
// Pairing them up generically (rather than hardcoding each field name) means
// this stays correct across Wazuh versions/OSes without guessing wrong.
function extractFimDiffPairs(syscheck: Record<string, unknown>): FimDiffPair[] {
  const pairs: FimDiffPair[] = [];
  for (const key of Object.keys(syscheck)) {
    if (!key.endsWith('_before')) continue;
    const base = key.slice(0, -'_before'.length);
    const afterKey = `${base}_after`;
    if (!(afterKey in syscheck)) continue;
    const beforeRaw = syscheck[key];
    const afterRaw = syscheck[afterKey];
    if (String(beforeRaw ?? '') === String(afterRaw ?? '')) continue;
    pairs.push({ key: base, label: humanizeFimKey(base), before: formatFimValue(base, beforeRaw), after: formatFimValue(base, afterRaw) });
  }
  return pairs;
}

const fimEventClass = (event: string | null): string => {
  const e = (event || '').toLowerCase();
  if (e === 'added') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  if (e === 'deleted') return 'text-red-400 bg-red-500/10 border-red-500/30';
  if (e === 'modified') return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
  return 'text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700';
};

const fimTabBtnClass = (active: boolean) =>
  `px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
    active ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
  }`;

const FIM_PAGE_SIZE = 25;

// Real change history, sourced from the Wazuh Indexer's FIM alerts (see
// backend/routes/compliance.js's /fim/:agentId) — every detected add/modify/
// delete event with its full before/after diff. This is what actually shows
// "what changed", unlike the manager API's /syscheck (Current State tab
// below), which only reports each file's latest snapshot.
const FimHistoryPanel: React.FC<{ agent: WazuhAgent; config: WazuhConfig }> = ({ agent, config }) => {
  const [page, setPage] = useState(1);
  const [path, setPath] = useState('');
  const [days, setDays] = useState<number | null>(30);
  const [events, setEvents] = useState<FimEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => { setPage(1); }, [path, days]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    getFimHistory(config, agent.id, { page, pageSize: FIM_PAGE_SIZE, days: days ?? undefined, path: path.trim() || undefined })
      .then((r) => { if (!cancelled) { setEvents(r.events); setTotal(r.total); } })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load FIM change history.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [agent.id, config, page, path, days]);

  const totalPages = Math.max(1, Math.ceil(total / FIM_PAGE_SIZE));

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="Filter by file path…"
          className="px-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-56"
        />
        <div className="flex items-center gap-1.5">
          {[7, 30, 90].map((d) => (
            <button key={d} onClick={() => setDays(d)} className={fimTabBtnClass(days === d)}>{d}d</button>
          ))}
          <button onClick={() => setDays(null)} className={fimTabBtnClass(days === null)}>All time</button>
        </div>
      </div>

      {loading && events.length === 0 ? (
        <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading change history…
        </div>
      ) : error ? (
        <div className="flex items-center gap-2 px-4 py-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      ) : events.length === 0 ? (
        <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">
          No file changes detected{path ? ' for this path' : ''}{days ? ` in the last ${days} days` : ''}.
        </p>
      ) : (
        <div className="space-y-2">
          {events.map((ev) => {
            const pairs = extractFimDiffPairs(ev.syscheck);
            const diffText = typeof ev.syscheck.diff === 'string' ? ev.syscheck.diff : null;
            return (
              <div key={ev.id} className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-800/30 p-3">
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <div className="min-w-0">
                    <p className="text-sm text-slate-900 dark:text-white font-mono break-all">{ev.path ?? 'Unknown path'}</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—'}
                      {ev.ruleDescription ? ` · ${ev.ruleDescription}` : ''}
                      {ev.ruleLevel !== null ? ` · level ${ev.ruleLevel}` : ''}
                    </p>
                  </div>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded border capitalize whitespace-nowrap ${fimEventClass(ev.event)}`}>
                    {ev.event ?? 'unknown'}
                  </span>
                </div>

                {ev.changedAttributes.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {ev.changedAttributes.map((a) => (
                      <span key={a} className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400">{a}</span>
                    ))}
                  </div>
                )}

                {pairs.length > 0 && (
                  <div className="mt-2.5 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-800/40">
                          <th className="py-1.5 px-2.5 text-left font-medium text-slate-400 dark:text-slate-500">Attribute</th>
                          <th className="py-1.5 px-2.5 text-left font-medium text-slate-400 dark:text-slate-500">Before</th>
                          <th className="py-1.5 px-2.5 text-left font-medium text-slate-400 dark:text-slate-500">After</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pairs.map((p) => (
                          <tr key={p.key} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0">
                            <td className="py-1.5 px-2.5 text-slate-500 dark:text-slate-400 whitespace-nowrap">{p.label}</td>
                            <td className="py-1.5 px-2.5 text-red-400/80 font-mono break-all">{p.before}</td>
                            <td className="py-1.5 px-2.5 text-emerald-400/80 font-mono break-all">{p.after}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {diffText && (
                  <pre className="mt-2.5 p-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 overflow-x-auto whitespace-pre-wrap">
                    {diffText}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      )}

      {total > 0 && (
        <div className="flex items-center justify-between px-1 pt-1">
          <p className="text-xs text-slate-400 dark:text-slate-500">Page {page} of {totalPages} · {total.toLocaleString()} total changes</p>
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
  );
};

// FIM tab shell: "Change History" (Indexer-backed, real diffs — see above)
// plus the original "Current State" snapshot table (manager API, no Indexer
// needed) so the tab still works even without an Indexer configured.
const FimSection: React.FC<{
  agent: WazuhAgent;
  config: WazuhConfig;
  details: WazuhAgentDetails | null;
  loading: boolean;
  error: string;
  onLoadMoreCurrent: () => void;
  loadingMoreCurrent: boolean;
}> = ({ agent, config, details, loading, error, onLoadMoreCurrent, loadingMoreCurrent }) => {
  const [view, setView] = useState<'history' | 'current'>(hasIndexerConfig(config) ? 'history' : 'current');

  return (
    <div className="space-y-4">
      <div className="flex gap-1.5">
        <button onClick={() => setView('history')} className={fimTabBtnClass(view === 'history')}>Change History</button>
        <button onClick={() => setView('current')} className={fimTabBtnClass(view === 'current')}>
          Current State{details?.fim.ok ? ` (${details.fim.total})` : ''}
        </button>
      </div>

      {view === 'history' ? (
        hasIndexerConfig(config) ? (
          <FimHistoryPanel agent={agent} config={config} />
        ) : (
          <div className="flex items-start gap-2 p-4 rounded-lg bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-slate-400 dark:text-slate-500 text-xs">
            <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <span>
              Real change history (before/after diffs) needs the Wazuh Indexer — add its connection details
              under Settings → Wazuh SIEM → "Wazuh Indexer settings". The Current State tab works without it.
            </span>
          </div>
        )
      ) : loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-slate-400 dark:text-slate-500 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading current state…
        </div>
      ) : error ? (
        <div className="flex items-center gap-2 px-4 py-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      ) : !details ? (
        <SectionUnavailable />
      ) : details.fim.ok ? (
        <SimpleTable
          columns={['File', 'Event', 'Owner', 'Permissions', 'Modified', 'SHA256']}
          rows={details.fim.items.map((f) => [
            <span key="f" className="font-mono">{safe(f.file)}</span>,
            safe(f.event), safe(f.uname), safe(f.perm), formatDate(f.mtime),
            typeof f.sha256 === 'string' && f.sha256 ? `${f.sha256.slice(0, 12)}…` : '—',
          ])}
          empty="No file integrity monitoring events for this agent"
          shownCount={details.fim.items.length}
          totalCount={details.fim.total}
          onLoadMore={onLoadMoreCurrent}
          loadingMore={loadingMoreCurrent}
        />
      ) : (
        <SectionUnavailable message={details.fim.error} />
      )}
    </div>
  );
};

// ─── Main modal ───────────────────────────────────────────────────────────────
const AgentDetailsModal: React.FC<{
  agent: WazuhAgent;
  config: WazuhConfig;
  onClose: () => void;
  // When set, the modal shows only this section — no tab bar, no way to
  // navigate to the others. Used when the modal is opened from a page that's
  // already scoped to one kind of data (e.g. the Vulnerabilities tab).
  onlySection?: SectionKey;
}> = ({ agent, config, onClose, onlySection }) => {
  const [details, setDetails] = useState<WazuhAgentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [section, setSection] = useState<SectionKey>(onlySection ?? 'overview');
  const [loadingMore, setLoadingMore] = useState<AgentDetailsSection | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    getAgentDetails(config, agent.id)
      .then((d) => { if (!cancelled) setDetails(d); })
      .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load agent details.'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [agent.id, config]);

  // Fetches the next page for one section and appends it in place — the initial
  // agent-details call already brings up to 500 items per section, so this only
  // kicks in for agents with unusually large inventories (500+ packages, etc.).
  const loadMoreSection = async (key: AgentDetailsSection) => {
    if (!details) return;
    const current = details[key];
    if (!current.ok || current.items.length >= current.total) return;

    setLoadingMore(key);
    try {
      const next = await getAgentDetailsSection<unknown>(config, agent.id, key, current.items.length, 300);
      setDetails((prev) => {
        if (!prev) return prev;
        const prevSection = prev[key];
        return {
          ...prev,
          [key]: { ...prevSection, items: [...prevSection.items, ...next.items], total: next.total },
        };
      });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to load more ${key}.`);
    } finally {
      setLoadingMore(null);
    }
  };

  const meta = statusMeta[normalizeAgentStatus(agent.status)];

  const sections: { id: SectionKey; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Server className="w-3.5 h-3.5" /> },
    { id: 'hardware', label: 'Hardware & OS', icon: <Cpu className="w-3.5 h-3.5" /> },
    { id: 'network', label: 'Network', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'software', label: 'Software', icon: <Package className="w-3.5 h-3.5" /> },
    { id: 'processes', label: 'Processes', icon: <Activity className="w-3.5 h-3.5" /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
    { id: 'sca', label: 'SCA', icon: <ClipboardCheck className="w-3.5 h-3.5" /> },
    { id: 'fim', label: 'FIM', icon: <FileSearch className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-4xl rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${meta.dot}`} />
              {agent.name}
              <span className="text-slate-400 dark:text-slate-600 font-mono text-xs font-normal">#{agent.id}</span>
            </h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{meta.label} · {agent.ip ?? 'no IP'} · {formatOs(agent.os)}</p>
          </div>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Section tabs — omitted entirely when the modal is scoped to one section */}
        {!onlySection && (
          <div className="flex gap-1 px-6 py-2.5 border-b border-slate-200 dark:border-slate-800 overflow-x-auto flex-shrink-0">
            {sections.map((s) => (
              <button
                key={s.id}
                onClick={() => setSection(s.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                  section === s.id
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-transparent'
                }`}
              >
                {s.icon} {s.label}
              </button>
            ))}
          </div>
        )}

        {/* Body */}
        <div className="px-6 py-5 overflow-y-auto">
        <SectionErrorBoundary resetKey={section}>
          {section === 'overview' ? (
            <KeyValueGrid rows={[
              ['ID', agent.id],
              ['Name', agent.name],
              ['Status', (
                <span className="flex items-center gap-1.5 justify-end">
                  <span className={`w-1.5 h-1.5 rounded-full ${meta.dot}`} />
                  <span className={meta.online ? 'text-emerald-400' : 'text-slate-700 dark:text-slate-300'}>{meta.label}</span>
                </span>
              )],
              ['IP Address', agent.ip ?? '—'],
              ['OS', formatOs(agent.os)],
              ['OS Platform', agent.os?.platform ?? '—'],
              ['OS Architecture', agent.os?.arch ?? '—'],
              ['OS Codename', agent.os?.codename ?? '—'],
              ['Agent Version', agent.version ?? '—'],
              ['Groups', agent.group && agent.group.length > 0 ? agent.group.join(', ') : '—'],
              ['Group Sync Status', agent.group_config_status ?? '—'],
              ['Manager', agent.manager ?? '—'],
              ['Cluster Node', agent.node_name ?? '—'],
              ['Registered', formatDate(agent.dateAdd)],
              ['Last Keep-Alive', formatDate(agent.lastKeepAlive)],
            ]} />
          ) : section === 'fim' ? (
            <FimSection
              agent={agent}
              config={config}
              details={details}
              loading={loading}
              error={error}
              onLoadMoreCurrent={() => loadMoreSection('fim')}
              loadingMoreCurrent={loadingMore === 'fim'}
            />
          ) : loading ? (
            <div className="flex items-center justify-center gap-2 py-16 text-slate-400 dark:text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading {sections.find((s) => s.id === section)?.label.toLowerCase()}…
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 px-4 py-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
            </div>
          ) : !details ? (
            <SectionUnavailable />
          ) : section === 'hardware' ? (
            <div className="space-y-5">
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Hardware</h3>
                {details.hardware.ok && details.hardware.item ? (
                  <KeyValueGrid rows={[
                    ['CPU', safe(details.hardware.item.cpu?.name)],
                    ['CPU Cores', safe(details.hardware.item.cpu?.cores)],
                    ['CPU Speed', details.hardware.item.cpu?.mhz ? `${details.hardware.item.cpu.mhz} MHz` : '—'],
                    ['Total RAM', formatKB(details.hardware.item.ram?.total)],
                    ['Free RAM', formatKB(details.hardware.item.ram?.free)],
                    ['RAM Usage', details.hardware.item.ram?.usage !== undefined ? `${details.hardware.item.ram.usage}%` : '—'],
                    ['Board Serial', safe(details.hardware.item.board_serial)],
                  ]} />
                ) : (
                  <SectionUnavailable message={details.hardware.error} />
                )}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Operating System</h3>
                {details.os.ok && details.os.item ? (
                  <KeyValueGrid rows={[
                    ['Hostname', safe(details.os.item.hostname)],
                    ['OS Name', safe(details.os.item.os?.name)],
                    ['Platform', safe(details.os.item.os?.platform)],
                    ['Version', safe(details.os.item.os?.version ?? details.os.item.version)],
                    ['Codename', safe(details.os.item.os?.codename)],
                    ['Architecture', safe(details.os.item.architecture)],
                    ['Kernel / Sysname', safe(details.os.item.sysname)],
                    ['Release', safe(details.os.item.release)],
                  ]} />
                ) : (
                  <SectionUnavailable message={details.os.error} />
                )}
              </div>
            </div>
          ) : section === 'network' ? (
            <div className="space-y-5">
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                  Interfaces {details.netiface.ok && `(${details.netiface.total})`}
                </h3>
                {details.netiface.ok ? (
                  <SimpleTable
                    columns={['Name', 'Adapter', 'State', 'Type', 'MTU', 'RX', 'TX']}
                    rows={details.netiface.items.map((n) => [
                      safe(n.name), safe(n.adapter), safe(n.state), safe(n.type),
                      safe(n.mtu), n.rx?.bytes !== undefined ? `${(n.rx.bytes / 1024).toFixed(0)} KB` : '—',
                      n.tx?.bytes !== undefined ? `${(n.tx.bytes / 1024).toFixed(0)} KB` : '—',
                    ])}
                    shownCount={details.netiface.items.length}
                    totalCount={details.netiface.total}
                    onLoadMore={() => loadMoreSection('netiface')}
                    loadingMore={loadingMore === 'netiface'}
                  />
                ) : <SectionUnavailable message={details.netiface.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                  IP Addresses {details.netaddr.ok && `(${details.netaddr.total})`}
                </h3>
                {details.netaddr.ok ? (
                  <SimpleTable
                    columns={['Interface', 'Protocol', 'Address', 'Netmask', 'Broadcast']}
                    rows={details.netaddr.items.map((n) => [
                      safe(n.iface), safe(n.proto), safe(n.address), safe(n.netmask), safe(n.broadcast),
                    ])}
                    shownCount={details.netaddr.items.length}
                    totalCount={details.netaddr.total}
                    onLoadMore={() => loadMoreSection('netaddr')}
                    loadingMore={loadingMore === 'netaddr'}
                  />
                ) : <SectionUnavailable message={details.netaddr.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                  Gateways {details.netproto.ok && `(${details.netproto.total})`}
                </h3>
                {details.netproto.ok ? (
                  <SimpleTable
                    columns={['Interface', 'Type', 'Gateway', 'DHCP']}
                    rows={details.netproto.items.map((n) => [safe(n.iface), safe(n.type), safe(n.gateway), safe(n.dhcp)])}
                    shownCount={details.netproto.items.length}
                    totalCount={details.netproto.total}
                    onLoadMore={() => loadMoreSection('netproto')}
                    loadingMore={loadingMore === 'netproto'}
                  />
                ) : <SectionUnavailable message={details.netproto.error} />}
              </div>
              <div>
                <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                  Listening / Active Ports {details.ports.ok && `(${details.ports.total})`}
                </h3>
                {details.ports.ok ? (
                  <SimpleTable
                    columns={['Local', 'Remote', 'Protocol', 'State', 'PID', 'Process']}
                    rows={details.ports.items.map((p) => [
                      p.local ? `${p.local.ip ?? '*'}:${p.local.port ?? '—'}` : '—',
                      p.remote ? `${p.remote.ip ?? '*'}:${p.remote.port ?? '—'}` : '—',
                      safe(p.protocol), safe(p.state), safe(p.pid), safe(p.process),
                    ])}
                    shownCount={details.ports.items.length}
                    totalCount={details.ports.total}
                    onLoadMore={() => loadMoreSection('ports')}
                    loadingMore={loadingMore === 'ports'}
                  />
                ) : <SectionUnavailable message={details.ports.error} />}
              </div>
            </div>
          ) : section === 'software' ? (
            details.packages.ok ? (
              <SimpleTable
                columns={['Name', 'Version', 'Vendor', 'Architecture', 'Installed']}
                rows={details.packages.items.map((p) => [
                  safe(p.name), safe(p.version), safe(p.vendor), safe(p.architecture), formatDate(p.install_time),
                ])}
                empty="No installed packages reported"
                shownCount={details.packages.items.length}
                totalCount={details.packages.total}
                onLoadMore={() => loadMoreSection('packages')}
                loadingMore={loadingMore === 'packages'}
              />
            ) : <SectionUnavailable message={details.packages.error} />
          ) : section === 'processes' ? (
            details.processes.ok ? (
              <SimpleTable
                columns={['PID', 'Name', 'State', 'Priority', 'Memory (KB)', 'Started']}
                rows={details.processes.items.map((p) => [
                  safe(p.pid), safe(p.name), safe(p.state), safe(p.priority), safe(p.vm_size), formatDate(p.start_time),
                ])}
                empty="No running processes reported"
                shownCount={details.processes.items.length}
                totalCount={details.processes.total}
                onLoadMore={() => loadMoreSection('processes')}
                loadingMore={loadingMore === 'processes'}
              />
            ) : <SectionUnavailable message={details.processes.error} />
          ) : section === 'vulnerabilities' ? (
            <VulnerabilitiesSection
              section={details.vulnerabilities}
              onLoadMore={() => loadMoreSection('vulnerabilities')}
              loadingMore={loadingMore === 'vulnerabilities'}
            />
          ) : section === 'sca' ? (
            details.sca.ok ? (
              <SimpleTable
                columns={['Policy', 'Description', 'Pass', 'Fail', 'Invalid', 'Score', 'Last Scan']}
                rows={details.sca.items.map((p) => [
                  safe(p.name ?? p.policy_id), safe(p.description),
                  <span key="p" className="text-emerald-400">{p.pass ?? 0}</span>,
                  <span key="f" className="text-red-400">{p.fail ?? 0}</span>,
                  safe(p.invalid ?? 0),
                  p.score !== undefined ? `${p.score}%` : '—',
                  formatDate(p.end_scan),
                ])}
                empty="No SCA policy results for this agent"
                shownCount={details.sca.items.length}
                totalCount={details.sca.total}
                onLoadMore={() => loadMoreSection('sca')}
                loadingMore={loadingMore === 'sca'}
              />
            ) : <SectionUnavailable message={details.sca.error} />
          ) : null}
        </SectionErrorBoundary>
        </div>
      </div>
    </div>
  );
};

export default AgentDetailsModal;
