// "Compliances" tab: HIPAA/GDPR/CIS alignment per device. CIS is a real Wazuh
// SCA benchmark scan; HIPAA/GDPR are derived from alert history (Wazuh's
// ruleset tags rules with the controls they map to) — not a certified audit,
// and the UI says so explicitly wherever these numbers are shown.
import React, { useEffect, useMemo, useState } from 'react';
import {
  ShieldCheck, Globe, ClipboardCheck, Loader2, AlertCircle, Info, X,
  CheckCircle, XCircle, AlertTriangle, Search, MinusCircle, Download, Printer,
} from 'lucide-react';
import { useWazuhContext } from './WazuhContext';
import {
  WazuhAgent, normalizeAgentStatus, formatOs,
  getScaSummary, getScaChecks, ScaAgentSummary, WazuhScaCheck,
} from './wazuhApi';
import {
  hasIndexerConfig, getComplianceSummary, getComplianceAgentDetail,
  ComplianceFramework, ComplianceSummary, ComplianceAgentDetail,
} from './complianceApi';
import { downloadCsv } from '../../utils/csv';

export type FrameworkTab = 'hipaa' | 'gdpr' | 'cis';

const FRAMEWORK_META: Record<FrameworkTab, { label: string; icon: React.ReactNode; description: string }> = {
  hipaa: { label: 'HIPAA', icon: <ShieldCheck className="w-3.5 h-3.5" />, description: 'US healthcare data protection — alert exposure by mapped control' },
  gdpr:  { label: 'GDPR',  icon: <Globe className="w-3.5 h-3.5" />,       description: 'EU data protection — alert exposure by mapped control' },
  cis:   { label: 'CIS',   icon: <ClipboardCheck className="w-3.5 h-3.5" />, description: 'CIS benchmark — real SCA configuration scan results' },
};

const deviceStatusDot: Record<string, string> = {
  active: 'bg-emerald-400',
  disconnected: 'bg-red-400',
  never_connected: 'bg-slate-600',
  pending: 'bg-amber-400',
};

const scoreColor = (score: number | null): string => {
  if (score === null) return 'text-slate-400 dark:text-slate-500';
  if (score >= 90) return 'text-emerald-400';
  if (score >= 70) return 'text-amber-400';
  return 'text-red-400';
};

// ─── SCA check result classification ────────────────────────────────────────
const resultKey = (result?: string) => (result || '').toLowerCase();
const isPassed = (c: WazuhScaCheck) => resultKey(c.result) === 'passed';
const isFailed = (c: WazuhScaCheck) => resultKey(c.result) === 'failed';
const isNotApplicable = (c: WazuhScaCheck) => resultKey(c.result).includes('not applicable');

const checkCardClass = (c: WazuhScaCheck): string => {
  if (isFailed(c)) return 'bg-red-500/5 border-red-500/20';
  if (isPassed(c)) return 'bg-emerald-500/5 border-emerald-500/20';
  return 'bg-slate-100 dark:bg-slate-800/40 border-slate-200 dark:border-slate-800';
};
const checkBadgeClass = (c: WazuhScaCheck): string => {
  if (isFailed(c)) return 'text-red-400 bg-red-500/10 border-red-500/30';
  if (isPassed(c)) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  return 'text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700';
};
const checkIcon = (c: WazuhScaCheck) => {
  if (isFailed(c)) return <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />;
  if (isPassed(c)) return <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />;
  return <MinusCircle className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 flex-shrink-0" />;
};

// ─── Detail modal ───────────────────────────────────────────────────────────
const ComplianceDetailModal: React.FC<{
  agent: WazuhAgent;
  framework: FrameworkTab;
  days: number;
  scaSummary?: ScaAgentSummary;
  onClose: () => void;
}> = ({ agent, framework, days, scaSummary, onClose }) => {
  const { config } = useWazuhContext();
  const meta = FRAMEWORK_META[framework];

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [alertDetail, setAlertDetail] = useState<ComplianceAgentDetail | null>(null);
  const [observedControls, setObservedControls] = useState<string[]>([]);
  const [checksByPolicy, setChecksByPolicy] = useState<Record<string, WazuhScaCheck[]>>({});

  const [search, setSearch] = useState('');
  const [cisView, setCisView] = useState<'failed' | 'passed' | 'na' | 'all'>('failed');
  const [controlView, setControlView] = useState<'flagged' | 'clear'>('flagged');

  useEffect(() => {
    let cancelled = false;
    if (!config) return;
    setLoading(true);
    setError('');

    if (framework === 'cis') {
      const policies = scaSummary?.policies ?? [];
      Promise.all(policies.map((p) => (p.policyId ? getScaChecks(config, agent.id, p.policyId) : Promise.resolve({ ok: false, items: [], total: 0, error: 'no policy id' }))))
        .then((results) => {
          if (cancelled) return;
          const byPolicy: Record<string, WazuhScaCheck[]> = {};
          results.forEach((r, i) => {
            const policyId = policies[i].policyId;
            if (policyId) byPolicy[policyId] = r.ok ? r.items : [];
          });
          setChecksByPolicy(byPolicy);
        })
        .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load CIS check details.'); })
        .finally(() => { if (!cancelled) setLoading(false); });
    } else {
      Promise.all([
        getComplianceAgentDetail(config, framework as ComplianceFramework, agent.id, days),
        getComplianceSummary(config, framework as ComplianceFramework, days, [agent.id]),
      ])
        .then(([detail, summary]) => {
          if (cancelled) return;
          setAlertDetail(detail);
          setObservedControls(summary.observedControls);
        })
        .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : `Failed to load ${meta.label} details.`); })
        .finally(() => { if (!cancelled) setLoading(false); });
    }

    return () => { cancelled = true; };
  }, [agent.id, framework, days, config, scaSummary, meta.label]);

  const allChecks = useMemo(() => Object.values(checksByPolicy).flat(), [checksByPolicy]);
  const passedChecks = allChecks.filter(isPassed);
  const failedChecks = allChecks.filter(isFailed);
  const naChecks = allChecks.filter(isNotApplicable);
  const cisChecksByView = { failed: failedChecks, passed: passedChecks, na: naChecks, all: allChecks }[cisView];
  const searchLower = search.trim().toLowerCase();
  const filteredCisChecks = searchLower
    ? cisChecksByView.filter((c) =>
        (c.title || '').toLowerCase().includes(searchLower) ||
        (c.description || '').toLowerCase().includes(searchLower) ||
        String(c.id ?? '').includes(searchLower)
      )
    : cisChecksByView;

  const violatedIds = new Set((alertDetail?.violatedControls ?? []).map((c) => c.control));
  const compliantControls = observedControls.filter((c) => !violatedIds.has(c));
  const violatedSorted = [...(alertDetail?.violatedControls ?? [])].sort((a, b) => b.alertCount - a.alertCount);
  const filteredViolated = searchLower ? violatedSorted.filter((v) => v.control.toLowerCase().includes(searchLower)) : violatedSorted;
  const filteredCompliant = searchLower ? compliantControls.filter((c) => c.toLowerCase().includes(searchLower)) : compliantControls;

  const tabBtn = (active: boolean) =>
    `px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
      active ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
    }`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-3xl rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[88vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
          <div>
            <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              {meta.icon} {meta.label} — {agent.name}
            </h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
              {framework === 'cis' ? 'CIS benchmark check results' : `Alert exposure over the last ${days} days`}
            </p>
          </div>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-5 overflow-y-auto space-y-4 flex-1 min-h-0">
          {loading ? (
            <div className="flex items-center justify-center gap-2 py-16 text-slate-400 dark:text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 px-4 py-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
            </div>
          ) : framework === 'cis' ? (
            <>
              <div className="grid grid-cols-4 gap-3">
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className="text-lg font-bold text-emerald-400">{passedChecks.length}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">Passed</p>
                </div>
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className="text-lg font-bold text-red-400">{failedChecks.length}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">Failed</p>
                </div>
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className="text-lg font-bold text-slate-500 dark:text-slate-400">{naChecks.length}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">N/A</p>
                </div>
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className={`text-lg font-bold ${scoreColor(scaSummary?.score ?? null)}`}>
                    {scaSummary?.score !== undefined && scaSummary?.score !== null ? `${scaSummary.score}%` : '—'}
                  </p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">Score</p>
                </div>
              </div>

              {allChecks.length === 0 ? (
                <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-8">
                  No CIS SCA policy results found for this device.
                </p>
              ) : (
                <>
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex gap-1.5 flex-wrap">
                      <button onClick={() => setCisView('failed')} className={tabBtn(cisView === 'failed')}>Failed ({failedChecks.length})</button>
                      <button onClick={() => setCisView('passed')} className={tabBtn(cisView === 'passed')}>Passed ({passedChecks.length})</button>
                      <button onClick={() => setCisView('na')} className={tabBtn(cisView === 'na')}>N/A ({naChecks.length})</button>
                      <button onClick={() => setCisView('all')} className={tabBtn(cisView === 'all')}>All ({allChecks.length})</button>
                    </div>
                    <div className="relative">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
                      <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search checks…"
                        className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-48"
                      />
                    </div>
                  </div>

                  <div className="space-y-2 max-h-[45vh] overflow-y-auto pr-1">
                    {filteredCisChecks.length === 0 ? (
                      <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8">No checks match.</p>
                    ) : (
                      filteredCisChecks.map((c, i) => (
                        <div key={c.id ?? i} className={`rounded-lg border p-3 ${checkCardClass(c)}`}>
                          <div className="flex items-start justify-between gap-2">
                            <p className="text-sm text-slate-900 dark:text-white font-medium flex items-center gap-2">
                              {checkIcon(c)} {c.title || `Check #${c.id}`}
                            </p>
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border whitespace-nowrap flex-shrink-0 ${checkBadgeClass(c)}`}>
                              {c.result || '—'}
                            </span>
                          </div>
                          {c.description && <p className="text-xs text-slate-500 dark:text-slate-400 mt-1.5">{c.description}</p>}
                          {c.rationale && (
                            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1"><span className="text-slate-500 dark:text-slate-400 font-medium">Rationale: </span>{c.rationale}</p>
                          )}
                          {c.remediation && (
                            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1"><span className="text-slate-500 dark:text-slate-400 font-medium">Remediation: </span>{c.remediation}</p>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </>
              )}
            </>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className="text-lg font-bold text-red-400">{violatedIds.size}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">Controls flagged</p>
                </div>
                <div className="rounded-xl bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 p-3 text-center">
                  <p className="text-lg font-bold text-emerald-400">{compliantControls.length}</p>
                  <p className="text-xs text-slate-400 dark:text-slate-500">No violations detected</p>
                </div>
              </div>

              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex gap-1.5">
                  <button onClick={() => setControlView('flagged')} className={tabBtn(controlView === 'flagged')}>Flagged ({violatedIds.size})</button>
                  <button onClick={() => setControlView('clear')} className={tabBtn(controlView === 'clear')}>Clear ({compliantControls.length})</button>
                </div>
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 dark:text-slate-500 pointer-events-none" />
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search controls…"
                    className="pl-8 pr-3 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 w-48"
                  />
                </div>
              </div>

              {controlView === 'flagged' ? (
                <div className="space-y-2 max-h-[45vh] overflow-y-auto pr-1">
                  {filteredViolated.length === 0 ? (
                    <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8">
                      {violatedSorted.length === 0
                        ? `No ${meta.label}-mapped alerts fired for this device in the last ${days} days.`
                        : 'No controls match.'}
                    </p>
                  ) : (
                    filteredViolated.map((v) => (
                      <div key={v.control} className="rounded-lg bg-red-500/5 border border-red-500/20 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-sm text-slate-900 dark:text-white font-medium flex items-center gap-2">
                            <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" /> {v.control}
                          </p>
                          <span className="text-xs text-slate-400 dark:text-slate-500 whitespace-nowrap">
                            {v.alertCount} alert{v.alertCount === 1 ? '' : 's'}{v.maxLevel !== null ? ` · max level ${v.maxLevel}` : ''}
                          </span>
                        </div>
                        {v.samples.length > 0 && (
                          <div className="mt-2 pt-2 border-t border-red-500/10 space-y-1">
                            {v.samples.map((s, i) => (
                              <p key={i} className="text-xs text-slate-400 dark:text-slate-500">
                                {s.timestamp && <span className="text-slate-400 dark:text-slate-600 font-mono">{new Date(s.timestamp).toLocaleString()}</span>}
                                {s.description && <span> — "{s.description}"</span>}
                                {s.ruleId && <span className="text-slate-400 dark:text-slate-600"> (rule {s.ruleId})</span>}
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              ) : (
                <div className="flex flex-wrap gap-1.5 max-h-[45vh] overflow-y-auto pr-1">
                  {filteredCompliant.length === 0 ? (
                    <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-8 w-full">No controls match.</p>
                  ) : (
                    filteredCompliant.map((c) => (
                      <span key={c} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs">
                        <CheckCircle className="w-2.5 h-2.5" /> {c}
                      </span>
                    ))
                  )}
                </div>
              )}

              <div className="flex items-start gap-2 p-3 rounded-lg bg-slate-100 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800">
                <Info className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 flex-shrink-0 mt-0.5" />
                <p className="text-xs text-slate-400 dark:text-slate-500">
                  Based on Wazuh alert activity mapped to {meta.label} controls — not a certified compliance
                  audit. "No violations detected" means no matching alert fired in this window, not that the
                  control has been formally verified.
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// ─── Main panel ───────────────────────────────────────────────────────────────
// `framework` is controlled by the sidebar (AdminDashboard's "Compliances"
// expandable group — HIPAA / GDPR / CIS sub-items, same pattern as the
// Settings group's Users / Wazuh SIEM / Audit Log), not an in-page tab bar.
const CompliancePanel: React.FC<{ framework: FrameworkTab }> = ({ framework }) => {
  const { config, agents, loadingAgents } = useWazuhContext();
  const [days, setDays] = useState(30);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [alertSummary, setAlertSummary] = useState<ComplianceSummary | null>(null);
  const [scaSummaries, setScaSummaries] = useState<ScaAgentSummary[]>([]);

  const agentIds = useMemo(() => agents.map((a) => a.id), [agents]);
  const indexerReady = hasIndexerConfig(config);

  useEffect(() => {
    if (!config || agentIds.length === 0) return;
    if (framework !== 'cis' && !indexerReady) return;

    let cancelled = false;
    setLoading(true);
    setError('');

    if (framework === 'cis') {
      getScaSummary(config, agentIds)
        .then((r) => { if (!cancelled) setScaSummaries(r); })
        .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load CIS summary.'); })
        .finally(() => { if (!cancelled) setLoading(false); });
    } else {
      getComplianceSummary(config, framework as ComplianceFramework, days, agentIds)
        .then((r) => { if (!cancelled) setAlertSummary(r); })
        .catch((err: unknown) => { if (!cancelled) setError(err instanceof Error ? err.message : `Failed to load ${FRAMEWORK_META[framework].label} summary.`); })
        .finally(() => { if (!cancelled) setLoading(false); });
    }

    return () => { cancelled = true; };
  }, [config, framework, days, agentIds, indexerReady]);

  const scaByAgent = useMemo(() => new Map(scaSummaries.map((s) => [s.agentId, s])), [scaSummaries]);
  const alertByAgent = useMemo(
    () => new Map((alertSummary?.agents ?? []).map((a) => [a.agentId, a])),
    [alertSummary]
  );

  // Same rows the summary table renders — built from data already loaded
  // client-side, same "everything's already in memory" precondition
  // AdminCasesPanel's CSV export relies on (see utils/csv.ts).
  const handleExportCsv = () => {
    const label = FRAMEWORK_META[framework].label;
    const headers = framework === 'cis'
      ? ['Status', 'Name', 'OS', 'CIS score (%)', 'Passed', 'Failed']
      : ['Status', 'Name', 'OS', `${label} controls flagged`];
    const rows = agents.map((ag) => {
      const normalized = normalizeAgentStatus(ag.status);
      if (framework === 'cis') {
        const sca = scaByAgent.get(ag.id);
        return [normalized, ag.name, formatOs(ag.os), sca?.score ?? '', sca?.pass ?? '', sca?.fail ?? ''];
      }
      const alertRow = alertByAgent.get(ag.id);
      const violated = alertRow?.violatedControls.length ?? 0;
      return [normalized, ag.name, formatOs(ag.os), violated];
    });
    const suffix = framework === 'cis' ? '' : `-${days}d`;
    downloadCsv(`medisiem-${framework}-compliance${suffix}-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows);
  };

  // "Save as PDF" is the browser's own print dialog (AdminDashboard's
  // sidebar/header are hidden at print time via the .no-print rule in
  // index.css) — force light mode for the print snapshot first, since
  // Tailwind's dark: utilities would otherwise render white-on-white text
  // against a printed page (window.print() blocks until the dialog closes,
  // so restoring the class right after is safe).
  const handlePrint = () => {
    const root = document.documentElement;
    const wasDark = root.classList.contains('dark');
    if (wasDark) root.classList.remove('dark');
    window.print();
    if (wasDark) root.classList.add('dark');
  };

  if (!config) {
    return (
      <div className="p-5">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            {FRAMEWORK_META[framework].icon} {FRAMEWORK_META[framework].label} Compliance
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{FRAMEWORK_META[framework].description}</p>
        </div>
        <div className="mt-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <ShieldCheck className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh SIEM is not connected</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Connect it under Settings → Wazuh SIEM to see compliance data here.</p>
        </div>
      </div>
    );
  }

  const needsIndexer = framework !== 'cis' && !indexerReady;

  return (
    <div className="p-5 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            {FRAMEWORK_META[framework].icon} {FRAMEWORK_META[framework].label} Compliance
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{FRAMEWORK_META[framework].description}</p>
        </div>
        <div className="no-print flex items-center gap-1.5 flex-wrap">
          {framework !== 'cis' && (
            <div className="flex items-center gap-1.5">
              {[7, 30, 90].map((d) => (
                <button
                  key={d}
                  onClick={() => setDays(d)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    days === d ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {d}d
                </button>
              ))}
            </div>
          )}
          {agents.length > 0 && (
            <div className="flex items-center gap-1.5 pl-1.5 ml-1 border-l border-slate-200 dark:border-slate-800">
              <button
                onClick={handleExportCsv}
                title="Export the summary table as CSV"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                <Download className="w-3.5 h-3.5" /> CSV
              </button>
              <button
                onClick={handlePrint}
                title="Save this report as a PDF via your browser's print dialog"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                <Printer className="w-3.5 h-3.5" /> Save as PDF
              </button>
            </div>
          )}
        </div>
      </div>

      {needsIndexer ? (
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-10 text-center">
          <Info className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
          <p className="text-sm text-slate-700 dark:text-slate-300 font-medium">Wazuh Indexer is not configured</p>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">
            {FRAMEWORK_META[framework].label} is derived from alert history in the Wazuh Indexer — add its
            connection details under Settings → Wazuh SIEM → "Wazuh Indexer settings".
          </p>
        </div>
      ) : (
        <div className="rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
          {(loading || loadingAgents) && agents.length === 0 ? (
            <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          ) : error ? (
            <div className="flex items-center gap-2 px-5 py-6 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
            </div>
          ) : agents.length === 0 ? (
            <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">No devices found.</p>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-5 text-left">Status</th>
                  <th className="py-2.5 px-5 text-left">Name</th>
                  <th className="py-2.5 px-5 text-left">OS</th>
                  <th className="py-2.5 px-5 text-left">{FRAMEWORK_META[framework].label} Alignment</th>
                  <th className="py-2.5 px-5 text-left"></th>
                </tr>
              </thead>
              <tbody>
                {agents.map((ag) => {
                  const normalized = normalizeAgentStatus(ag.status);
                  const sca = scaByAgent.get(ag.id);
                  const alertRow = alertByAgent.get(ag.id);
                  const violated = alertRow?.violatedControls.length ?? 0;

                  return (
                    <tr key={ag.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-5">
                        <span className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${deviceStatusDot[normalized] ?? 'bg-slate-600'}`} />
                          <span className="text-xs text-slate-500 dark:text-slate-400 capitalize">{normalized.replace('_', ' ')}</span>
                        </span>
                      </td>
                      <td className="py-3 px-5 text-sm">
                        <button onClick={() => setSelectedAgent(ag)} className="text-slate-900 dark:text-white font-medium hover:text-cyan-400 transition-colors text-left">
                          {ag.name}
                        </button>
                      </td>
                      <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{formatOs(ag.os)}</td>
                      <td className="py-3 px-5 text-xs">
                        {framework === 'cis' ? (
                          sca && sca.ok && sca.total !== undefined && sca.total > 0 ? (
                            <span className="flex items-center gap-2">
                              <span className={`font-bold ${scoreColor(sca.score ?? null)}`}>{sca.score}%</span>
                              <span className="text-slate-400 dark:text-slate-500">{sca.pass} pass / {sca.fail} fail</span>
                            </span>
                          ) : (
                            <span className="text-slate-400 dark:text-slate-600">No CIS scan data</span>
                          )
                        ) : violated === 0 ? (
                          <span className="flex items-center gap-1.5 text-emerald-400">
                            <CheckCircle className="w-3.5 h-3.5" /> No violations
                          </span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-red-400">
                            <AlertTriangle className="w-3.5 h-3.5" /> {violated} control{violated === 1 ? '' : 's'} flagged
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-5 text-right">
                        <button onClick={() => setSelectedAgent(ag)} className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap">
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {framework !== 'cis' && (
        <div className="flex items-start gap-2 px-1">
          <Info className="w-3.5 h-3.5 text-slate-400 dark:text-slate-600 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-slate-400 dark:text-slate-600">
            {FRAMEWORK_META[framework].label} alignment reflects Wazuh alert activity mapped to regulatory
            controls over the selected window — it is not a certified compliance audit.
          </p>
        </div>
      )}

      {selectedAgent && (
        <ComplianceDetailModal
          agent={selectedAgent}
          framework={framework}
          days={days}
          scaSummary={scaByAgent.get(selectedAgent.id)}
          onClose={() => setSelectedAgent(null)}
        />
      )}
    </div>
  );
};

export default CompliancePanel;
