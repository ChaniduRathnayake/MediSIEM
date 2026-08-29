// MedShield IP Reputation Intelligence — ported from the standalone
// medisiem-ip-reputation React app into a first-class MediSIEM tab. This
// component replaces that app's dark-sidebar nav (Overview / IP Investigation /
// Threat Hunt / Intelligence Lists / Cases / Log Sources / Audit) with an
// internal sub-tab bar, styled like CompliancePanel.tsx's FRAMEWORK_META
// button-group pattern, inside this one panel.
//
// The investigation state (ip/result/history/analystData/correlation/
// operational/wazuh/loading/error) and its mutation handlers (setList/
// setVerdict/addNote/createCase) are owned here — one level above
// InvestigationView — so the Threat Hunt tab's "Investigate Src/Dst" links can
// switch to the Investigate tab AND kick off a lookup for that IP in one call,
// exactly like the original App.jsx's `onInvestigate` callback.
//
// The "Live" tab additionally embeds the real-time MedShield ML feed
// (LiveDashboardView) above the investigation workspace, so clicking
// "Investigate" on a live row drives the same shared investigation state and
// scrolls straight into the results — one continuous live-monitor-to-deep-dive
// flow instead of a separate disconnected page.
import React, { useCallback, useState } from 'react';
import { Network, Globe, Search, Radar, ListChecks, FolderKanban, Database, ScrollText } from 'lucide-react';
import { useToast } from '../../../context/ToastContext';
import { useAuth } from '../../../context/AuthContext';
import LiveDashboardView from './LiveDashboardView';
import OverviewView from './OverviewView';
import InvestigationView from './InvestigationView';
import ThreatHuntView from './ThreatHuntView';
import IntelligenceListsView from './IntelligenceListsView';
import CasesView from './CasesView';
import LogSourcesView from './LogSourcesView';
import AuditView from './AuditView';
import {
  lookupIp, getIntelligenceHistory, getAnalystIntelligence, getCorrelation,
  getWazuhEvidence, getOperationalAssessment, setReputationList, setAnalystVerdict,
  addAnalystNote, createCase,
} from './ipReputationApi';
import type {
  ReputationLookupResponse, HistoryItem, AnalystIntelligence, CorrelationResult,
  WazuhEvidenceResult, OperationalResult,
} from './ipReputationApi';

type IpReputationTab = 'live' | 'overview' | 'investigate' | 'threat-hunt' | 'lists' | 'cases' | 'log-sources' | 'audit';

const TAB_META: Record<IpReputationTab, { label: string; icon: React.ReactNode }> = {
  live:          { label: 'Live Dashboard',     icon: <Network className="w-3.5 h-3.5" /> },
  overview:      { label: 'Overview',           icon: <Globe className="w-3.5 h-3.5" /> },
  investigate:   { label: 'Investigate',        icon: <Search className="w-3.5 h-3.5" /> },
  'threat-hunt': { label: 'Threat Hunt',        icon: <Radar className="w-3.5 h-3.5" /> },
  lists:         { label: 'Intelligence Lists', icon: <ListChecks className="w-3.5 h-3.5" /> },
  cases:         { label: 'Cases',              icon: <FolderKanban className="w-3.5 h-3.5" /> },
  'log-sources': { label: 'Log Sources',        icon: <Database className="w-3.5 h-3.5" /> },
  audit:         { label: 'Audit',              icon: <ScrollText className="w-3.5 h-3.5" /> },
};

const TAB_ORDER: IpReputationTab[] = ['live', 'overview', 'investigate', 'threat-hunt', 'lists', 'cases', 'log-sources', 'audit'];

const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];

// Anchors within the Live tab's combined monitor+investigate layout — lets
// the quick-jump nav below skip straight to a section instead of scrolling
// past the live feed table (10 columns, forces its own horizontal scroll)
// to reach the investigation workspace underneath it.
const LIVE_SECTIONS: { id: string; label: string }[] = [
  { id: 'live-overview', label: 'Overview' },
  { id: 'live-feed', label: 'Live Feed' },
  { id: 'medshield-investigation', label: 'Investigate' },
];

const IpReputationPanel: React.FC = () => {
  const { showToast } = useToast();
  const { user } = useAuth();
  // The original standalone app had no login system at all, so every analyst
  // action was hardcoded to a fake 'analyst01' actor. MediSIEM has a real
  // logged-in session here — attribute actions to it instead, same as the
  // rest of the app's audit trail does.
  const actor = user?.email || user?.name || 'unknown-analyst';
  const [tab, setTab] = useState<IpReputationTab>('live');

  // ── Shared investigation state ────────────────────────────────────────────
  const [ip, setIp] = useState('');
  const [result, setResult] = useState<ReputationLookupResponse | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [analystData, setAnalystData] = useState<AnalystIntelligence | null>(null);
  const [correlation, setCorrelation] = useState<CorrelationResult | null>(null);
  const [operational, setOperational] = useState<OperationalResult | null>(null);
  const [wazuh, setWazuh] = useState<WazuhEvidenceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const investigate = useCallback(async (targetIp?: string) => {
    const cleanIp = (typeof targetIp === 'string' ? targetIp : ip).trim();
    if (typeof targetIp === 'string') setIp(cleanIp);
    if (!cleanIp) return;

    setWazuh(null);
    setCorrelation(null);
    setOperational(null);
    setLoading(true);
    setError('');

    try {
      // These six calls are all keyed off cleanIp alone (none depends on
      // another's result), so run them concurrently instead of chaining
      // awaits — sequentially, the wazuh/operational calls each pay a
      // ~10s timeout against an unreachable Wazuh indexer, turning one
      // investigation into a ~25s wait instead of the ~11s the slowest
      // single call actually takes.
      const [lookupSettled, historySettled, analystSettled, correlationSettled, wazuhSettled, operationalSettled] =
        await Promise.allSettled([
          lookupIp(cleanIp),
          getIntelligenceHistory(cleanIp),
          getAnalystIntelligence(cleanIp),
          getCorrelation(cleanIp),
          getWazuhEvidence(cleanIp, 20),
          getOperationalAssessment(cleanIp, 1000, 20),
        ]);

      if (lookupSettled.status === 'rejected') throw lookupSettled.reason;
      setResult(lookupSettled.value);

      setHistory(historySettled.status === 'fulfilled' ? (historySettled.value.history || []) : []);
      setAnalystData(analystSettled.status === 'fulfilled' ? analystSettled.value.analyst_intelligence : null);
      setCorrelation(correlationSettled.status === 'fulfilled' ? correlationSettled.value : null);
      setWazuh(wazuhSettled.status === 'fulfilled' ? wazuhSettled.value : null);
      setOperational(operationalSettled.status === 'fulfilled' ? operationalSettled.value : null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'IP investigation failed.');
      setResult(null);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ip]);

  const handleSetList = useCallback(async (listType: string, reason: string) => {
    if (!result) return;

    try {
      await setReputationList({ ip: result.ip, list_type: listType, reason, actor });
      showToast({ title: 'Internal intelligence updated', message: `${result.ip} added to the ${listType} list.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Update failed', message: err instanceof Error ? err.message : 'Unable to update internal intelligence.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleSetVerdict = useCallback(async (verdict: string, reason: string) => {
    if (!result) return;

    try {
      await setAnalystVerdict({ ip: result.ip, verdict, reason, actor });
      showToast({ title: 'Verdict saved', message: `${result.ip} marked ${verdict}.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Save failed', message: err instanceof Error ? err.message : 'Unable to save analyst verdict.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleAddNote = useCallback(async (note: string) => {
    if (!result || !note.trim()) return;

    try {
      await addAnalystNote({ ip: result.ip, note, actor });
      showToast({ title: 'Note saved', message: `Investigation note added for ${result.ip}.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Save failed', message: err instanceof Error ? err.message : 'Unable to save analyst note.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleCreateCase = useCallback(async (title: string, description: string, severity: string) => {
    if (!result || !title.trim()) return;

    if (!SEVERITIES.includes(severity)) {
      showToast({ title: 'Invalid severity', message: 'Severity must be Low, Medium, High or Critical.', severity: 'high' });
      return;
    }

    try {
      await createCase({ ip: result.ip, title, description, severity, actor });
      showToast({ title: 'Case created', message: `Investigation case created for ${result.ip}.`, severity: 'info' });
      setTab('cases');
    } catch (err: unknown) {
      showToast({ title: 'Case creation failed', message: err instanceof Error ? err.message : 'Unable to create investigation case.', severity: 'high' });
    }
  }, [result, showToast]);

  const handleThreatHuntInvestigate = useCallback((targetIp: string) => {
    setTab('investigate');
    void investigate(targetIp);
  }, [investigate]);

  // Live feed rows drive the same shared investigation state as every other
  // entry point, then smooth-scroll down into the results panel that already
  // renders below the live table on this tab — one continuous flow instead of
  // a tab switch.
  const handleLiveInvestigate = useCallback((targetIp: string) => {
    void investigate(targetIp).then(() => {
      window.setTimeout(() => {
        document
          .getElementById('medshield-investigation')
          ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 100);
    });
  }, [investigate]);

  const scrollToSection = useCallback((id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, []);

  return (
    <div className="p-5 space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
          <Network className="w-4.5 h-4.5 text-cyan-500 dark:text-cyan-400" /> IP Reputation Intelligence
        </h2>
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
          External reputation, internal intelligence, MIRS correlation and analyst context for any IP address.
        </p>
      </div>

      <div className="flex items-center gap-1.5 flex-wrap">
        {TAB_ORDER.map((key) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              tab === key
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            {TAB_META[key].icon} {TAB_META[key].label}
          </button>
        ))}
      </div>

      {tab === 'live' && (
        <div className="space-y-10">
          <nav className="sticky top-0 z-10 -mx-5 flex items-center gap-1 border-b border-slate-200 bg-white/90 px-5 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-950/90">
            <span className="mr-1 text-[10px] font-semibold uppercase tracking-wide text-slate-400">Jump to</span>
            {LIVE_SECTIONS.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => scrollToSection(s.id)}
                className="rounded-md px-2 py-1 text-[11px] font-medium text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white"
              >
                {s.label}
              </button>
            ))}
          </nav>

          <LiveDashboardView onInvestigate={handleLiveInvestigate} />

          <section
            id="medshield-investigation"
            className="scroll-mt-20 border-t border-slate-200 pt-8 dark:border-slate-800"
          >
            <div className="mb-5">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                MedShield IP Reputation Intelligence
              </h2>
              <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
                Multi-source IP investigation, local ML correlation and analyst workflow
              </p>
              <div className="mt-4 inline-flex rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300">
                Investigate
              </div>
            </div>

            <InvestigationView
              ip={ip}
              onIpChange={setIp}
              result={result}
              history={history}
              analystData={analystData}
              correlation={correlation}
              operational={operational}
              wazuh={wazuh}
              loading={loading}
              error={error}
              onInvestigate={investigate}
              onSetList={handleSetList}
              onSetVerdict={handleSetVerdict}
              onAddNote={handleAddNote}
              onCreateCase={handleCreateCase}
            />
          </section>
        </div>
      )}

      {tab === 'overview' && <OverviewView />}

      {tab === 'investigate' && (
        <InvestigationView
          ip={ip}
          onIpChange={setIp}
          result={result}
          history={history}
          analystData={analystData}
          correlation={correlation}
          operational={operational}
          wazuh={wazuh}
          loading={loading}
          error={error}
          onInvestigate={investigate}
          onSetList={handleSetList}
          onSetVerdict={handleSetVerdict}
          onAddNote={handleAddNote}
          onCreateCase={handleCreateCase}
        />
      )}

      {tab === 'threat-hunt' && <ThreatHuntView onInvestigate={handleThreatHuntInvestigate} />}
      {tab === 'lists' && <IntelligenceListsView />}
      {tab === 'cases' && <CasesView />}
      {tab === 'log-sources' && <LogSourcesView />}
      {tab === 'audit' && <AuditView />}
    </div>
  );
};

export default IpReputationPanel;
