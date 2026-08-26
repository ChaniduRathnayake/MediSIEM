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
import React, { useCallback, useState } from 'react';
import { Network, Globe, Search, Radar, ListChecks, FolderKanban, Database, ScrollText } from 'lucide-react';
import { useToast } from '../../../context/ToastContext';
import { useAuth } from '../../../context/AuthContext';
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

type IpReputationTab = 'overview' | 'investigate' | 'threat-hunt' | 'lists' | 'cases' | 'log-sources' | 'audit';

const TAB_META: Record<IpReputationTab, { label: string; icon: React.ReactNode }> = {
  overview:      { label: 'Overview',           icon: <Globe className="w-3.5 h-3.5" /> },
  investigate:   { label: 'Investigate',        icon: <Search className="w-3.5 h-3.5" /> },
  'threat-hunt': { label: 'Threat Hunt',        icon: <Radar className="w-3.5 h-3.5" /> },
  lists:         { label: 'Intelligence Lists', icon: <ListChecks className="w-3.5 h-3.5" /> },
  cases:         { label: 'Cases',              icon: <FolderKanban className="w-3.5 h-3.5" /> },
  'log-sources': { label: 'Log Sources',        icon: <Database className="w-3.5 h-3.5" /> },
  audit:         { label: 'Audit',              icon: <ScrollText className="w-3.5 h-3.5" /> },
};

const TAB_ORDER: IpReputationTab[] = ['overview', 'investigate', 'threat-hunt', 'lists', 'cases', 'log-sources', 'audit'];

const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];

const IpReputationPanel: React.FC = () => {
  const { showToast } = useToast();
  const { user } = useAuth();
  // The original standalone app had no login system at all, so every analyst
  // action was hardcoded to a fake 'analyst01' actor. MediSIEM has a real
  // logged-in session here — attribute actions to it instead, same as the
  // rest of the app's audit trail does.
  const actor = user?.email || user?.name || 'unknown-analyst';
  const [tab, setTab] = useState<IpReputationTab>('overview');

  // ── Shared investigation state ────────────────────────────────────────────
  const [ip, setIp] = useState('8.8.8.8');
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
      const lookup = await lookupIp(cleanIp);
      setResult(lookup);

      try {
        const historyData = await getIntelligenceHistory(cleanIp);
        setHistory(historyData.history || []);
      } catch {
        setHistory([]);
      }

      try {
        const analystResp = await getAnalystIntelligence(cleanIp);
        setAnalystData(analystResp.analyst_intelligence);
      } catch {
        setAnalystData(null);
      }

      try {
        const correlationData = await getCorrelation(cleanIp);
        setCorrelation(correlationData);
      } catch {
        setCorrelation(null);
      }

      try {
        const wazuhData = await getWazuhEvidence(cleanIp, 20);
        setWazuh(wazuhData);
      } catch {
        setWazuh(null);
      }

      try {
        const operationalData = await getOperationalAssessment(cleanIp, 100, 20);
        setOperational(operationalData);
      } catch {
        setOperational(null);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'IP investigation failed.');
      setResult(null);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ip]);

  const handleSetList = useCallback(async (listType: string) => {
    if (!result) return;
    const reason = window.prompt(`Reason for adding ${result.ip} to ${listType} list:`, 'Added from MedShield IP investigation');
    if (reason === null) return;

    try {
      await setReputationList({ ip: result.ip, list_type: listType, reason, actor });
      showToast({ title: 'Internal intelligence updated', message: `${result.ip} added to the ${listType} list.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Update failed', message: err instanceof Error ? err.message : 'Unable to update internal intelligence.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleSetVerdict = useCallback(async (verdict: string) => {
    if (!result) return;
    const reason = window.prompt(`Reason for analyst verdict: ${verdict}`, '');
    if (reason === null) return;

    try {
      await setAnalystVerdict({ ip: result.ip, verdict, reason, actor });
      showToast({ title: 'Verdict saved', message: `${result.ip} marked ${verdict}.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Save failed', message: err instanceof Error ? err.message : 'Unable to save analyst verdict.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleAddNote = useCallback(async () => {
    if (!result) return;
    const note = window.prompt('Enter investigation note:');
    if (!note) return;

    try {
      await addAnalystNote({ ip: result.ip, note, actor });
      showToast({ title: 'Note saved', message: `Investigation note added for ${result.ip}.`, severity: 'info' });
      await investigate();
    } catch (err: unknown) {
      showToast({ title: 'Save failed', message: err instanceof Error ? err.message : 'Unable to save analyst note.', severity: 'high' });
    }
  }, [result, investigate, showToast]);

  const handleCreateCase = useCallback(async () => {
    if (!result) return;

    const title = window.prompt('Case title:', `Investigate ${result.ip}`);
    if (!title) return;

    const description = window.prompt(
      'Case description:',
      `Created from MedShield IP investigation. External reputation risk: ${result.risk_level || 'Unknown'}.`
    );
    if (description === null) return;

    const defaultSeverity = SEVERITIES.includes(result.risk_level ?? '') ? (result.risk_level as string) : 'Medium';
    const severityInput = window.prompt('Severity: Low, Medium, High or Critical', defaultSeverity);
    if (severityInput === null) return;

    const severity = severityInput.trim();
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
