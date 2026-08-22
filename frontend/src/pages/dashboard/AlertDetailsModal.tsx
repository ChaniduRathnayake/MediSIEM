// "100% of the alert" — renders whichever shape it's given (EnrichedAlert from the ML/CAS
// pipeline, or WazuhAlertRow) plus a raw-JSON fallback so nothing is ever hidden.
import React, { useEffect, useState } from 'react';
import { X, ChevronDown, ChevronRight, Terminal, MapPin, Tag, ShieldCheck, Brain, Info, Sparkles, Loader2, MessageSquare, Send, GitBranch, Printer, Wand2 } from 'lucide-react';
import type { EnrichedAlert, AlertNote } from '../../services/alertsApi';
import { apiTriageAlert, apiGetAlertNotes, apiAddAlertNote, apiSummarizeNotes } from '../../services/alertsApi';
import type { WazuhAlertRow } from './complianceApi';
import { casToSeverity } from '../../utils/chartData';
import type { Severity } from '../../utils/chartData';
import TopBarChart from '../../components/charts/TopBarChart';
import SeverityBadge from '../../components/SeverityBadge';

type Props =
  | {
      kind: 'ml';
      alert: EnrichedAlert;
      onClose: () => void;
      token?: string | null;
      // Used only to compute "other activity on this device" — omitted callers just skip that section.
      allAlerts?: EnrichedAlert[];
    }
  | { kind: 'wazuh'; alert: WazuhAlertRow; onClose: () => void };

const SEV_CLASS: Record<Severity, string> = {
  CRITICAL: 'text-red-500 dark:text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-500 dark:text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/30',
  LOW: 'text-blue-500 dark:text-blue-400 bg-blue-500/10 border-blue-500/30',
};

const wazuhSeverity = (level: number | null): Severity => {
  const l = level ?? 0;
  if (l >= 12) return 'CRITICAL';
  if (l >= 8) return 'HIGH';
  if (l >= 5) return 'MEDIUM';
  return 'LOW';
};

// Matches CasWeightsSettingsPanel.tsx's PROFILE_TABS labels — which named
// weight profile (see ai_server/src/cas_config.py's SCENARIO_WEIGHT_PROFILES)
// actually produced this alert's CAS score.
const SCENARIO_LABELS: Record<string, string> = {
  default: 'Default (AHP baseline)',
  icu_critical_care: 'ICU / Critical Care',
  general_ward_admin: 'General Ward / Admin',
  hospital_wide_mixed: 'Hospital-Wide Mixed',
  custom: 'Custom (admin override)',
};
const formatScenario = (key: string): string => SCENARIO_LABELS[key] ?? key;

const KeyValueGrid: React.FC<{ rows: [string, React.ReactNode][] }> = ({ rows }) => (
  <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2.5">
    {rows.map(([label, value]) => (
      <div key={label} className="flex items-center justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-800/60 text-sm">
        <dt className="text-slate-400 dark:text-slate-500 flex-shrink-0">{label}</dt>
        <dd className="text-slate-900 dark:text-white text-right break-all font-mono text-xs">{value}</dd>
      </div>
    ))}
  </dl>
);

const SectionTitle: React.FC<{ icon: React.ReactNode; children: React.ReactNode }> = ({ icon, children }) => (
  <h3 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
    {icon} {children}
  </h3>
);

const BadgeRow: React.FC<{ items: string[]; empty?: string }> = ({ items, empty = '—' }) =>
  items.length === 0 ? (
    <span className="text-xs text-slate-400 dark:text-slate-600">{empty}</span>
  ) : (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it) => (
        <span key={it} className="text-xs px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
          {it}
        </span>
      ))}
    </div>
  );

const RawJson: React.FC<{ data: unknown }> = ({ data }) => {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
      >
        {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        Raw JSON (every field the backend sent)
      </button>
      {open && (
        <pre className="mt-2 p-3 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
};

// Surfaced explicitly (not buried in the generic field list) — source/destination is
// what an analyst looks for first.
function extractNetworkFields(data: Record<string, unknown> | null): { source: string | null; destination: string | null } {
  if (!data) return { source: null, destination: null };
  const srcIp = data.srcip ?? data.src_ip ?? null;
  const srcPort = data.srcport ?? data.src_port ?? null;
  const dstIp = data.dstip ?? data.dst_ip ?? null;
  const dstPort = data.dstport ?? data.dst_port ?? null;
  const source = srcIp ? `${srcIp}${srcPort ? ':' + srcPort : ''}` : null;
  const destination = dstIp ? `${dstIp}${dstPort ? ':' + dstPort : ''}` : null;
  return { source: source as string | null, destination: destination as string | null };
}

// Fired on demand (spends the configured Gemini key per click). Shows the backend's
// error text verbatim — it's what tells the analyst what to do next.
const AiTriageSection: React.FC<{ alertId: string; token?: string | null }> = ({ alertId, token }) => {
  const [state, setState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [explanation, setExplanation] = useState('');
  const [error, setError] = useState('');

  const ask = async () => {
    if (!token) return;
    setState('loading');
    setError('');
    try {
      const result = await apiTriageAlert(token, alertId);
      setExplanation(result.explanation);
      setState('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI triage assistant request failed.');
      setState('error');
    }
  };

  return (
    <div>
      <SectionTitle icon={<Sparkles className="w-3.5 h-3.5" />}>AI triage assistant</SectionTitle>
      {state === 'idle' && (
        <button
          onClick={ask}
          disabled={!token}
          className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400 hover:bg-violet-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Sparkles className="w-3.5 h-3.5" /> Ask AI
        </button>
      )}
      {state === 'loading' && (
        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Asking AI assistant…
        </div>
      )}
      {state === 'error' && (
        <div>
          <p className="text-xs text-red-500 dark:text-red-400">{error}</p>
          <button onClick={ask} className="mt-1.5 text-xs text-violet-600 dark:text-violet-400 hover:underline">
            Retry
          </button>
        </div>
      )}
      {state === 'done' && (
        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed bg-violet-500/5 border border-violet-500/20 rounded-lg px-3 py-2.5 whitespace-pre-wrap">
          {explanation}
        </p>
      )}
    </div>
  );
};

// AbuseIPDB's 0-100 "confidence of abuse" scale — 50+ is their threshold for "likely malicious".
function reputationBadge(score: number): { label: string; className: string } {
  if (score >= 50) return { label: `Malicious (${score})`, className: 'text-red-500 dark:text-red-400 bg-red-500/10 border-red-500/30' };
  if (score >= 15) return { label: `Suspicious (${score})`, className: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/30' };
  return { label: `Clean (${score})`, className: 'text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border-emerald-500/30' };
}

const RELATED_WINDOW_MS = 2 * 60 * 60 * 1000;

const RelatedActivitySection: React.FC<{ alert: EnrichedAlert; allAlerts: EnrichedAlert[] }> = ({ alert, allAlerts }) => {
  const t = new Date(alert.timestamp).getTime();
  const related = allAlerts
    .filter((a) => a.id !== alert.id && a.agent === alert.agent && Math.abs(new Date(a.timestamp).getTime() - t) <= RELATED_WINDOW_MS)
    .sort((a, b) => Math.abs(new Date(a.timestamp).getTime() - t) - Math.abs(new Date(b.timestamp).getTime() - t));

  return (
    <div>
      <SectionTitle icon={<GitBranch className="w-3.5 h-3.5" />}>Related activity on {alert.agent}</SectionTitle>
      {related.length === 0 ? (
        <p className="text-xs text-slate-400 dark:text-slate-500">No other alerts on this device within 2 hours of this one.</p>
      ) : (
        <div className="space-y-1.5">
          {related.slice(0, 6).map((r) => {
            const sev = casToSeverity(r.CAS);
            return (
              <div key={r.id} className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                <SeverityBadge severity={sev} />
                <span className="text-xs text-slate-700 dark:text-slate-300 truncate flex-1">{r.label !== 'Unclassified' ? r.label : r.ruleDescription}</span>
                <span className="text-[10px] text-slate-400 dark:text-slate-600 whitespace-nowrap">{new Date(r.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
            );
          })}
          {related.length > 6 && <p className="text-[11px] text-slate-400 dark:text-slate-500">+{related.length - 6} more</p>}
        </div>
      )}
    </div>
  );
};

// Notes fetched by the parent (not here) so the printable single-incident report can include them too.
const NotesSection: React.FC<{
  alertId: string;
  token?: string | null;
  notes: AlertNote[];
  loading: boolean;
  onNoteAdded: (note: AlertNote) => void;
}> = ({ alertId, token, notes, loading, onNoteAdded }) => {
  const [text, setText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [summaryState, setSummaryState] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [summary, setSummary] = useState('');
  const [summaryError, setSummaryError] = useState('');

  const submit = async () => {
    if (!token || !text.trim()) return;
    setSubmitting(true);
    setError('');
    try {
      const { note } = await apiAddAlertNote(token, alertId, text.trim());
      onNoteAdded(note);
      setText('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add note.');
    } finally {
      setSubmitting(false);
    }
  };

  const summarize = async () => {
    if (!token) return;
    setSummaryState('loading');
    setSummaryError('');
    try {
      const { summary: s } = await apiSummarizeNotes(token, alertId);
      setSummary(s);
      setSummaryState('done');
    } catch (err) {
      setSummaryError(err instanceof Error ? err.message : 'AI assistant request failed.');
      setSummaryState('error');
    }
  };

  if (!token) return null;

  return (
    <div>
      <div className="flex items-center justify-between gap-2 mb-2">
        <SectionTitle icon={<MessageSquare className="w-3.5 h-3.5" />}>Investigation notes</SectionTitle>
        {notes.length > 0 && summaryState === 'idle' && (
          <button
            onClick={summarize}
            className="flex-shrink-0 flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400 hover:bg-violet-500/20 transition-colors"
          >
            <Wand2 className="w-3 h-3" /> Summarize case
          </button>
        )}
      </div>
      {summaryState === 'loading' && (
        <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 mb-3">
          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Summarizing…
        </div>
      )}
      {summaryState === 'error' && (
        <div className="mb-3">
          <p className="text-xs text-red-500 dark:text-red-400">{summaryError}</p>
          <button onClick={summarize} className="mt-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">Retry</button>
        </div>
      )}
      {summaryState === 'done' && (
        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed bg-violet-500/5 border border-violet-500/20 rounded-lg px-3 py-2.5 whitespace-pre-wrap mb-3">
          {summary}
        </p>
      )}
      {loading ? (
        <div className="flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading notes…
        </div>
      ) : (
        <div className="space-y-2 mb-3">
          {notes.length === 0 ? (
            <p className="text-xs text-slate-400 dark:text-slate-500">No notes yet — jot down what you're checking as you go.</p>
          ) : (
            notes.map((n) => (
              <div key={n.id} className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between gap-2 mb-0.5">
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">{n.author.name}</span>
                  <span className="text-[10px] text-slate-400 dark:text-slate-600">{new Date(n.createdAt).toLocaleString()}</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 whitespace-pre-wrap break-words">{n.text}</p>
              </div>
            ))
          )}
        </div>
      )}
      <div className="flex items-start gap-2">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Add a note — type @Name to notify a teammate"
          rows={2}
          maxLength={2000}
          className="flex-1 px-2.5 py-1.5 text-xs bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60 resize-y"
        />
        <button
          onClick={submit}
          disabled={submitting || !text.trim()}
          className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 transition-colors"
        >
          {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
        </button>
      </div>
      {error && <p className="text-xs text-red-500 dark:text-red-400 mt-1.5">{error}</p>}
    </div>
  );
};

const MlAlertBody: React.FC<{
  alert: EnrichedAlert; token?: string | null; allAlerts?: EnrichedAlert[];
  notes: AlertNote[]; notesLoading: boolean; onNoteAdded: (note: AlertNote) => void;
}> = ({ alert, token, allAlerts, notes, notesLoading, onNoteAdded }) => {
  const severity = casToSeverity(alert.CAS);
  return (
    <div className="space-y-5">
      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Identity &amp; timing</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Alert ID', alert.id],
            ['Timestamp', new Date(alert.timestamp).toLocaleString()],
            ['Severity', <span key="s" className={`px-2 py-0.5 rounded border font-bold ${SEV_CLASS[severity]}`}>{severity}</span>],
            ['Action', alert.action],
            ['Status', alert.assignedTo ? `Assigned to ${alert.assignedTo.name}` : 'Unassigned'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<MapPin className="w-3.5 h-3.5" />}>Source &amp; asset</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Source IP', alert.src_ip ?? '— not captured for this alert —'],
            ...(typeof alert.ipReputationScore === 'number'
              ? ([['IP reputation', (() => {
                  const b = reputationBadge(alert.ipReputationScore);
                  return <span className={`px-2 py-0.5 rounded border font-bold ${b.className}`}>{b.label}</span>;
                })()]] as [string, React.ReactNode][])
              : []),
            ['Destination', 'not tracked — this pipeline classifies per-device behavior, not connection pairs'],
            ['Device', alert.agent],
            ['Device type', alert.deviceType ?? '— not onboarded in the medical device inventory —'],
            ['Device criticality', alert.deviceCriticality ?? '—'],
            ['Department', alert.department],
            ['Cluster', alert.cluster],
          ]}
        />
      </div>

      {alert.mitre && alert.mitre.id.length > 0 && (
        <div>
          <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>MITRE ATT&amp;CK mapping</SectionTitle>
          <KeyValueGrid
            rows={[
              ['Technique ID', alert.mitre.id.join(', ')],
              ['Technique', alert.mitre.technique.join(', ') || '—'],
              ['Tactic', alert.mitre.tactic.join(', ') || '—'],
            ]}
          />
        </div>
      )}

      <div>
        <SectionTitle icon={<Brain className="w-3.5 h-3.5" />}>Why it's classified this way</SectionTitle>
        <div className="grid grid-cols-5 gap-2 mb-3">
          {([
            ['TR', alert.TR_score, 'Threat Risk — RF classification confidence'],
            ['CC', alert.CC_score, 'Clinical Criticality — how life-critical this device is'],
            ['TS', alert.TS_score, 'Time Sensitivity — Isolation Forest anomaly + time of day'],
            ['AE', alert.AE_score, 'Active Exploitation — known-exploited CVE match'],
            ['TC', alert.TC_score, 'Temporal Context — shift-based rule'],
          ] as [string, number, string][]).map(([label, value, hint]) => (
            <div key={label} className="px-2 py-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800" title={hint}>
              <div className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</div>
              <div className="text-sm font-mono text-slate-900 dark:text-white mt-0.5">{value.toFixed(1)}</div>
            </div>
          ))}
        </div>
        <KeyValueGrid
          rows={[
            ['Clinical Alert Score', alert.CAS.toFixed(2)],
            ...(typeof alert.CVSS === 'number'
              ? ([['CVSS-equivalent baseline', <span key="cvss" title="Depends only on attack type — never device or time. Shown for direct comparison against CAS.">{alert.CVSS.toFixed(1)} <span className="text-slate-400 dark:text-slate-600 font-normal">(clinically blind, for comparison)</span></span>]] as [string, React.ReactNode][])
              : []),
            ['Label', alert.label],
            ['Confidence', typeof alert.confidence === 'number' ? `${(alert.confidence * 100).toFixed(1)}%` : 'n/a (rule.level fallback)'],
            ...(alert.scenario ? ([['Scoring profile', formatScenario(alert.scenario)]] as [string, React.ReactNode][]) : []),
          ]}
        />
        {alert.shap_top_features && alert.shap_top_features.length > 0 ? (
          <div className="mt-3">
            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1.5">
              SHAP explanation — which features pushed the model toward (
              <span className="text-red-500 dark:text-red-400">red</span>) or away from (
              <span className="text-blue-500 dark:text-blue-400">blue</span>) predicting "{alert.label}":
            </p>
            <div style={{ height: Math.max(60, alert.shap_top_features.length * 28) }}>
              <TopBarChart
                data={alert.shap_top_features.map((f) => ({ label: f.feature, value: f.value }))}
                colorOf={(entry) => (entry.value >= 0 ? '#ef4444' : '#3b82f6')}
              />
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
            <span className="text-slate-400 dark:text-slate-500">Explanation: </span>{alert.explanation}
          </p>
        )}
      </div>

      <AiTriageSection alertId={alert.id} token={token} />

      {allAlerts && <RelatedActivitySection alert={alert} allAlerts={allAlerts} />}

      <NotesSection alertId={alert.id} token={token} notes={notes} loading={notesLoading} onNoteAdded={onNoteAdded} />

      <div>
        <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>Matched detection rules</SectionTitle>
        <BadgeRow items={(alert.matchedRules ?? []).map((r) => r.name)} empty="No custom rule matched — ML detection only" />
      </div>

      {alert.flow && (
        <div>
          <SectionTitle icon={<Terminal className="w-3.5 h-3.5" />}>Raw flow features (all 45, as scored)</SectionTitle>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
            <table className="w-full text-xs">
              <tbody>
                {Object.entries(alert.flow).map(([k, v], i) => (
                  <tr key={k} className={i % 2 === 0 ? 'bg-slate-50 dark:bg-slate-900/40' : ''}>
                    <td className="py-1 px-2.5 text-slate-500 dark:text-slate-400 whitespace-nowrap">{k}</td>
                    <td className="py-1 px-2.5 text-slate-900 dark:text-white font-mono text-right">{String(v)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <RawJson data={alert} />
    </div>
  );
};

const WazuhAlertBody: React.FC<{ alert: WazuhAlertRow }> = ({ alert }) => {
  const severity = wazuhSeverity(alert.ruleLevel);
  const { source, destination } = extractNetworkFields(alert.data);
  const complianceBadges: { label: string; values: string[] }[] = [
    { label: 'HIPAA', values: alert.compliance?.hipaa ?? [] },
    { label: 'PCI-DSS', values: alert.compliance?.pciDss ?? [] },
    { label: 'GDPR', values: alert.compliance?.gdpr ?? [] },
    { label: 'NIST 800-53', values: alert.compliance?.nist80053 ?? [] },
    { label: 'TSC', values: alert.compliance?.tsc ?? [] },
    { label: 'GPG13', values: alert.compliance?.gpg13 ?? [] },
  ].filter((c) => c.values.length > 0);

  return (
    <div className="space-y-5">
      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Identity &amp; timing</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Alert ID', alert.id],
            ['Timestamp', alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'],
            ['Severity', <span key="s" className={`px-2 py-0.5 rounded border font-bold ${SEV_CLASS[severity]}`}>{severity}</span>],
            ['Rule ID', alert.ruleId ?? '—'],
            ['Rule level', alert.ruleLevel ?? '—'],
            ['Fired recently', alert.ruleFiredTimes !== null ? `${alert.ruleFiredTimes}x` : '—'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<MapPin className="w-3.5 h-3.5" />}>Source &amp; destination</SectionTitle>
        <KeyValueGrid
          rows={[
            ['Agent', `${alert.agentName ?? '—'} (#${alert.agentId ?? '—'})`],
            ['Agent IP', alert.agentIp ?? '—'],
            ['Source (from log)', source ?? '— not present in this alert\'s decoded fields —'],
            ['Destination (from log)', destination ?? '— not present in this alert\'s decoded fields —'],
            ['Location', alert.location ?? '—'],
            ['Decoder', alert.decoder ?? '—'],
          ]}
        />
      </div>

      <div>
        <SectionTitle icon={<Terminal className="w-3.5 h-3.5" />}>Raw log</SectionTitle>
        <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 whitespace-pre-wrap break-all">
          {alert.fullLog ?? '— not captured for this alert —'}
        </pre>
      </div>

      <div>
        <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Full description</SectionTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">{alert.ruleDescription ?? '—'}</p>
      </div>

      {alert.data && Object.keys(alert.data).length > 0 && (
        <div>
          <SectionTitle icon={<Info className="w-3.5 h-3.5" />}>Decoded fields</SectionTitle>
          <KeyValueGrid rows={Object.entries(alert.data).map(([k, v]) => [k, String(v)])} />
        </div>
      )}

      <div>
        <SectionTitle icon={<Tag className="w-3.5 h-3.5" />}>Rule groups</SectionTitle>
        <BadgeRow items={alert.ruleGroups} />
      </div>

      {complianceBadges.length > 0 && (
        <div>
          <SectionTitle icon={<ShieldCheck className="w-3.5 h-3.5" />}>Compliance mapping</SectionTitle>
          <div className="flex flex-wrap gap-1.5">
            {complianceBadges.map((c) => (
              <span
                key={c.label}
                title={c.values.join(', ')}
                className="text-xs px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400"
              >
                {c.label} ({c.values.join(', ')})
              </span>
            ))}
          </div>
        </div>
      )}

      <RawJson data={alert} />
    </div>
  );
};

// Shown only when printing — a normal-flow block, since the interactive modal is a
// position:fixed scrolling card that prints unreliably across browsers.
const PrintableCaseReport: React.FC<{ alert: EnrichedAlert; notes: AlertNote[]; allAlerts?: EnrichedAlert[] }> = ({ alert, notes, allAlerts }) => {
  const severity = casToSeverity(alert.CAS);
  const t = new Date(alert.timestamp).getTime();
  const related = (allAlerts ?? [])
    .filter((a) => a.id !== alert.id && a.agent === alert.agent && Math.abs(new Date(a.timestamp).getTime() - t) <= RELATED_WINDOW_MS)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return (
    <div className="hidden print:block p-8 text-slate-900">
      <h1 className="text-xl font-bold mb-1">{alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription}</h1>
      <p className="text-sm text-slate-500 mb-6">MediSIEM case report — printed {new Date().toLocaleString()}</p>
      <table className="w-full text-sm mb-6" style={{ borderCollapse: 'collapse' }}>
        <tbody>
          {([
            ['Alert ID', alert.id],
            ['Detected', new Date(alert.timestamp).toLocaleString()],
            ['Severity', `${severity} (CAS ${alert.CAS.toFixed(2)})`],
            ['Action', alert.action],
            ['Device', alert.agent],
            ['Department', alert.department],
            ['Device type', alert.deviceType ?? '—'],
            ['Status', alert.assignedTo ? `Assigned to ${alert.assignedTo.name}` : 'Unassigned'],
          ] as [string, string][]).map(([k, v]) => (
            <tr key={k} style={{ borderBottom: '1px solid #e2e8f0' }}>
              <td className="py-1.5 pr-4 font-medium text-slate-500 whitespace-nowrap">{k}</td>
              <td className="py-1.5">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 className="text-sm font-bold mb-2">Resolution</h2>
      {alert.closure ? (
        <div className="mb-6">
          <p className="text-sm mb-1"><span className="font-medium text-slate-500">Verdict: </span>{alert.closure.verdict?.replace('_', ' ') ?? 'not recorded'}</p>
          <p className="text-sm mb-1"><span className="font-medium text-slate-500">Closed by: </span>{alert.closure.closedBy.name} — {new Date(alert.closure.createdAt).toLocaleString()}</p>
          <p className="text-sm mb-1"><span className="font-medium text-slate-500">Reason: </span>{alert.closure.reason}</p>
          <p className="text-sm whitespace-pre-wrap"><span className="font-medium text-slate-500">Evidence: </span>{alert.closure.evidence}</p>
        </div>
      ) : (
        <p className="text-sm text-slate-500 italic mb-6">Case still open — no resolution recorded yet.</p>
      )}

      <h2 className="text-sm font-bold mb-2">Investigation timeline</h2>
      {notes.length === 0 ? (
        <p className="text-sm text-slate-500 italic mb-6">No notes were recorded during this investigation.</p>
      ) : (
        <div className="mb-6 space-y-2">
          {notes.map((n) => (
            <p key={n.id} className="text-sm">
              <span className="font-medium text-slate-500">{new Date(n.createdAt).toLocaleString()} — {n.author.name}: </span>
              {n.text}
            </p>
          ))}
        </div>
      )}

      <h2 className="text-sm font-bold mb-2">Related activity on {alert.agent}</h2>
      {related.length === 0 ? (
        <p className="text-sm text-slate-500 italic">No other alerts on this device within 2 hours of this one.</p>
      ) : (
        <table className="w-full text-sm" style={{ borderCollapse: 'collapse' }}>
          <tbody>
            {related.map((r) => (
              <tr key={r.id} style={{ borderBottom: '1px solid #e2e8f0' }}>
                <td className="py-1 pr-4 whitespace-nowrap text-slate-500">{new Date(r.timestamp).toLocaleString()}</td>
                <td className="py-1 pr-4 whitespace-nowrap">{casToSeverity(r.CAS)}</td>
                <td className="py-1">{r.label !== 'Unclassified' ? r.label : r.ruleDescription}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

const AlertDetailsModal: React.FC<Props> = (props) => {
  const { onClose } = props;
  const title = props.kind === 'ml'
    ? (props.alert.label !== 'Unclassified' ? props.alert.label : props.alert.ruleDescription)
    : (props.alert.ruleDescription ?? 'Alert details');
  const subtitle = props.kind === 'ml' ? `${props.alert.agent} · CAS ${props.alert.CAS.toFixed(1)}` : `${props.alert.agentName ?? 'Unknown agent'} · level ${props.alert.ruleLevel ?? '—'}`;

  // Fetched once here so both the notes section and the print-only report can show them.
  const mlAlertId = props.kind === 'ml' ? props.alert.id : null;
  const mlToken = props.kind === 'ml' ? (props.token ?? null) : null;
  const [notes, setNotes] = useState<AlertNote[]>([]);
  const [notesLoading, setNotesLoading] = useState(true);
  useEffect(() => {
    if (!mlAlertId || !mlToken) { setNotesLoading(false); return; }
    let cancelled = false;
    apiGetAlertNotes(mlToken, mlAlertId)
      .then(({ notes: n }) => { if (!cancelled) setNotes(n); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setNotesLoading(false); });
    return () => { cancelled = true; };
  }, [mlAlertId, mlToken]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm print:static print:block print:bg-white print:p-0" onClick={onClose}>
      <div
        className="w-full max-w-3xl rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[88vh] flex flex-col print:max-h-none print:shadow-none print:border-0 print:rounded-none print:block"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0 no-print">
          <div className="min-w-0">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white truncate">{title}</h2>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">{subtitle}</p>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0 ml-3">
            {props.kind === 'ml' && (
              <button
                onClick={() => window.print()}
                title="Print a one-page case report"
                className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
              >
                <Printer className="w-4 h-4" />
              </button>
            )}
            <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="px-6 py-5 overflow-y-auto no-print">
          {props.kind === 'ml'
            ? <MlAlertBody alert={props.alert} token={props.token} allAlerts={props.allAlerts} notes={notes} notesLoading={notesLoading} onNoteAdded={(n) => setNotes((prev) => [...prev, n])} />
            : <WazuhAlertBody alert={props.alert} />}
        </div>
        {props.kind === 'ml' && <PrintableCaseReport alert={props.alert} notes={notes} allAlerts={props.allAlerts} />}
      </div>
    </div>
  );
};

export default AlertDetailsModal;
