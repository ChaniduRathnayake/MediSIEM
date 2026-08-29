// Port of App.jsx's "investigation" page — the main IP investigation console.
// State (ip/result/history/analystData/correlation/operational/wazuh/loading/
// error) and the mutation handlers (setList/setVerdict/addNote/createCase) all
// live in IpReputationPanel.tsx so the Threat Hunt tab's "Investigate" cross-link
// can drive this view from outside; this component is purely presentational,
// aside from the small local form state (verdict/note/list-reason/case fields)
// that only this view's inline forms need.
import React, { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import type {
  ReputationLookupResponse, HistoryItem, AnalystIntelligence, CorrelationResult,
  OperationalResult, WazuhEvidenceResult, AbuseIpdbEvidence, VirusTotalEvidence,
} from './ipReputationApi';
import WazuhEvidenceCard from './WazuhEvidenceCard';
import {
  SectionCard, MetricTile, DataRow, Badge, EmptyNotice, ErrorBanner, JsonBlock, EvidenceTile,
  fmtDateTime, toneOf, formatMirsDimension, formatLabel,
} from './shared';
import type { EvidenceState } from './shared';

interface InvestigationViewProps {
  ip: string;
  onIpChange: (ip: string) => void;
  result: ReputationLookupResponse | null;
  history: HistoryItem[];
  analystData: AnalystIntelligence | null;
  correlation: CorrelationResult | null;
  operational: OperationalResult | null;
  wazuh: WazuhEvidenceResult | null;
  loading: boolean;
  error: string;
  onInvestigate: (targetIp?: string) => void | Promise<void>;
  onSetList: (listType: string, reason: string) => void | Promise<void>;
  onSetVerdict: (verdict: string, reason: string) => void | Promise<void>;
  onAddNote: (note: string) => void | Promise<void>;
  onCreateCase: (title: string, description: string, severity: string) => void | Promise<void>;
}

const VERDICTS = ['undetermined', 'benign', 'suspicious', 'malicious'];
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];

const InvestigationView: React.FC<InvestigationViewProps> = ({
  ip, onIpChange, result, history, analystData, correlation, operational, wazuh,
  loading, error, onInvestigate, onSetList, onSetVerdict, onAddNote, onCreateCase,
}) => {
  const analysis = result?.reputation_analysis;
  const internal = result?.internal_intelligence;
  const abuse = result?.threat_intelligence?.providers?.abuseipdb?.evidence as AbuseIpdbEvidence | null | undefined;
  const vt = result?.threat_intelligence?.providers?.virustotal?.evidence as VirusTotalEvidence | null | undefined;

  const mirsEvidence = correlation?.mirs_evidence;
  const mirsBreakdown = mirsEvidence?.breakdown || {};
  // The softmax-weighted per-dimension breakdown lives at the top level for
  // events stored before the Attack-Preserving MIRS v2 rollout, and under
  // baseline_adaptive_breakdown (kept for research comparison) afterward.
  const baselineBreakdown = mirsBreakdown.baseline_adaptive_breakdown || mirsBreakdown;
  const mirsComponents = baselineBreakdown.components || {};
  const mirsWeights = baselineBreakdown.weights || {};
  const mirsAvailability = baselineBreakdown.availability || {};
  const isAttackPreservingV2 = mirsBreakdown.mirs_version === 'attack_preserving_v2';
  const vulnerabilityComponent = mirsBreakdown.support_components?.vulnerability_exposure;

  const mirsComponentScore = (name: string): number | null => {
    if (mirsAvailability[name] === false) return null;
    return mirsComponents[name]?.input_score ?? null;
  };
  const mirsComponentWeight = (name: string): number | null => mirsWeights[name] ?? null;

  const verdict = analystData?.current_verdict;

  // ── Local form state for the inline Internal Intelligence / Analyst /
  // Case forms (the original app drove these through window.prompt() —
  // replaced with real fields so they read/behave like the rest of the UI). ──
  const [listReason, setListReason] = useState('Added from MedShield IP investigation');
  const [verdictChoice, setVerdictChoice] = useState('undetermined');
  const [verdictReason, setVerdictReason] = useState('');
  const [noteText, setNoteText] = useState('');
  const [caseTitle, setCaseTitle] = useState('');
  const [caseDescription, setCaseDescription] = useState('');
  const [caseSeverity, setCaseSeverity] = useState('Medium');

  // Reset the inline forms whenever a new IP is investigated, and seed the
  // case form / verdict choice from the freshly-loaded result.
  useEffect(() => {
    if (!result) return;
    setListReason('Added from MedShield IP investigation');
    setVerdictChoice(analystData?.current_verdict?.verdict || 'undetermined');
    setVerdictReason('');
    setNoteText('');
    setCaseTitle(`Investigate ${result.ip}`);
    setCaseDescription(`Created from MedShield IP investigation. External reputation risk: ${result.risk_level || 'Unknown'}.`);
    setCaseSeverity(SEVERITIES.includes(result.risk_level ?? '') ? (result.risk_level as string) : 'Medium');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result?.ip]);

  // ── Evidence Availability — reports whether each already-fetched source
  // actually returned usable data for this investigation, not just whether
  // its API call succeeded. ──
  const evidenceTiles: { label: string; state: EvidenceState; detail: string }[] = result
    ? [
        {
          label: 'External Threat Intelligence',
          state: result.threat_intelligence ? 'ok' : 'missing',
          detail: result.threat_intelligence ? 'Provider response available' : 'No provider response',
        },
        {
          label: 'Local ML Correlation',
          state: correlation?.available && (correlation.matched_event_count ?? 0) > 0 ? 'ok' : correlation?.available ? 'warn' : 'missing',
          detail: correlation?.available
            ? `${correlation.matched_event_count ?? 0} matching flow observation${correlation.matched_event_count === 1 ? '' : 's'}`
            : 'Correlation engine unavailable',
        },
        {
          label: 'Stored Intelligence',
          state: internal ? 'ok' : 'missing',
          detail: internal ? (internal.matched ? 'Stored profile available' : 'No matching internal profile') : 'Unavailable',
        },
        {
          label: 'Reputation History',
          state: history.length > 0 ? 'ok' : 'warn',
          detail: `${history.length} historical observation${history.length === 1 ? '' : 's'}`,
        },
        {
          label: 'Analyst Intelligence',
          state: !analystData ? 'missing' : verdict || (analystData.note_count ?? 0) > 0 ? 'ok' : 'warn',
          detail: !analystData
            ? 'Analyst service unavailable'
            : verdict || (analystData.note_count ?? 0) > 0
            ? `${analystData.verdict_count ?? 0} verdict(s), ${analystData.note_count ?? 0} note(s)`
            : 'Analyst service available; no verdict or notes yet',
        },
        {
          label: 'MIRS Core',
          state: mirsEvidence?.available ? 'ok' : 'missing',
          detail: mirsEvidence?.available
            ? `Adaptive MIRS evidence available; ${mirsEvidence.risk_band || 'Unknown'} risk`
            : mirsEvidence?.message || 'MIRS evidence unavailable',
        },
        {
          label: 'Operational Assessment',
          state: operational?.operational_assessment ? 'ok' : 'missing',
          detail: operational?.operational_assessment
            ? `${operational.operational_assessment.operational_risk_level} risk | ${(operational.operational_assessment.confidence || 'unknown').toLowerCase()} confidence`
            : 'Unavailable',
        },
      ]
    : [];

  const healthcareContext = mirsEvidence?.healthcare_context || null;
  const healthcareEntries = healthcareContext
    ? Object.entries(healthcareContext).filter(([key, value]) => key !== 'known' && value !== null && value !== undefined)
    : [];

  return (
    <div className="space-y-5">
      <SectionCard>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500 pointer-events-none" />
            <input
              value={ip}
              onChange={(e) => onIpChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void onInvestigate();
              }}
              placeholder="Enter an IPv4 address"
              className="w-full pl-9 pr-3 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
          </div>
          <button
            onClick={() => void onInvestigate()}
            disabled={loading}
            className="px-4 py-2.5 rounded-lg text-sm font-medium bg-cyan-500 hover:bg-cyan-400 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
          >
            {loading ? 'Investigating…' : 'Investigate'}
          </button>
        </div>
      </SectionCard>

      {error && <ErrorBanner message={error} />}

      {!result && !error && (
        <SectionCard>
          <div className="text-center py-8">
            <Search className="w-8 h-8 text-slate-400 dark:text-slate-600 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Start an IP investigation</h3>
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1 max-w-md mx-auto">
              Search an address to retrieve AbuseIPDB, VirusTotal, MedShield reputation history and analyst intelligence.
            </p>
          </div>
        </SectionCard>
      )}

      {result && (
        <>
          {/* Identity row */}
          <SectionCard>
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div>
                <span className="text-[10px] font-semibold tracking-wider text-cyan-600 dark:text-cyan-400 uppercase">Investigated Address</span>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white mt-0.5">{result.ip}</h2>
                <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">{result.classification?.reason}</p>
              </div>
              <div className="flex items-center gap-1.5">
                <Badge>{result.classification?.category}</Badge>
                <Badge>IPv{result.classification?.version}</Badge>
              </div>
            </div>
          </SectionCard>

          {/* Top-level metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            <MetricTile label="Reputation Score" value={result.reputation_score == null ? '—' : `${result.reputation_score}/100`} />
            <MetricTile label="External Risk" value={result.risk_level || 'Unknown'} tone={toneOf(result.risk_level)} />
            <MetricTile label="Score-based Risk" value={analysis?.score_based_risk_level || 'Unknown'} tone={toneOf(analysis?.score_based_risk_level)} />
            <MetricTile label="Evidence Floor" value={analysis?.evidence_floor_level || 'None'} />
            <MetricTile label="Confidence" value={result.confidence || 'None'} />
            <MetricTile label="Provider Agreement" value={analysis?.provider_agreement || 'N/A'} />
            <MetricTile label="Internal Status" value={internal?.effective_status || 'none'} tone={toneOf(internal?.effective_status)} />
          </div>

          {/* Operational risk assessment */}
          {operational?.operational_assessment && (
            <SectionCard
              eyebrow="MEDSHIELD CORRELATED ASSESSMENT"
              title={
                <span>
                  Operational Risk: <strong className={toneOf(operational.operational_assessment.operational_risk_level) === 'bad' ? 'text-red-500 dark:text-red-400' : undefined}>{operational.operational_assessment.operational_risk_level}</strong>
                </span>
              }
              subtitle="External reputation, local ML/context, Wazuh/Suricata, analyst intelligence and internal policy are evaluated as separate evidence dimensions."
              right={<Badge tone={toneOf(operational.operational_assessment.decision)}>{operational.operational_assessment.decision}</Badge>}
            >
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
                <MetricTile label="Operational Risk" value={operational.operational_assessment.operational_risk_level} tone={toneOf(operational.operational_assessment.operational_risk_level)} />
                <MetricTile label="External Risk" value={operational.operational_assessment.dimensions?.external_reputation || 'Unknown'} tone={toneOf(operational.operational_assessment.dimensions?.external_reputation)} />
                <MetricTile label="Local ML / Context" value={operational.operational_assessment.dimensions?.local_ml_context || 'Unknown'} tone={toneOf(operational.operational_assessment.dimensions?.local_ml_context)} />
                <MetricTile label="Wazuh / Suricata" value={operational.operational_assessment.dimensions?.wazuh_suricata || 'Unknown'} tone={toneOf(operational.operational_assessment.dimensions?.wazuh_suricata)} />
                <MetricTile label="Internal Intelligence" value={operational.operational_assessment.dimensions?.internal_intelligence || 'none'} tone={toneOf(operational.operational_assessment.dimensions?.internal_intelligence)} />
                <MetricTile label="Analyst Verdict" value={operational.operational_assessment.dimensions?.analyst_verdict || 'none'} tone={toneOf(operational.operational_assessment.dimensions?.analyst_verdict)} />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
                <div>
                  <DataRow label="Assessment confidence" value={operational.operational_assessment.confidence ?? '—'} />
                  <DataRow label="Evidence dimensions" value={operational.operational_assessment.evidence_dimensions ?? '—'} />
                  <DataRow label="Cross-signal escalation" value={operational.operational_assessment.cross_signal_escalation ? 'Yes' : 'No'} />
                </div>
                <div>
                  <DataRow label="Decision" value={operational.operational_assessment.decision} />
                  <DataRow label="Recommended action" value={operational.operational_assessment.recommended_action ?? '—'} />
                </div>
              </div>

              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Why MedShield reached this decision</p>
              <ul className="list-disc list-inside space-y-1 text-sm text-slate-600 dark:text-slate-300">
                {operational.operational_assessment.reasons?.map((reason, index) => <li key={index}>{reason}</li>)}
              </ul>
            </SectionCard>
          )}

          {/* MIRS panel */}
          <SectionCard
            eyebrow="MEDSHIELD INTEGRATED RISK SCORE"
            title={
              <span>
                MIRS <strong>{mirsEvidence?.available ? `${mirsEvidence.latest_score}/100` : 'Unavailable'}</strong>
              </span>
            }
            subtitle="Flow-level integrated risk from local ML, anomaly, healthcare context and external reputation evidence. The external Reputation Score above remains a separate threat-intelligence measurement."
            right={<Badge tone={mirsEvidence?.available ? toneOf(mirsEvidence.risk_band) : 'neutral'}>{mirsEvidence?.available ? mirsEvidence.risk_band : 'No MIRS'}</Badge>}
          >
            {!correlation?.available ? (
              <EmptyNotice>Local MedShield evidence is unavailable, so MIRS cannot be displayed.</EmptyNotice>
            ) : correlation?.matched_event_count === 0 ? (
              <EmptyNotice>No locally observed flow matched this IP. MIRS is only shown when MedShield has flow evidence for the address.</EmptyNotice>
            ) : !mirsEvidence?.available ? (
              <EmptyNotice>{mirsEvidence?.message || 'Matching flows exist, but those stored events do not contain MIRS yet.'}</EmptyNotice>
            ) : (
              <>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                  <MetricTile label="Latest MIRS" value={`${mirsEvidence.latest_score}/100`} tone={toneOf(mirsEvidence.risk_band)} />
                  <MetricTile label="MIRS Risk Band" value={mirsEvidence.risk_band || 'Unknown'} tone={toneOf(mirsEvidence.risk_band)} />
                  <MetricTile label="APS" value={mirsEvidence.latest_aps == null ? '—' : `${mirsEvidence.latest_aps}/100`} />
                  <MetricTile label="ML Fusion" value={mirsEvidence.ml_fusion_enabled ? 'Enabled' : 'Excluded'} />
                  <MetricTile label="Real Feature Coverage" value={mirsEvidence.real_feature_coverage == null ? '—' : `${mirsEvidence.real_feature_coverage}%`} />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
                  <div>
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">MIRS Dimension Scores</p>
                    <DataRow label="Random Forest" value={formatMirsDimension(mirsComponentScore('random_forest'), mirsComponentWeight('random_forest'))} />
                    <DataRow label="Isolation Forest" value={formatMirsDimension(mirsComponentScore('isolation_forest'), mirsComponentWeight('isolation_forest'))} />
                    <DataRow label="Healthcare Context" value={formatMirsDimension(mirsComponentScore('context'), mirsComponentWeight('context'))} />
                    <DataRow label="External Reputation" value={formatMirsDimension(mirsComponentScore('reputation'), mirsComponentWeight('reputation'))} />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">MIRS Evidence State</p>
                    <DataRow label="Latest flow" value={mirsEvidence.src_ip && mirsEvidence.dest_ip ? `${mirsEvidence.src_ip} → ${mirsEvidence.dest_ip}` : '—'} />
                    <DataRow label="Flow reputation target" value={mirsEvidence.flow_reputation?.enriched_ip || 'Not enriched'} />
                    <DataRow label="Flow reputation score" value={mirsEvidence.flow_reputation?.score == null ? '—' : `${mirsEvidence.flow_reputation.score}/100`} />
                    <DataRow label="Healthcare asset known" value={healthcareContext?.known ? 'Yes' : 'No'} />
                    <DataRow label="Latest evidence time" value={fmtDateTime(mirsEvidence.timestamp)} />
                  </div>
                </div>

                {(mirsEvidence.explanations?.length ?? 0) > 0 && (
                  <>
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Why this MIRS was produced</p>
                    <ul className="list-disc list-inside space-y-1 text-sm text-slate-600 dark:text-slate-300 mb-4">
                      {mirsEvidence.explanations?.map((reason, index) => <li key={index}>{reason}</li>)}
                    </ul>
                  </>
                )}

                {/* MIRS Evidence Breakdown + Healthcare Context */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2 border-t border-slate-100 dark:border-slate-800/60">
                  <div className="pt-4">
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-1">MIRS Evidence Breakdown</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500 mb-3">Evidence dimensions and weighting supplied by the correlation engine.</p>
                    <DataRow label="Adaptive MIRS" value={mirsBreakdown.adaptive_MIRS ?? '—'} />
                    {mirsBreakdown.mirs_version && <DataRow label="Mirs Version" value={mirsBreakdown.mirs_version} />}
                    <DataRow label="Risk Level" value={mirsBreakdown.risk_level || 'Unknown'} />
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Formula</p>
                    <p className="text-xs font-mono text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 mb-3">
                      {mirsBreakdown.formula || 'Unavailable'}
                    </p>

                    {isAttackPreservingV2 ? (
                      <>
                        <DataRow label="Primary Attack Score" value={mirsBreakdown.primary_attack_score ?? '—'} />
                        <DataRow label="Primary Attack Source" value={formatLabel(mirsBreakdown.primary_attack_source)} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Primary Candidates</p>
                        <JsonBlock data={mirsBreakdown.primary_candidates || {}} />
                        <DataRow label="Support Score" value={mirsBreakdown.support_score ?? '—'} />
                        <DataRow label="Support Gain" value={mirsBreakdown.support_gain ?? '—'} />
                        <DataRow label="Support Increment" value={mirsBreakdown.support_increment ?? '—'} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Support Weights</p>
                        <JsonBlock data={mirsBreakdown.support_weights || {}} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Support Components</p>
                        <JsonBlock data={mirsBreakdown.support_components || {}} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Attack Preservation</p>
                        <JsonBlock data={mirsBreakdown.attack_preservation || {}} />
                        <DataRow label="External Frameworks Used In Formula" value={mirsBreakdown.external_frameworks_used_in_formula ? 'Yes' : 'No'} />
                        {mirsBreakdown.explanation && (
                          <>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Explanation</p>
                            <p className="text-xs text-slate-600 dark:text-slate-300">{mirsBreakdown.explanation}</p>
                          </>
                        )}
                        {mirsBreakdown.baseline_adaptive_MIRS != null && (
                          <>
                            <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mt-4 mb-1">Baseline Adaptive MIRS (research comparison)</p>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-2">
                              The superseded softmax-weighted score, kept for PP2 evaluation. It no longer drives the operational risk level above.
                            </p>
                            <DataRow label="Baseline Adaptive MIRS" value={`${mirsBreakdown.baseline_adaptive_MIRS}/100`} />
                            <DataRow label="Baseline Risk Level" value={mirsBreakdown.baseline_adaptive_risk_level || 'Unknown'} />
                          </>
                        )}
                      </>
                    ) : (
                      <DataRow label="Model Disagreement" value={mirsBreakdown.model_disagreement == null ? '—' : `${mirsBreakdown.model_disagreement}%`} />
                    )}

                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Weights{isAttackPreservingV2 ? ' (baseline)' : ''}</p>
                    <JsonBlock data={baselineBreakdown.weights || {}} />
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Weight Percentages{isAttackPreservingV2 ? ' (baseline)' : ''}</p>
                    <JsonBlock data={baselineBreakdown.weight_percentages || {}} />
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Raw Adaptive Weights{isAttackPreservingV2 ? ' (baseline)' : ''}</p>
                    <JsonBlock data={baselineBreakdown.raw_adaptive_weights || {}} />
                    {(baselineBreakdown.adaptation_reasons?.length ?? 0) > 0 && (
                      <>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-3 mb-1">Weight Adaptation Reasons{isAttackPreservingV2 ? ' (baseline)' : ''}</p>
                        <ul className="list-disc list-inside space-y-1 text-xs text-slate-600 dark:text-slate-300">
                          {baselineBreakdown.adaptation_reasons?.map((reason, index) => <li key={index}>{reason}</li>)}
                        </ul>
                      </>
                    )}
                  </div>

                  <div className="pt-4">
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-1">Healthcare Context</p>
                    <p className="text-xs text-slate-400 dark:text-slate-500 mb-3">Healthcare-specific context is shown only when the backend provides it.</p>
                    {healthcareEntries.length > 0 ? (
                      healthcareEntries.map(([key, value]) => (
                        <DataRow key={key} label={formatLabel(key)} value={typeof value === 'object' ? JSON.stringify(value) : String(value)} />
                      ))
                    ) : (
                      <EmptyNotice>
                        No healthcare-specific asset context is currently supplied for this investigation. MedShield does not infer or
                        fabricate healthcare context when the evidence is unavailable.
                      </EmptyNotice>
                    )}
                  </div>
                </div>
              </>
            )}
          </SectionCard>

          {/* Attack-Preserving MIRS v2 */}
          {mirsEvidence?.available && (
            <SectionCard
              eyebrow="MEDSHIELD"
              title="Attack-Preserving MIRS v2"
              subtitle="Availability-aware operational cyber-risk fusion with a preserved primary attack floor."
              right={<Badge tone={toneOf(mirsBreakdown.risk_level)}>{mirsBreakdown.risk_level || 'Unknown'}</Badge>}
            >
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <MetricTile label="Current MIRS" value={mirsBreakdown.adaptive_MIRS == null ? '—' : `${mirsBreakdown.adaptive_MIRS}/100`} tone={toneOf(mirsBreakdown.risk_level)} />
                <MetricTile
                  label="Primary Attack Evidence"
                  value={mirsBreakdown.primary_attack_score == null ? 'Unavailable' : `${mirsBreakdown.primary_attack_score}/100`}
                />
                <MetricTile
                  label="Vulnerability Exposure"
                  value={vulnerabilityComponent?.available ? `${vulnerabilityComponent.input_score}/100` : 'Unavailable'}
                />
                <MetricTile
                  label="Supporting Evidence"
                  value={mirsBreakdown.support_score == null ? '—' : `${mirsBreakdown.support_score}/100`}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-2">
                <div>
                  <DataRow label="Primary source" value={formatLabel(mirsBreakdown.primary_attack_source)} />
                  <DataRow label="MIRS version" value={mirsBreakdown.mirs_version || 'Unknown'} />
                </div>
                <div>
                  <DataRow label="ML fusion" value={mirsEvidence.ml_fusion_enabled ? 'Enabled' : 'Excluded'} />
                  <DataRow label="Risk basis" value={isAttackPreservingV2 ? 'Attack-preserving operational evidence' : 'Legacy adaptive evidence'} />
                </div>
              </div>

              <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">
                Evidence scores are normalized /100 dimensions. They are not probabilities of compromise or exploit success.
              </p>
            </SectionCard>
          )}

          {/* AbuseIPDB / VirusTotal */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <SectionCard title="AbuseIPDB">
              <DataRow label="Abuse confidence" value={abuse ? `${abuse.abuse_confidence_score}%` : 'Unavailable'} />
              <DataRow label="Total reports" value={abuse?.total_reports ?? '—'} />
              <DataRow label="Distinct reporters" value={abuse?.distinct_reporters ?? '—'} />
              <DataRow label="ISP" value={abuse?.isp ?? '—'} />
              <DataRow label="Country" value={abuse?.country_code ?? '—'} />
            </SectionCard>

            <SectionCard title="VirusTotal">
              <DataRow label="Malicious engines" value={vt?.last_analysis_stats?.malicious ?? '—'} />
              <DataRow label="Suspicious engines" value={vt?.last_analysis_stats?.suspicious ?? '—'} />
              <DataRow label="Total engines" value={vt?.last_analysis_stats?.total ?? '—'} />
              <DataRow label="ASN" value={vt?.asn ?? '—'} />
              <DataRow label="Network owner" value={vt?.as_owner ?? '—'} />
            </SectionCard>
          </div>

          {/* Local ML & Context Evidence */}
          <SectionCard
            title="Local ML & Context Evidence"
            subtitle="Correlation with locally observed Suricata, machine-learning and healthcare-context evidence."
            right={<Badge tone={toneOf(correlation?.status)}>{correlation?.status || 'unknown'}</Badge>}
          >
            {!correlation?.available ? (
              <EmptyNotice>Local MedShield ML/context engine is unavailable.</EmptyNotice>
            ) : correlation?.matched_event_count === 0 ? (
              <EmptyNotice>No local network evidence was found for this IP. External reputation remains independent of local ML evidence.</EmptyNotice>
            ) : (
              <>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                  <MetricTile label="Matched Flows" value={correlation.matched_event_count} />
                  <MetricTile
                    label="Max RF Attack %"
                    value={correlation.summary?.max_rf_attack_probability == null ? '—' : `${correlation.summary.max_rf_attack_probability.toFixed(2)}%`}
                  />
                  <MetricTile label="Max IF Anomaly" value={correlation.summary?.max_if_anomaly_score ?? '—'} />
                  <MetricTile label="Feature Coverage" value={`${correlation.summary?.average_feature_coverage ?? 0}%`} />
                  <MetricTile
                    label="Context Risk"
                    value={correlation.summary?.max_context_risk_score == null ? '—' : `${correlation.summary.max_context_risk_score}/100`}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-4">
                  <div>
                    <DataRow label="Context level" value={correlation.summary?.latest_context_risk_level || 'Unknown'} />
                    <DataRow label="Operational priority" value={correlation.summary?.latest_operational_priority || 'Unknown'} />
                    <DataRow label="ML fusion observed" value={correlation.ml_fusion_observed ? 'Yes' : 'No'} />
                  </div>
                  <div>
                    <DataRow label="Source matches" value={correlation.source_matches ?? 0} />
                    <DataRow label="Destination matches" value={correlation.destination_matches ?? 0} />
                    <DataRow label="Records scanned" value={correlation.records_scanned ?? 0} />
                  </div>
                </div>

                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Local Evidence</p>
                <div className="overflow-x-auto -mx-1">
                  <table className="w-full min-w-[720px]">
                    <thead>
                      <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                        <th className="py-2 px-2 text-left">Flow</th>
                        <th className="py-2 px-2 text-left">RF</th>
                        <th className="py-2 px-2 text-left">IF</th>
                        <th className="py-2 px-2 text-left">Context</th>
                        <th className="py-2 px-2 text-left">Priority</th>
                      </tr>
                    </thead>
                    <tbody>
                      {correlation.events?.slice(0, 10).map((event) => (
                        <tr key={event.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                          <td className="py-2 px-2">
                            <span className="font-medium text-slate-900 dark:text-white">{event.src_ip}</span>
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">
                              → {event.dest_ip} • {event.protocol || 'Unknown'}
                            </span>
                          </td>
                          <td className="py-2 px-2">
                            {event.random_forest?.prediction || '—'}
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">
                              {event.random_forest?.attack_probability == null ? '—' : `${event.random_forest.attack_probability.toFixed(2)}%`}
                            </span>
                          </td>
                          <td className="py-2 px-2">
                            {event.isolation_forest?.prediction || '—'}
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">{event.isolation_forest?.anomaly_score ?? '—'}</span>
                          </td>
                          <td className="py-2 px-2">
                            {event.context_risk_level || '—'}
                            <br />
                            <span className="text-xs text-slate-400 dark:text-slate-500">{event.context_risk_score ?? '—'}</span>
                          </td>
                          <td className="py-2 px-2">{event.operational_priority || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </SectionCard>

          <WazuhEvidenceCard data={wazuh} />

          {/* Internal Intelligence Controls */}
          <SectionCard
            title="Internal Intelligence Controls"
            subtitle="Organization-specific allow, watch and block decisions remain separate from external reputation."
            right={<Badge tone={toneOf(internal?.effective_status)}>Current: {internal?.effective_status || 'none'}</Badge>}
          >
            <input
              value={listReason}
              onChange={(e) => setListReason(e.target.value)}
              placeholder="Reason for allow/watch/block decision"
              className="w-full mb-3 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
            <div className="flex items-center gap-1.5 mb-4">
              <button onClick={() => void onSetList('allow', listReason)} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors">
                Allow
              </button>
              <button onClick={() => void onSetList('watch', listReason)} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition-colors">
                Watch
              </button>
              <button onClick={() => void onSetList('block', listReason)} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors">
                Block
              </button>
            </div>

            <DataRow label="Matched" value={internal?.matched ? 'Yes' : 'No'} />
            <DataRow label="Memberships" value={internal?.memberships?.join(', ') || 'None'} />
            <DataRow label="Disposition" value={internal?.operational_disposition || 'No internal override'} />
            <DataRow label="Conflict" value={internal?.conflict ? 'Yes' : 'No'} />
          </SectionCard>

          {/* Analyst Intelligence */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <SectionCard title="Analyst Verdict" subtitle="Human judgment is persisted separately from automated evidence.">
              <DataRow label="Current verdict" value={verdict?.verdict || 'No analyst verdict'} />
              <DataRow label="Verdict history" value={analystData?.verdict_count ?? 0} />

              <div className="mt-3 space-y-2">
                <select
                  value={verdictChoice}
                  onChange={(e) => setVerdictChoice(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white capitalize focus:outline-none focus:border-cyan-500/60"
                >
                  {VERDICTS.map((item) => (
                    <option key={item} value={item}>
                      {formatLabel(item)}
                    </option>
                  ))}
                </select>
                <textarea
                  value={verdictReason}
                  onChange={(e) => setVerdictReason(e.target.value)}
                  placeholder="Reason for analyst verdict"
                  rows={2}
                  className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 resize-y"
                />
                <button
                  onClick={() => void onSetVerdict(verdictChoice, verdictReason)}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-cyan-500 hover:bg-cyan-400 text-white transition-colors"
                >
                  Save Verdict
                </button>
              </div>
            </SectionCard>

            <SectionCard title="Investigation Note" subtitle="Freeform analyst notes captured against this investigation.">
              <DataRow label="Stored notes" value={analystData?.note_count ?? 0} />

              <div className="mt-3 space-y-2">
                <textarea
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                  placeholder="Add analyst investigation notes…"
                  rows={4}
                  className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 resize-y"
                />
                <button
                  onClick={() => {
                    void onAddNote(noteText);
                    setNoteText('');
                  }}
                  disabled={!noteText.trim()}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Add Note
                </button>
              </div>
            </SectionCard>
          </div>

          {/* Create Investigation Case */}
          <SectionCard title="Create Investigation Case" subtitle="Persist this IP investigation as a MedShield case for follow-up.">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
              <input
                value={caseTitle}
                onChange={(e) => setCaseTitle(e.target.value)}
                placeholder="Case title"
                className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
              />
              <select
                value={caseSeverity}
                onChange={(e) => setCaseSeverity(e.target.value)}
                className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:outline-none focus:border-cyan-500/60"
              >
                {SEVERITIES.map((sev) => (
                  <option key={sev} value={sev}>{sev}</option>
                ))}
              </select>
            </div>
            <textarea
              value={caseDescription}
              onChange={(e) => setCaseDescription(e.target.value)}
              placeholder="Case description"
              rows={2}
              className="w-full mb-3 px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 resize-y"
            />
            <button
              onClick={() => void onCreateCase(caseTitle, caseDescription, caseSeverity)}
              disabled={!caseTitle.trim()}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Create Case
            </button>
          </SectionCard>

          {/* Reputation History */}
          <SectionCard title="Reputation History">
            {history.length === 0 ? (
              <EmptyNotice>No historical observations.</EmptyNotice>
            ) : (
              <div className="overflow-x-auto -mx-1">
                <table className="w-full min-w-[520px]">
                  <thead>
                    <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                      <th className="py-2 px-2 text-left">Observed</th>
                      <th className="py-2 px-2 text-left">Score</th>
                      <th className="py-2 px-2 text-left">Risk</th>
                      <th className="py-2 px-2 text-left">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.slice(0, 10).map((item) => (
                      <tr key={item._id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 text-sm">
                        <td className="py-2 px-2 text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDateTime(item.observed_at)}</td>
                        <td className="py-2 px-2 text-slate-900 dark:text-white">{item.reputation_score ?? '—'}</td>
                        <td className="py-2 px-2">
                          <Badge tone={toneOf(item.risk_level)}>{item.risk_level || 'Unknown'}</Badge>
                        </td>
                        <td className="py-2 px-2 text-slate-500 dark:text-slate-400">{item.confidence || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>

          {/* Explanation */}
          <SectionCard title="MedShield Explanation">
            <ul className="list-disc list-inside space-y-1.5 text-sm text-slate-600 dark:text-slate-300">
              {result.explanation?.map((item, index) => <li key={index}>{item}</li>)}
            </ul>
          </SectionCard>

          {/* Evidence Availability */}
          <SectionCard title="Evidence Availability" subtitle="Which evidence sources actually returned data for this investigation.">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {evidenceTiles.map((tile) => (
                <EvidenceTile key={tile.label} label={tile.label} state={tile.state} detail={tile.detail} />
              ))}
            </div>
          </SectionCard>

          {/* Raw investigation evidence */}
          <SectionCard>
            <details>
              <summary className="cursor-pointer text-sm font-semibold text-slate-900 dark:text-white select-none">
                Raw investigation evidence
              </summary>
              <div className="mt-3">
                <JsonBlock data={{ result, correlation, operational, wazuh, history, analystData }} maxHeight="480px" />
              </div>
            </details>
          </SectionCard>
        </>
      )}
    </div>
  );
};

export default InvestigationView;
