// Port of App.jsx's "investigation" page — the main IP investigation console.
// State (ip/result/history/analystData/correlation/operational/wazuh/loading/
// error) and the mutation handlers (setList/setVerdict/addNote/createCase) all
// live in IpReputationPanel.tsx so the Threat Hunt tab's "Investigate" cross-link
// can drive this view from outside; this component is purely presentational.
import React from 'react';
import { Search } from 'lucide-react';
import type {
  ReputationLookupResponse, HistoryItem, AnalystIntelligence, CorrelationResult,
  OperationalResult, WazuhEvidenceResult, AbuseIpdbEvidence, VirusTotalEvidence,
} from './ipReputationApi';
import WazuhEvidenceCard from './WazuhEvidenceCard';
import {
  SectionCard, MetricTile, DataRow, Badge, EmptyNotice, ErrorBanner,
  fmtDateTime, toneOf, formatMirsDimension,
} from './shared';

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
  onSetList: (listType: string) => void | Promise<void>;
  onSetVerdict: (verdict: string) => void | Promise<void>;
  onAddNote: () => void | Promise<void>;
  onCreateCase: () => void | Promise<void>;
}

const VERDICTS = ['benign', 'suspicious', 'malicious', 'undetermined'];

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
  const mirsComponents = mirsBreakdown.components || {};
  const mirsDimensions = mirsBreakdown.dimensions || {};
  const mirsConfiguredWeights = mirsBreakdown.configured_weights || {};
  const mirsEffectiveWeights = mirsBreakdown.effective_weights || {};
  const mirsAvailability = mirsBreakdown.availability || {};

  const mirsComponentScore = (name: string): number | null => {
    if (mirsAvailability[name] === false) return null;
    return mirsComponents[name] ?? mirsDimensions[name]?.score ?? null;
  };
  const mirsComponentWeight = (name: string): number | null =>
    mirsEffectiveWeights[name] ?? mirsDimensions[name]?.effective_weight ?? mirsConfiguredWeights[name] ?? mirsDimensions[name]?.base_weight ?? null;

  const verdict = analystData?.current_verdict;

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
              placeholder="Enter IPv4 or IPv6 address"
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
                    <DataRow label="Healthcare asset known" value={mirsEvidence.healthcare_context?.known ? 'Yes' : 'No'} />
                    <DataRow label="Latest evidence time" value={fmtDateTime(mirsEvidence.timestamp)} />
                  </div>
                </div>

                {(mirsEvidence.explanations?.length ?? 0) > 0 && (
                  <>
                    <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide mb-2">Why this MIRS was produced</p>
                    <ul className="list-disc list-inside space-y-1 text-sm text-slate-600 dark:text-slate-300">
                      {mirsEvidence.explanations?.map((reason, index) => <li key={index}>{reason}</li>)}
                    </ul>
                  </>
                )}
              </>
            )}
          </SectionCard>

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
                    value={correlation.summary?.max_rf_attack_probability == null ? '—' : `${(correlation.summary.max_rf_attack_probability * 100).toFixed(2)}%`}
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
                              {event.random_forest?.attack_probability == null ? '—' : `${(event.random_forest.attack_probability * 100).toFixed(2)}%`}
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

          {/* Internal Intelligence */}
          <SectionCard
            title="Internal Intelligence"
            subtitle="Organization-specific analyst controls remain separate from external reputation evidence."
            right={
              <div className="flex items-center gap-1.5">
                <button onClick={() => void onSetList('allow')} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-colors">
                  Allow
                </button>
                <button onClick={() => void onSetList('watch')} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition-colors">
                  Watch
                </button>
                <button onClick={() => void onSetList('block')} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-colors">
                  Block
                </button>
              </div>
            }
          >
            <DataRow label="Matched" value={internal?.matched ? 'Yes' : 'No'} />
            <DataRow label="Memberships" value={internal?.memberships?.join(', ') || 'None'} />
            <DataRow label="Disposition" value={internal?.operational_disposition || 'No internal override'} />
            <DataRow label="Conflict" value={internal?.conflict ? 'Yes' : 'No'} />
          </SectionCard>

          {/* Analyst Assessment */}
          <SectionCard
            title="Analyst Assessment"
            subtitle="Human judgment is stored separately from automated reputation evidence."
            right={
              <div className="flex items-center gap-1.5">
                <button onClick={() => void onAddNote()} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors">
                  Add Note
                </button>
                <button onClick={() => void onCreateCase()} className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors">
                  Create Case
                </button>
              </div>
            }
          >
            <div className="flex items-center gap-1.5 flex-wrap mb-4">
              {VERDICTS.map((item) => (
                <button
                  key={item}
                  onClick={() => void onSetVerdict(item)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors ${
                    verdict?.verdict === item
                      ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>

            <DataRow label="Current verdict" value={verdict?.verdict || 'Not assigned'} />
            <DataRow label="Analyst" value={verdict?.actor || '—'} />
            <DataRow label="Reason" value={verdict?.reason || '—'} />
            <DataRow label="Notes" value={analystData?.note_count ?? 0} />
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
        </>
      )}
    </div>
  );
};

export default InvestigationView;
