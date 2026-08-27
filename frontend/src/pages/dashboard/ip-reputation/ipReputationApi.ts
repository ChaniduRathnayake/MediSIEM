// Client for the MedShield IP Reputation Intelligence service, proxied through
// backend/routes/ipReputation.js (mounted at /api/ip-reputation, `protect`-gated —
// a real MediSIEM login is required, unlike the original standalone app which had
// no auth at all). The proxy forwards everything after the prefix straight to
// `${IP_REPUTATION_SERVICE_URL}/api/v1<path>`, so every path here is the FastAPI
// service's original route with its `/api/v1` prefix stripped off.
import { BASE_URL } from '../../../services/api';

const PROXY = `${BASE_URL}/ip-reputation`;

// Same storage key AuthContext.tsx / wazuhApi.ts use.
function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('medisiem_token') ?? '';
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${PROXY}${path}`, { headers: authHeaders(), ...options });
  } catch (networkErr) {
    // fetch() itself throws only on network-level failures (backend unreachable)
    throw new Error(
      `Cannot reach the MediSIEM backend at ${PROXY}. Make sure the Express server ` +
      `and the IP Reputation service are running. (${(networkErr as Error).message})`
    );
  }

  const contentType = res.headers.get('content-type') || '';
  const data: unknown = contentType.includes('application/json')
    ? await res.json().catch(() => null)
    : await res.text().catch(() => null);

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    if (data && typeof data === 'object') {
      const obj = data as { detail?: unknown; error?: unknown; message?: unknown };
      message = String(obj.detail ?? obj.error ?? obj.message ?? message);
    } else if (typeof data === 'string' && data.trim()) {
      message = data;
    }
    throw new Error(message);
  }

  return data as T;
}

// ─── IP classification ──────────────────────────────────────────────────────
export interface IpClassification {
  ip: string;
  version: number;
  category: string;
  is_global: boolean;
  is_private: boolean;
  is_loopback: boolean;
  is_link_local: boolean;
  is_multicast: boolean;
  is_reserved: boolean;
  is_unspecified: boolean;
  external_reputation_applicable: boolean;
  reason: string;
}

// ─── Threat intelligence providers ──────────────────────────────────────────
export interface ProviderResult {
  provider: string;
  configured: boolean;
  available: boolean;
  status: string;
  http_status?: number | null;
  error?: string | null;
  evidence?: Record<string, unknown> | null;
}

export interface ProviderSummary {
  configured: number;
  successful: number;
  total: number;
}

export interface ThreatIntelligenceResult {
  providers: Record<string, ProviderResult>;
  provider_summary: ProviderSummary;
}

export interface AbuseIpdbEvidence {
  abuse_confidence_score?: number;
  total_reports?: number;
  distinct_reporters?: number;
  isp?: string;
  country_code?: string;
  [key: string]: unknown;
}

export interface VirusTotalEvidence {
  last_analysis_stats?: { malicious?: number; suspicious?: number; total?: number; [key: string]: unknown };
  asn?: string | number;
  as_owner?: string;
  [key: string]: unknown;
}

// ─── Reputation engine ───────────────────────────────────────────────────────
export interface ReputationSignal {
  provider: string;
  signal: number;
  evidence: Record<string, unknown>;
}

export interface ReputationAnalysis {
  score?: number | null;
  score_based_risk_level?: string | null;
  evidence_floor_level?: string | null;
  risk_level: string;
  decision: string;
  confidence: string;
  provider_agreement: string;
  provider_signal_count: number;
  signals: ReputationSignal[];
  explanation: string[];
  recommended_action: string;
}

// ─── Internal intelligence (allow / watch / block) ──────────────────────────
export interface ListEntry {
  _id: string;
  ip: string;
  list_type: string;
  reason?: string;
  actor: string;
  created_at: string;
  updated_at: string;
}

export interface InternalIntelligence {
  matched: boolean;
  memberships: string[];
  effective_status: string;
  operational_disposition: string;
  conflict: boolean;
  message: string;
  entries: ListEntry[];
}

// ─── Main lookup response ───────────────────────────────────────────────────
export interface ReputationLookupResponse {
  ip: string;
  classification: IpClassification;
  reputation_status: string;
  reputation_score: number | null;
  risk_level: string | null;
  confidence: string | null;
  threat_intelligence: ThreatIntelligenceResult | null;
  reputation_analysis: ReputationAnalysis | null;
  internal_intelligence: InternalIntelligence | null;
  explanation: string[];
}

export interface HistoryItem {
  _id: string;
  ip: string;
  observed_at: string;
  reputation_score?: number | null;
  risk_level?: string | null;
  confidence?: string | null;
  [key: string]: unknown;
}

// ─── Analyst intelligence ────────────────────────────────────────────────────
export interface AnalystVerdict {
  _id?: string;
  ip: string;
  verdict: string;
  reason?: string;
  actor: string;
  created_at?: string;
}

export interface AnalystNote {
  _id?: string;
  ip: string;
  note: string;
  actor: string;
  created_at?: string;
}

export interface AnalystIntelligence {
  ip: string;
  current_verdict: AnalystVerdict | null;
  note_count: number;
  verdict_count: number;
  notes: AnalystNote[];
  verdict_history: AnalystVerdict[];
}

// ─── Local ML / healthcare-context correlation + MIRS ───────────────────────
export interface MirsDimension {
  score?: number | null;
  effective_weight?: number | null;
  base_weight?: number | null;
}

export interface MirsBreakdown {
  components?: Record<string, number>;
  dimensions?: Record<string, MirsDimension>;
  configured_weights?: Record<string, number>;
  effective_weights?: Record<string, number>;
  availability?: Record<string, boolean>;
}

export interface MirsEvidence {
  available: boolean;
  status: string;
  message?: string;
  latest_score?: number | null;
  max_score?: number | null;
  average_score?: number | null;
  risk_band?: string | null;
  latest_aps?: number | null;
  max_aps?: number | null;
  ml_fusion_enabled?: boolean;
  feature_coverage?: number | null;
  real_feature_coverage?: number | null;
  timestamp?: string | null;
  flow_id?: string | null;
  src_ip?: string | null;
  dest_ip?: string | null;
  breakdown?: MirsBreakdown;
  flow_reputation?: { enriched_ip?: string; score?: number | null; [key: string]: unknown } | null;
  healthcare_context?: { known?: boolean; [key: string]: unknown } | null;
  explanations?: string[];
}

export interface CorrelationEvent {
  id: string;
  timestamp?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  protocol?: string | null;
  application?: string | null;
  risk_level?: string | null;
  operational_priority?: string | null;
  random_forest?: { prediction?: string | null; attack_probability?: number | null; confidence?: number | null };
  isolation_forest?: { prediction?: string | null; anomaly_score?: number | null; anomaly_score_normalised?: number | null };
  context_risk_score?: number | null;
  context_risk_level?: string | null;
  [key: string]: unknown;
}

export interface CorrelationSummary {
  max_rf_attack_probability?: number | null;
  max_if_anomaly_score?: number | null;
  average_feature_coverage?: number | null;
  average_real_feature_coverage?: number | null;
  max_context_risk_score?: number | null;
  max_healthcare_context_score?: number | null;
  latest_mirs?: number | null;
  max_mirs?: number | null;
  latest_aps?: number | null;
  latest_context_risk_level?: string | null;
  latest_operational_priority?: string | null;
  latest_assessment_mode?: string | null;
  latest_timestamp?: string | null;
}

export interface CorrelationResult {
  available: boolean;
  status: string;
  ip?: string;
  error?: string;
  records_scanned?: number;
  matched_event_count: number;
  source_matches?: number;
  destination_matches?: number;
  ml_fusion_observed?: boolean;
  mirs_evidence?: MirsEvidence;
  summary?: CorrelationSummary | null;
  events?: CorrelationEvent[];
}

// ─── Wazuh / Suricata evidence ───────────────────────────────────────────────
export interface WazuhRuleRef {
  id?: string;
  level?: number;
  description?: string;
  groups?: string[];
}

export interface SuricataAlertRef {
  signature?: string;
  signature_id?: string | number;
  category?: string;
  severity?: string | number;
}

export interface WazuhAlertEvidence {
  document_id: string;
  timestamp?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  protocol?: string | null;
  app_proto?: string | null;
  direction?: string | null;
  wazuh_rule?: WazuhRuleRef;
  suricata_alert?: SuricataAlertRef;
  medshield_log_source?: string | null;
}

export interface WazuhEvidenceResult {
  ip: string;
  available: boolean;
  status: string;
  error?: string;
  http_status?: number;
  matched_alert_count: number;
  suricata_alert_count?: number;
  highest_rule_level?: number | null;
  latest_alert_timestamp?: string | null;
  top_rules?: { description: string; count: number }[];
  alerts?: WazuhAlertEvidence[];
}

// ─── Operational risk assessment ────────────────────────────────────────────
export interface OperationalAssessment {
  operational_risk_level: string;
  decision: string;
  dimensions?: {
    external_reputation?: string;
    local_ml_context?: string;
    wazuh_suricata?: string;
    internal_intelligence?: string;
    analyst_verdict?: string;
  };
  confidence?: string;
  evidence_dimensions?: number;
  cross_signal_escalation?: boolean;
  recommended_action?: string;
  reasons?: string[];
}

export interface OperationalResult {
  ip: string;
  classification: IpClassification;
  external_reputation: { available: boolean; score: number | null; risk_level: string; confidence: string };
  local_ml_context: { available: boolean; status?: string; matched_event_count: number; summary?: CorrelationSummary | null };
  wazuh_suricata: {
    available: boolean;
    status?: string;
    matched_alert_count: number;
    suricata_alert_count: number;
    highest_rule_level?: number | null;
    latest_alert_timestamp?: string | null;
    top_rules?: { description: string; count: number }[];
  };
  internal_intelligence: InternalIntelligence | null;
  analyst_intelligence: AnalystIntelligence | null;
  operational_assessment: OperationalAssessment;
}

// ─── Cases ────────────────────────────────────────────────────────────────────
// NOTE: these are IP-reputation-scoped investigation cases stored in the FastAPI
// service's own `cases` Mongo collection — unrelated to MediSIEM's AdminCasesPanel
// incident-case feature (different data model, different collection, different DB).
export interface CaseItem {
  _id: string;
  ip: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  created_by?: string;
  assigned_to?: string;
  created_at?: string;
  updated_at?: string;
  closed_at?: string | null;
  reputation_snapshot?: { score?: number | null; risk_level?: string | null; confidence?: string | null; last_seen?: string | null } | null;
}

// ─── Audit trail ──────────────────────────────────────────────────────────────
export interface AuditEvent {
  _id: string;
  action: string;
  subject?: string;
  actor?: string;
  details?: Record<string, unknown>;
  created_at?: string;
}

// ─── Log sources ──────────────────────────────────────────────────────────────
export interface LogSource {
  id: string;
  name: string;
  type: string;
  endpoint?: string;
  status: string;
  reachable: boolean;
  checked_at?: string;
  records_available: number;
  latest_event_timestamp?: string | null;
  ml_fusion_observed: boolean;
  average_feature_coverage?: number | null;
  message?: string | null;
  http_status?: number;
}

export interface LogSourcesResult {
  count: number;
  healthy: number;
  degraded: number;
  unavailable: number;
  sources: LogSource[];
}

// ─── Observed IP intelligence profiles (Overview) ───────────────────────────
export interface IntelligenceProfile {
  _id: string;
  ip: string;
  classification?: { category?: string; version?: number; [key: string]: unknown };
  current_risk_level?: string | null;
  current_score?: number | null;
  confidence?: string | null;
  observation_count?: number;
  last_seen?: string | null;
  latest_reputation_analysis?: { decision?: string; [key: string]: unknown } | null;
  [key: string]: unknown;
}

// ─── Threat Hunt ──────────────────────────────────────────────────────────────
export interface ThreatHuntFilters {
  hours: string;
  ip: string;
  src_ip: string;
  dest_ip: string;
  min_level: string;
  rule_id: string;
  signature: string;
  signature_id: string;
  protocol: string;
  app_proto: string;
  direction: string;
}

export type ThreatHuntAlert = WazuhAlertEvidence;

export interface ThreatHuntResult {
  status: string;
  total_matches?: number;
  returned_count?: number;
  suricata_alert_count?: number;
  highest_rule_level?: number | null;
  unique_source_ips?: number;
  unique_destination_ips?: number;
  top_rules?: { description: string; count: number }[];
  top_signatures?: { signature: string; count: number }[];
  alerts?: ThreatHuntAlert[];
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function lookupIp(ip: string): Promise<ReputationLookupResponse> {
  return request<ReputationLookupResponse>('/reputation/lookup', {
    method: 'POST',
    body: JSON.stringify({ ip }),
  });
}

export async function getIntelligenceHistory(ip: string, limit = 50): Promise<{ ip: string; count: number; limit: number; history: HistoryItem[] }> {
  return request(`/intelligence/${encodeURIComponent(ip)}/history?limit=${limit}`);
}

export async function getAnalystIntelligence(ip: string): Promise<{ status: string; analyst_intelligence: AnalystIntelligence }> {
  return request(`/analyst/${encodeURIComponent(ip)}`);
}

export async function getCorrelation(ip: string, limit = 100): Promise<CorrelationResult> {
  return request(`/correlation/${encodeURIComponent(ip)}?limit=${limit}`);
}

export async function getWazuhEvidence(ip: string, limit = 20): Promise<WazuhEvidenceResult> {
  return request(`/wazuh/${encodeURIComponent(ip)}?limit=${limit}`);
}

export async function getOperationalAssessment(ip: string, localLimit = 100, wazuhLimit = 20): Promise<OperationalResult> {
  return request(`/operational/${encodeURIComponent(ip)}?local_limit=${localLimit}&wazuh_limit=${wazuhLimit}`);
}

export async function setReputationList(payload: { ip: string; list_type: string; reason: string; actor: string }): Promise<{ status: string; entry: ListEntry }> {
  return request('/lists', { method: 'POST', body: JSON.stringify(payload) });
}

export async function getAllLists(listType?: string): Promise<{ count: number; items: ListEntry[] }> {
  const qs = listType ? `?list_type=${encodeURIComponent(listType)}` : '';
  return request(`/lists${qs}`);
}

export async function removeListEntry(listType: string, ip: string, actor = 'analyst01'): Promise<unknown> {
  return request(`/lists/${encodeURIComponent(listType)}/${encodeURIComponent(ip)}?actor=${encodeURIComponent(actor)}`, {
    method: 'DELETE',
  });
}

export async function setAnalystVerdict(payload: { ip: string; verdict: string; reason: string; actor: string }): Promise<{ status: string; verdict: AnalystVerdict }> {
  return request('/analyst/verdict', { method: 'POST', body: JSON.stringify(payload) });
}

export async function addAnalystNote(payload: { ip: string; note: string; actor: string }): Promise<{ status: string; note: AnalystNote }> {
  return request('/analyst/note', { method: 'POST', body: JSON.stringify(payload) });
}

export async function createCase(payload: { ip: string; title: string; description: string; severity: string; actor: string }): Promise<{ status: string; case: CaseItem }> {
  return request('/cases', { method: 'POST', body: JSON.stringify(payload) });
}

export async function listCases(limit = 100, status?: string): Promise<{ count: number; cases: CaseItem[] }> {
  const qs = new URLSearchParams({ limit: String(limit) });
  if (status) qs.set('status', status);
  return request(`/cases?${qs.toString()}`);
}

export async function updateCaseStatus(caseId: string, payload: { status: string; reason: string; actor: string }): Promise<{ status: string; case: CaseItem }> {
  return request(`/cases/${encodeURIComponent(caseId)}/status`, { method: 'PATCH', body: JSON.stringify(payload) });
}

export async function getIntelligenceProfiles(limit = 500): Promise<{ count: number; limit: number; profiles: IntelligenceProfile[] }> {
  return request(`/intelligence?limit=${limit}`);
}

export async function getAuditEvents(limit = 100): Promise<{ count: number; events: AuditEvent[] }> {
  return request(`/audit?limit=${limit}`);
}

export async function getLogSources(): Promise<LogSourcesResult> {
  return request('/log-sources');
}

export async function threatHunt(filters: ThreatHuntFilters, limit = 100): Promise<ThreatHuntResult> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    const clean = String(value ?? '').trim();
    if (clean) params.set(key, clean);
  });
  params.set('limit', String(limit));
  return request(`/threat-hunt?${params.toString()}`);
}

// ─── MEDSHIELD LIVE CORRELATION FEED ────────────────────────────────────────
// Current :8088 contract:
// GET /api/v1/correlation/live-feed
// This is an IP-centric live evidence feed. Each row represents a recently
// observed public IP and embeds the latest matching flow plus local ML evidence.

export interface LiveCorrelationFlow {
  src_ip?: string | null;
  src_port?: number | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  protocol?: string | null;
  application?: string | null;
  flow_id?: number | string | null;
}

export interface LiveCorrelationFeedItem {
  ip: string;
  flow_count: number;
  source_matches: number;
  destination_matches: number;

  latest_timestamp?: string | null;

  latest_risk_level?: string | null;

  latest_mirs?: number | null;
  max_mirs?: number | null;

  latest_aps?: number | null;
  max_aps?: number | null;

  latest_rf_prediction?: string | null;
  latest_rf_attack_probability?: number | null;
  max_rf_attack_probability?: number | null;

  latest_if_prediction?: string | null;
  latest_if_anomaly_score?: number | null;
  max_if_anomaly_score?: number | null;

  ml_fusion_observed: boolean;

  latest_real_feature_coverage?: number | null;
  latest_supplied_feature_coverage?: number | null;

  latest_flow?: LiveCorrelationFlow | null;

  risk_band?: string | null;
  suspicious: boolean;
}

export interface LiveCorrelationFeedResult {
  available: boolean;
  status: string;
  records_scanned: number;
  unique_public_ips: number;
  returned_count: number;
  suspicious_count: number;
  items: LiveCorrelationFeedItem[];
}

export async function getLiveCorrelationFeed(
  scanLimit = 1000,
  maxItems = 100,
): Promise<LiveCorrelationFeedResult> {
  const params = new URLSearchParams({
    scan_limit: String(scanLimit),
    max_items: String(maxItems),
  });

  return request(`/correlation/live-feed?${params.toString()}`);
}
