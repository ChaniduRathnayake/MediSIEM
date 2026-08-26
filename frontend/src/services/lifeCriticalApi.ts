import { BASE_URL } from './api';

// Mirrors life-critical-orchestration/engine/src/models/decision.py's Tier enum.
export type LifeCriticalTier = 1 | 2 | 3;

export type LifeCriticalAction =
  | 'log_only'
  | 'block_port'
  | 'isolate_host'
  | 'monitored_mode'
  | 'await_clinician_approval'
  | 'throttle'
  | 'selective_block'
  | 'quarantine';

export interface LifeCriticalDecision {
  decision_id: string;
  decided_at: string;
  alert_id: string;
  asset_id: string;
  tier: LifeCriticalTier;
  action: LifeCriticalAction;
  rationale: string;
  matched_rule: string;
  fail_safe_applied: boolean;
  effective_criticality?: 'non_critical' | 'clinical_support' | 'life_critical' | null;
  effective_criticality_score?: number | null;
  extreme_threat: boolean;
  proposed_action_if_approved?: LifeCriticalAction | null;
  block_dest?: string | null;
  block_ports?: number[] | null;
}

// Loosely typed — this is the engine's own "Enriched Alert" echoed back for
// display, not a MediSIEM model. Only the fields the panel actually renders
// are named; extra="allow" on the engine's Pydantic models means real
// payloads may carry more.
export interface LifeCriticalEchoedAlert {
  alert_id: string;
  timestamp: string;
  source?: { rule_description?: string; rule_level?: number };
  threat?: {
    category?: string;
    cvss_score?: number;
    cas_score?: number;
    technical_severity?: string;
    indicators?: { src_ip?: string; dst_ip?: string; dst_port?: number };
  };
  asset?: { asset_id?: string; hostname?: string; ip_address?: string; department?: string; device_category?: string };
  clinical_context?: { criticality_score?: number; patient_dependency?: string; time_sensitivity?: number; shift?: string };
}

export interface LifeCriticalDecisionItem {
  alert: LifeCriticalEchoedAlert;
  decision: LifeCriticalDecision;
}

export interface LifeCriticalStatus {
  engineReachable: boolean;
  error?: string;
  health?: { status: string; service: string; version: string };
  bridge: {
    pushed: number;
    failed: number;
    lastError: string | null;
    lastErrorAt: string | null;
    lastDecision: { alertId: string; tier: number; action: string; at: string } | null;
    engineUrl: string;
  };
}

export interface ClinicianFollowup {
  kind: 'clinician_response';
  referenced_decision_id: string;
  asset_id: string;
  approved: boolean;
  clinician_id: string;
  final_action: string;
  responded_at: string;
  original_action: string;
  entry_hash?: string;
}

// One row of the engine's durable, hash-chained audit log. Either `decision`
// (an original classification) or `followup` (a clinician response) is
// present, never both — mirrors engine/src/audit/logger.py's entry shape.
export interface AuditEntry {
  logged_at: string;
  previous_hash: string;
  entry_hash: string;
  decision?: LifeCriticalDecision;
  followup?: ClinicianFollowup;
}

export interface ShuffleAction {
  logged_at: string;
  decision_id: string;
  asset_id: string;
  workflow: string;
  step: string;
  status: string;
  detail: string;
  extra?: Record<string, unknown>;
}

async function getJson<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
  return json;
}

export async function apiGetLifeCriticalStatus(token: string): Promise<LifeCriticalStatus> {
  return getJson('/life-critical/status', token);
}

export async function apiGetRecentDecisions(token: string, limit = 50): Promise<{ items: LifeCriticalDecisionItem[] }> {
  return getJson(`/life-critical/recent-decisions?limit=${limit}`, token);
}

export async function apiGetPendingApprovals(token: string): Promise<{ pending: LifeCriticalDecisionItem[] }> {
  return getJson('/life-critical/pending-approvals', token);
}

export async function apiVerifyAuditChain(token: string): Promise<{ ok: boolean; error: string | null }> {
  return getJson('/life-critical/audit-verify', token);
}

export async function apiGetAuditLog(token: string): Promise<{ entries: AuditEntry[] }> {
  return getJson('/life-critical/audit', token);
}

export async function apiGetClinicianDecisions(token: string): Promise<{ byDecisionId: Record<string, ClinicianFollowup> }> {
  return getJson('/life-critical/clinician-decisions', token);
}

// Classify one alert on demand (mirrors the standalone console's stub picker
// posting straight to the engine's POST /decide). `alert` is a full Enriched
// Alert per docs/alert-schema.md.
export async function apiDecideAlert(token: string, alert: Record<string, unknown>): Promise<LifeCriticalDecision> {
  const res = await fetch(`${BASE_URL}/life-critical/decide`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(alert),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Classification failed');
  return json;
}

export async function apiGetShuffleActions(
  token: string,
  assetId: string
): Promise<{ reachable: boolean; actions: ShuffleAction[]; error?: string }> {
  return getJson(`/life-critical/shuffle-actions?assetId=${encodeURIComponent(assetId)}`, token);
}

export async function apiSubmitClinicianDecision(
  token: string,
  decisionId: string,
  approved: boolean
): Promise<{ ok: boolean; entry: unknown; final_action: string }> {
  const res = await fetch(`${BASE_URL}/life-critical/clinician-decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ decisionId, approved }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Clinician decision failed');
  return json;
}
