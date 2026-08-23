import { BASE_URL } from './api';

export interface AssignedAnalyst {
  id: string;
  name: string;
  email: string;
}

// The analyst's own judgment of whether this was a real detection — the
// one piece of ground truth this system captures about its own accuracy,
// as opposed to the device-criticality proxy the live Detection
// Performance metrics use. Optional: closures made before this field
// existed have none.
export type AlertVerdict = 'true_positive' | 'false_positive' | 'benign' | 'uncertain';

export interface AlertClosure {
  id: string;
  reason: string;
  evidence: string;
  verdict?: AlertVerdict | null;
  closedBy: { id: string; name: string; email: string };
  createdAt: string;
}

export interface EnrichedAlert {
  id: string;
  timestamp: string;
  agent: string;
  department: string;
  // Resolved from the admin-managed MedicalDevice inventory (same lookup CAS
  // scoring uses) — absent/'Unknown Device' when the source agent isn't
  // onboarded there yet.
  deviceType?: string;
  // 'critical' | 'high' | 'medium' | 'low' — drives the "life-critical
  // device" badge independent of whatever CAS the alert scored.
  deviceCriticality?: string;
  ruleDescription: string;
  ruleLevel: number | null;
  // Repeats of the same rule+device+source within a short window are folded
  // into the original occurrence instead of appearing as separate rows —
  // see DEDUP_WINDOW_MS in backend/services/alertPipeline.js. 1 (or absent,
  // for alerts from before this existed) means no repeats were folded in.
  duplicateCount?: number;
  // Present when Wazuh's ruleset tags this rule with a MITRE ATT&CK mapping.
  mitre?: { id: string[]; tactic: string[]; technique: string[] } | null;
  label: string;
  confidence: number | null;
  TR_score: number;
  TS_score: number;
  CC_score: number;
  AE_score: number;
  TC_score: number;
  cluster: string;
  CAS: number;
  // CVSS-equivalent baseline, shown alongside CAS for direct comparison — a
  // representative CVSS v3.1 base-score band per classified attack type (no
  // real CVE field exists anywhere in this dataset), clinically blind by
  // design: depends only on attack type, never on device or time. See
  // ai_server/src/cas_config.py's lookup_cvss(). Absent only for alerts
  // scored before this field existed.
  CVSS?: number;
  action: 'Immediate' | 'Investigate' | 'Monitor';
  // Which named weight profile actually produced this CAS score — 'default',
  // one of ai_server/src/cas_config.py's SCENARIO_WEIGHT_PROFILES keys
  // (auto-resolved from the device's department), or 'custom' when an admin
  // has overridden the vector in Settings -> CAS Weights. Absent only for
  // alerts scored before this field existed.
  scenario?: string;
  weights_used?: { TR: number; CC: number; TS: number; AE: number; TC: number };
  // Plain-text SHAP summary — always present when there's a real RF
  // classification behind this alert; a rule.level/AI-unreachable fallback
  // (see caapService.js) sets it to a disclaimer sentence instead.
  explanation: string;
  // Structured form of the same explanation (feature/value/direction, top-3
  // by |value|) — present only alongside a real SHAP result; the two
  // fallback paths in caapService.js that have no real SHAP explicitly
  // strip this field, so its absence means "render the plain-text
  // explanation above", not "still loading".
  shap_top_features?: { feature: string; value: number; direction: 'increases' | 'decreases' }[];
  assignedTo?: AssignedAnalyst | null;
  // true when this is CAS-CRITICAL, still unassigned/open, and has sat that
  // way for 10+ minutes — see ESCALATION_THRESHOLD_MS in routes/alerts.js.
  escalated?: boolean;
  // Present once a SOC analyst (or admin) has closed the case with a reason
  // + evidence — absent/null means the case is still open.
  closure?: AlertClosure | null;
  // Populated by alertPipeline.js's rule evaluator — empty/absent means no
  // custom detection rule matched this alert (it may still be a real ML
  // detection via `confidence`).
  matchedRules?: { id: string; name: string }[];
  // Only present for alerts scored from a real captured network flow
  // (ml-pipeline/flow_consumer.py) — absent for replayed/simulated rows.
  src_ip?: string;
  // AbuseIPDB's 0-100 "confidence of abuse" score for src_ip (see
  // backend/services/ipReputationService.js) — already factored into
  // AE_score, surfaced here too so the analyst can see the raw signal
  // instead of just its effect on a composite number. Absent when there's
  // no src_ip, no AbuseIPDB key configured, or the IP is a private range.
  ipReputationScore?: number | null;
  // The full 45-column CICIoT2023 feature vector this alert was scored from —
  // same fields ai_server/src/app.py's FEATURE_COLUMNS lists. Not typed field
  // by field since it's a pass-through of whatever the model actually used.
  flow?: Record<string, number | string>;
  // Present while the case is snoozed (hidden from the active queue) — see
  // PATCH /api/alerts/:id/snooze. Absent/null once snoozedUntil passes or
  // it's explicitly unsnoozed.
  snoozed?: AlertSnoozeInfo | null;
}

export interface AlertSnoozeInfo {
  snoozedUntil: string;
  reason: string;
  snoozedBy: { id: string; name: string; email: string };
}

export interface AlertNote {
  id: string;
  alertId: string;
  author: { id: string; name: string; email: string };
  text: string;
  mentions: string[];
  createdAt: string;
}

export interface AlertStats {
  totalCount: number;
  severityTotals: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
}

export async function apiGetAlerts(
  token: string,
  limit = 100
): Promise<{ alerts: EnrichedAlert[]; count: number } & AlertStats> {
  const res = await fetch(`${BASE_URL}/alerts?limit=${limit}`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to fetch alerts');
  return json;
}

export async function apiAssignAlert(
  token: string,
  alertId: string,
  analystId: string | null
): Promise<{ assignedTo: AssignedAnalyst | null }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/assign`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ analystId }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to assign alert');
  return json;
}

// Server-streamed CSV (see backend/routes/alerts.js's training-feedback-export
// route) rather than client-built via utils/csv.ts, since the rows come from
// AlertClosure documents the browser never loads in bulk — returns a Blob for
// the caller to trigger a download from, same as any other authenticated file
// fetch (the endpoint needs the bearer token, so a plain <a href> won't work).
export async function apiExportTrainingFeedback(token: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/alerts/training-feedback-export`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(json.error || `HTTP ${res.status}`);
  }
  return res.blob();
}

export async function apiTriageAlert(token: string, alertId: string): Promise<{ explanation: string }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'AI triage assistant request failed');
  return json;
}

export async function apiCloseAlert(
  token: string,
  alertId: string,
  reason: string,
  evidence: string,
  verdict?: AlertVerdict
): Promise<{ closure: AlertClosure }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/close`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ reason, evidence, verdict }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to close case');
  return json;
}

export async function apiGetAlertNotes(token: string, alertId: string): Promise<{ notes: AlertNote[] }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/notes`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to load notes');
  return json;
}

export async function apiAddAlertNote(token: string, alertId: string, text: string): Promise<{ note: AlertNote }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ text }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to add note');
  return json;
}

// Pass minutes: null to unsnooze.
export async function apiSnoozeAlert(
  token: string,
  alertId: string,
  minutes: number | null,
  reason?: string
): Promise<{ snoozed: AlertSnoozeInfo | null }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/snooze`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ minutes, reason }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to snooze alert');
  return json;
}

export interface MyAlertStats {
  totalClosed: number;
  closedThisWeek: number;
  verdictCounts: { true_positive: number; false_positive: number; benign: number; uncertain: number; unset: number };
  avgResolutionMinutes: number | null;
}

export async function apiGetMyStats(token: string): Promise<MyAlertStats> {
  const res = await fetch(`${BASE_URL}/alerts/my-stats`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to load stats');
  return json;
}

// A closed case as returned by the permanent AlertClosure record — same
// shape GET /my-history reconstructs from alertSnapshot, distinct from
// EnrichedAlert since a case this old may have long since aged out of the
// live buffer (see routes/alerts.js's reconstruction logic on GET /).
export interface MyHistoryClosure extends AlertClosure {
  alertId: string;
  alertSnapshot: {
    timestamp: string;
    agent: string;
    department: string;
    ruleDescription: string;
    label: string;
    CAS: number;
  } | null;
}

export interface MyCaseHistoryOptions {
  search?: string;
  from?: string; // ISO date
  to?: string; // ISO date
  limit?: number;
}

// ─── AI assistant (backend/services/aiAssistantService.js) ────────────────────
export interface CloseDraft {
  verdict: AlertVerdict;
  reason: string;
  evidence: string;
}

export async function apiDraftCloseReason(token: string, alertId: string): Promise<{ draft: CloseDraft }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/draft-close`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'AI assistant request failed');
  return json;
}

export async function apiSummarizeNotes(token: string, alertId: string): Promise<{ summary: string }> {
  const res = await fetch(`${BASE_URL}/alerts/${alertId}/summarize-notes`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'AI assistant request failed');
  return json;
}

// Same shape as AlertsPanel's internal AlertsPanelFilters — the AI maps
// free text onto exactly those dimensions, so the result can be fed
// straight into applyFilters().
export interface ParsedAlertQuery {
  severityFilter: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'all';
  departmentFilter: string;
  actionFilter: 'Immediate' | 'Investigate' | 'Monitor' | 'all';
  detectionFilter: 'all' | 'ml' | 'rules' | 'combined';
  sortBy: 'cas' | 'time';
  search: string;
}

export async function apiParseAlertQuery(token: string, prompt: string, departments: string[]): Promise<{ filters: ParsedAlertQuery }> {
  const res = await fetch(`${BASE_URL}/alerts/parse-query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ prompt, departments }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'AI assistant request failed');
  return json;
}

export async function apiGetMyCaseHistory(token: string, opts: MyCaseHistoryOptions | string): Promise<{ closures: MyHistoryClosure[] }> {
  // Accepts a bare search string too — every existing call site (the
  // Closed Cases search box in MyAlertsPanel.tsx) passes just a string.
  const o: MyCaseHistoryOptions = typeof opts === 'string' ? { search: opts } : opts;
  const params = new URLSearchParams();
  if (o.search) params.set('search', o.search);
  if (o.from) params.set('from', o.from);
  if (o.to) params.set('to', o.to);
  if (o.limit) params.set('limit', String(o.limit));
  const res = await fetch(`${BASE_URL}/alerts/my-history?${params.toString()}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to search case history');
  return json;
}
