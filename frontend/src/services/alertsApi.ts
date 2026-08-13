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
  action: 'Immediate' | 'Investigate' | 'Monitor';
  explanation: string;
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
  // The full 45-column CICIoT2023 feature vector this alert was scored from —
  // same fields ai_server/src/app.py's FEATURE_COLUMNS lists. Not typed field
  // by field since it's a pass-through of whatever the model actually used.
  flow?: Record<string, number | string>;
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
