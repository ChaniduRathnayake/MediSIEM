import { BASE_URL } from './api';

export interface AssignedAnalyst {
  id: string;
  name: string;
  email: string;
}

export interface EnrichedAlert {
  id: string;
  timestamp: string;
  agent: string;
  department: string;
  ruleDescription: string;
  ruleLevel: number | null;
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
