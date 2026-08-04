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
}

export async function apiGetAlerts(token: string, limit = 100): Promise<{ alerts: EnrichedAlert[]; count: number }> {
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
