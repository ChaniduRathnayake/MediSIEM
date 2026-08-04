// frontend/src/services/alertsApi.ts
//
// Add this alongside your existing api.ts functions (same BASE_URL / request()
// helper already defined there — import them instead of redefining if you
// merge this file in).

import { BASE_URL, getStoredToken } from './api'; // adjust names to match your actual exports

export interface EnrichedAlert {
  id: string;
  timestamp: string;
  agent: string;
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
}

export async function apiGetAlerts(limit = 100): Promise<{ alerts: EnrichedAlert[]; count: number }> {
  const token = getStoredToken();
  const res = await fetch(`${BASE_URL}/alerts?limit=${limit}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to fetch alerts');
  return json;
}
