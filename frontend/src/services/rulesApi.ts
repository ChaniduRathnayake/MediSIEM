import { BASE_URL } from './api';

export type RuleField = 'ruleDescription' | 'ruleLevel' | 'agent' | 'department' | 'CAS' | 'label' | 'action' | 'cluster';
export type RuleOperator = 'contains' | 'equals' | 'gte' | 'lte' | 'gt' | 'lt';

export const RULE_FIELDS: RuleField[] = ['ruleDescription', 'ruleLevel', 'agent', 'department', 'CAS', 'label', 'action', 'cluster'];
export const RULE_OPERATORS: RuleOperator[] = ['contains', 'equals', 'gte', 'lte', 'gt', 'lt'];

// Fields that only make sense with numeric comparison operators — the
// condition-row UI uses this to decide which operators to offer.
export const NUMERIC_RULE_FIELDS: RuleField[] = ['ruleLevel', 'CAS'];

export interface RuleCondition {
  field: RuleField;
  operator: RuleOperator;
  value: string | number;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: RuleCondition[];
  createdBy?: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
}

async function request<T>(path: string, token: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(init?.headers ?? {}) },
  });
  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json as T;
}

export const apiGetRules = (token: string) => request<{ rules: DetectionRule[] }>('/rules', token);

export const apiCreateRule = (
  token: string,
  payload: { name: string; description?: string; conditions: RuleCondition[]; enabled?: boolean }
) => request<{ rule: DetectionRule }>('/rules', token, { method: 'POST', body: JSON.stringify(payload) });

export const apiUpdateRule = (
  token: string,
  id: string,
  payload: Partial<{ name: string; description: string; conditions: RuleCondition[]; enabled: boolean }>
) => request<{ rule: DetectionRule }>(`/rules/${id}`, token, { method: 'PATCH', body: JSON.stringify(payload) });

export const apiDeleteRule = (token: string, id: string) =>
  request<{ ok: true }>(`/rules/${id}`, token, { method: 'DELETE' });

export const apiSeedSampleRules = (token: string) =>
  request<{ inserted: number; skipped: number }>('/rules/seed-samples', token, { method: 'POST' });
