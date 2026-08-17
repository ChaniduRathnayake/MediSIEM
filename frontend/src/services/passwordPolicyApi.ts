import { BASE_URL } from './api';

export interface PasswordPolicy {
  id: string;
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSpecialChar: boolean;
  updatedBy?: { id: string; name: string };
  createdAt: string;
  updatedAt: string;
}

export type PasswordPolicyUpdate = Partial<
  Pick<PasswordPolicy, 'minLength' | 'requireUppercase' | 'requireLowercase' | 'requireNumber' | 'requireSpecialChar'>
>;

async function request<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init?.headers ?? {}) },
  });
  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json as T;
}

// token is optional — the backend route is public (see routes/passwordPolicy.js)
// specifically so the pre-auth reset-password page can show live requirement
// feedback without a session yet.
export const apiGetPasswordPolicy = (token?: string) =>
  request<{ policy: PasswordPolicy }>('/password-policy', token);

export const apiUpdatePasswordPolicy = (token: string, payload: PasswordPolicyUpdate) =>
  request<{ policy: PasswordPolicy }>('/password-policy', token, { method: 'PATCH', body: JSON.stringify(payload) });
