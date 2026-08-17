import { BASE_URL } from './api';

export interface SystemSettings {
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    user: string;
    fromAddress: string;
    passConfigured: boolean;
  };
  notifyEmailRecipients: string[];
  slackConfigured: boolean;
  teamsConfigured: boolean;
  anthropicConfigured: boolean;
  abuseIpdbConfigured: boolean;
  mfaRequiredForAdmin: boolean;
  lockout: { maxAttempts: number; lockDurationMinutes: number };
  notifyOnImmediateCas: boolean;
  notifyChannels: { email: boolean; slack: boolean; teams: boolean };
  updatedBy?: { id: string; name: string } | null;
  updatedAt: string | null;
}

// Every *WebhookUrl/*ApiKey/smtp.pass field follows the same write
// convention as the backend route: omit to leave untouched, '' to clear,
// a non-empty string to replace. Never present in a GET response — see
// SystemSettings.passConfigured/*Configured booleans instead.
export interface SystemSettingsUpdate {
  smtp?: Partial<{ host: string; port: number; secure: boolean; user: string; pass: string; fromAddress: string }>;
  notifyEmailRecipients?: string[];
  slackWebhookUrl?: string;
  teamsWebhookUrl?: string;
  anthropicApiKey?: string;
  abuseIpdbApiKey?: string;
  mfaRequiredForAdmin?: boolean;
  lockout?: Partial<{ maxAttempts: number; lockDurationMinutes: number }>;
  notifyOnImmediateCas?: boolean;
  notifyChannels?: Partial<{ email: boolean; slack: boolean; teams: boolean }>;
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

export const apiGetSettings = (token: string) => request<{ settings: SystemSettings }>('/settings', token);

export const apiUpdateSettings = (token: string, payload: SystemSettingsUpdate) =>
  request<{ settings: SystemSettings }>('/settings', token, { method: 'PATCH', body: JSON.stringify(payload) });

export const apiTestEmail = (token: string, to?: string) =>
  request<{ sent: boolean }>('/settings/test-email', token, { method: 'POST', body: JSON.stringify(to ? { to } : {}) });

export const apiTestWebhook = (token: string, channel: 'slack' | 'teams') =>
  request<{ sent: boolean }>('/settings/test-webhook', token, { method: 'POST', body: JSON.stringify({ channel }) });
