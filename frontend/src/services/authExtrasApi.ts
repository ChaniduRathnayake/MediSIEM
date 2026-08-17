// MFA enrollment/verification + forgot/reset-password — split out from
// api.ts since these have no mock-fallback demo path.
import { BASE_URL } from './api';
import type { User } from '../types';

async function request<T>(path: string, init?: RequestInit, token?: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init?.headers ?? {}) },
  });
  const json = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json as T;
}

export const apiVerifyMfa = (mfaToken: string, code: string) =>
  request<{ token: string; user: User }>('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ mfaToken, code }) });

export const apiMfaSetup = (token: string) =>
  request<{ secret: string; qrDataUrl: string }>('/auth/mfa/setup', { method: 'POST' }, token);

export const apiMfaConfirm = (token: string, code: string) =>
  request<{ message: string; backupCodes: string[] }>('/auth/mfa/confirm', { method: 'POST', body: JSON.stringify({ code }) }, token);

export const apiMfaDisable = (token: string, password: string) =>
  request<{ message: string }>('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ password }) }, token);

// ─── Admin-initiated MFA control (Users tab → Configure 2FA, non-admin targets only) ──
export const apiSetUserMfaRequired = (token: string, userId: string, required: boolean) =>
  request<{ user: User }>(`/users/${userId}/mfa-required`, { method: 'PATCH', body: JSON.stringify({ required }) }, token);

export const apiAdminResetUserMfa = (token: string, userId: string) =>
  request<{ user: User }>(`/users/${userId}/mfa-reset`, { method: 'POST' }, token);

export const apiForgotPassword = (email: string) =>
  request<{ message: string }>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });

export const apiResetPassword = (resetToken: string, password: string) =>
  request<{ message: string }>(`/auth/reset-password/${resetToken}`, { method: 'POST', body: JSON.stringify({ password }) });
