import type { LoginPayload, User, UserRole, AuditLogEntry } from '../types';

const MOCK_ROLE_LABEL: Record<UserRole, string> = { admin: 'Admin', user: 'SOC Analyst', biomed: 'Biomedical Engineer', auditor: 'Auditor' };

/**
 * Base URL for the backend API.
 * In development, the Express backend runs at http://localhost:5000
 * (see backend/server.js's PORT default / backend/.env.example) — port 5001
 * is the separate Python CAAP AI server, not this one.
 * Change this to your deployed backend URL in production.
 *
 * For demo/preview purposes (no backend running), the service
 * falls back to a local mock implementation below.
 */
export const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

// ─── Mock Data (used when backend is unavailable) ─────────────────────────────
const MOCK_USERS: (User & { password: string })[] = [
  {
    id: '1',
    name: 'System Administrator',
    email: 'admin@medisiem.com',
    password: 'Admin@1234',
    role: 'admin',
    createdAt: '2025-01-01T00:00:00.000Z',
  },
  {
    id: '2',
    name: 'SOC Analyst',
    email: 'user@medisiem.com',
    password: 'User@1234',
    role: 'user',
    createdAt: '2025-03-01T00:00:00.000Z',
  },
];

let mockUsers = [...MOCK_USERS];
let mockAuditLog: AuditLogEntry[] = [];

// Simple mock JWT (not secure – for demo only)
function mockToken(user: User): string {
  const payload = btoa(JSON.stringify({ id: user.id, email: user.email, role: user.role, name: user.name, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  return `mock.${payload}.signature`;
}

function decodeMockToken(token: string): User | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Date.now()) return null;
    return { id: payload.id, email: payload.email, role: payload.role, name: payload.name };
  } catch {
    return null;
  }
}

// Mirrors the backend's admin-action audit trail for the mock fallback.
function pushMockAudit(token: string, action: AuditLogEntry['action'], target: AuditLogEntry['target'], details: string) {
  const actor = decodeMockToken(token);
  if (!actor || actor.role !== 'admin') return;
  mockAuditLog = [
    {
      id: Math.random().toString(36).slice(2),
      action,
      actor: { id: actor.id, name: actor.name, email: actor.email },
      target,
      details,
      createdAt: new Date().toISOString(),
    },
    ...mockAuditLog,
  ];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      ...options,
    });
    clearTimeout(timeout);

    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Request failed');
    return json as T;
  } catch (err: unknown) {
    clearTimeout(timeout);
    if (err instanceof Error && (err.name === 'AbortError' || err.message.includes('fetch') || err.message.includes('Failed'))) {
      throw new Error('__USE_MOCK__');
    }
    throw err;
  }
}

// ─── Auth API ─────────────────────────────────────────────────────────────────
// When the account has two-factor enabled, the backend returns a short-lived
// mfaToken instead of a real session — see AuthContext.login()/verifyMfa().
// mfaRequired is a literal discriminant on both branches (rather than an
// optional/absent field) so TypeScript can narrow the union cleanly.
export type LoginResult =
  | { mfaRequired: false; token: string; user: User }
  | { mfaRequired: true; mfaToken: string };

export async function apiLogin(payload: LoginPayload): Promise<LoginResult> {
  try {
    const result = await request<{ token?: string; user?: User; mfaRequired?: boolean; mfaToken?: string }>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify(payload) }
    );
    if (result.mfaRequired && result.mfaToken) {
      return { mfaRequired: true, mfaToken: result.mfaToken };
    }
    return { mfaRequired: false, token: result.token!, user: result.user! };
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      // Mock fallback
      const found = mockUsers.find(
        (u) => u.email.toLowerCase() === payload.email.toLowerCase() && u.password === payload.password
      );
      if (!found) throw new Error('Invalid credentials.');
      const { password: _, ...user } = found;
      return { mfaRequired: false, token: mockToken(user), user };
    }
    throw err;
  }
}

export async function apiGetMe(token: string): Promise<{ user: User }> {
  try {
    return await request('/auth/me', { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` } });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      const user = decodeMockToken(token);
      if (!user) throw new Error('Invalid token.');
      return { user };
    }
    throw err;
  }
}

// ─── User Management API ───────────────────────────────────────────────────────
export async function apiGetAllUsers(token: string): Promise<{ users: User[] }> {
  try {
    return await request('/users', {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      return { users: mockUsers.map(({ password: _, ...u }) => u) };
    }
    throw err;
  }
}

export async function apiCreateUser(
  token: string,
  payload: { name: string; email: string; password: string; role: UserRole }
): Promise<{ user: User }> {
  try {
    return await request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      if (!payload.name || !payload.email || !payload.password) throw new Error('Name, email and password are required.');
      if (payload.password.length < 8) throw new Error('Password must be at least 8 characters.');
      if (mockUsers.find((u) => u.email.toLowerCase() === payload.email.toLowerCase())) {
        throw new Error('Email already registered.');
      }
      const newUser: User & { password: string } = {
        id: Math.random().toString(36).slice(2),
        name: payload.name.trim(),
        email: payload.email.toLowerCase().trim(),
        password: payload.password,
        role: payload.role || 'user',
        createdAt: new Date().toISOString(),
      };
      mockUsers.push(newUser);
      const { password: _, ...user } = newUser;
      pushMockAudit(token, 'create_user', { id: user.id, name: user.name, email: user.email }, `Created as ${MOCK_ROLE_LABEL[user.role] ?? user.role}`);
      return { user };
    }
    throw err;
  }
}

export async function apiUpdateUser(
  token: string,
  id: string,
  payload: { name?: string; email?: string; password?: string; currentPassword?: string; role?: UserRole }
): Promise<{ user: User }> {
  try {
    return await request(`/users/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      const idx = mockUsers.findIndex((u) => u.id === id);
      if (idx === -1) throw new Error('User not found.');
      if (payload.password) {
        if (payload.currentPassword !== undefined && mockUsers[idx].password !== payload.currentPassword) {
          throw new Error('Current password is incorrect.');
        }
        if (payload.password.length < 8) throw new Error('Password must be at least 8 characters.');
      }
      if (payload.email && mockUsers.some((u) => u.id !== id && u.email.toLowerCase() === payload.email!.toLowerCase())) {
        throw new Error('Email already registered.');
      }
      const before = mockUsers[idx];
      const updated = {
        ...before,
        ...(payload.name ? { name: payload.name.trim() } : {}),
        ...(payload.email ? { email: payload.email.toLowerCase().trim() } : {}),
        ...(payload.password ? { password: payload.password } : {}),
        ...(payload.role ? { role: payload.role } : {}),
      };
      mockUsers[idx] = updated;
      const { password: _, ...user } = updated;

      const changes: string[] = [];
      if (payload.name && updated.name !== before.name) changes.push(`name "${before.name}" → "${updated.name}"`);
      if (payload.email && updated.email !== before.email) changes.push(`email "${before.email}" → "${updated.email}"`);
      if (payload.role && updated.role !== before.role) changes.push(`role "${before.role}" → "${updated.role}"`);
      if (payload.password) changes.push('password changed');
      if (changes.length > 0) {
        pushMockAudit(token, 'update_user', { id: user.id, name: user.name, email: user.email }, changes.join(', '));
      }

      return { user };
    }
    throw err;
  }
}

export async function apiDeleteUser(token: string, id: string): Promise<{ message: string }> {
  try {
    return await request(`/users/${id}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      const idx = mockUsers.findIndex((u) => u.id === id);
      if (idx === -1) throw new Error('User not found.');
      const [removed] = mockUsers.splice(idx, 1);
      pushMockAudit(token, 'delete_user', { id: removed.id, name: removed.name, email: removed.email }, `Deleted ${removed.role === 'admin' ? 'Admin' : 'SOC Analyst'} account`);
      return { message: 'User deleted successfully.' };
    }
    throw err;
  }
}

// ─── Presence API ───────────────────────────────────────────────────────────
export interface PresenceBucket {
  online: number;
  total: number;
}

export interface PresenceRosterEntry {
  id: string;
  name: string;
  email: string;
  online: boolean;
  lastActiveAt: string | null;
}

export interface PresenceSummary {
  admins: PresenceBucket;
  analysts: PresenceBucket;
  biomed: PresenceBucket;
  auditors: PresenceBucket;
  thresholdMs: number;
  // Only populated for admin callers — everyone else gets counts only.
  roster?: {
    admins: PresenceRosterEntry[];
    analysts: PresenceRosterEntry[];
    biomed: PresenceRosterEntry[];
    auditors: PresenceRosterEntry[];
  };
}

export async function apiGetPresenceSummary(token: string): Promise<PresenceSummary> {
  try {
    return await request('/users/presence', {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      // Demo fallback: no real session tracking in mock mode, so just report
      // the signed-in mock user as the only "online" member of their role.
      const admins = mockUsers.filter((u) => u.role === 'admin');
      const analysts = mockUsers.filter((u) => u.role === 'user');
      const biomed = mockUsers.filter((u) => u.role === 'biomed');
      const auditors = mockUsers.filter((u) => u.role === 'auditor');
      const actor = decodeMockToken(token);
      const toRoster = (list: typeof mockUsers): PresenceRosterEntry[] =>
        list.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          online: actor?.id === u.id,
          lastActiveAt: actor?.id === u.id ? new Date().toISOString() : null,
        }));
      const bucketOf = (list: typeof mockUsers) => ({ online: list.some((u) => u.id === actor?.id) ? 1 : 0, total: list.length });
      return {
        admins: bucketOf(admins),
        analysts: bucketOf(analysts),
        biomed: bucketOf(biomed),
        auditors: bucketOf(auditors),
        thresholdMs: 2 * 60 * 1000,
        roster: actor?.role === 'admin'
          ? { admins: toRoster(admins), analysts: toRoster(analysts), biomed: toRoster(biomed), auditors: toRoster(auditors) }
          : undefined,
      };
    }
    throw err;
  }
}

export async function apiGetAuditLog(token: string): Promise<{ logs: AuditLogEntry[] }> {
  try {
    return await request('/audit-log', {
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      return { logs: mockAuditLog };
    }
    throw err;
  }
}
