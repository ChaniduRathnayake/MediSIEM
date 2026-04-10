import type { LoginPayload, RegisterPayload, User } from '../types';

/**
 * Base URL for the backend API.
 * In development, the backend runs at http://localhost:5001.
 * Change this to your deployed backend URL in production.
 *
 * For demo/preview purposes (no backend running), the service
 * falls back to a local mock implementation below.
 */
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001/api';

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
export async function apiLogin(payload: LoginPayload): Promise<{ token: string; user: User }> {
  try {
    return await request('/auth/login', { method: 'POST', body: JSON.stringify(payload) });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      // Mock fallback
      const found = mockUsers.find(
        (u) => u.email.toLowerCase() === payload.email.toLowerCase() && u.password === payload.password
      );
      if (!found) throw new Error('Invalid credentials.');
      const { password: _, ...user } = found;
      return { token: mockToken(user), user };
    }
    throw err;
  }
}

export async function apiRegister(payload: RegisterPayload): Promise<{ token: string; user: User }> {
  try {
    return await request('/auth/register', { method: 'POST', body: JSON.stringify(payload) });
  } catch (err: unknown) {
    if (err instanceof Error && err.message === '__USE_MOCK__') {
      // Mock fallback
      if (!payload.name || !payload.email || !payload.password) throw new Error('All fields are required.');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) throw new Error('Invalid email format.');
      if (payload.password.length < 8) throw new Error('Password must be at least 8 characters.');
      if (mockUsers.find((u) => u.email.toLowerCase() === payload.email.toLowerCase())) {
        throw new Error('Email already registered.');
      }
      const newUser: User & { password: string } = {
        id: Math.random().toString(36).slice(2),
        name: payload.name.trim(),
        email: payload.email.toLowerCase().trim(),
        password: payload.password,
        role: 'user',
        createdAt: new Date().toISOString(),
      };
      mockUsers.push(newUser);
      const { password: _, ...user } = newUser;
      return { token: mockToken(user), user };
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
