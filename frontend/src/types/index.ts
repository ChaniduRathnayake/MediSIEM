export interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user';
  createdAt?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface AuditLogEntry {
  id: string;
  action: 'create_user' | 'update_user' | 'delete_user';
  actor: { id: string; name?: string; email?: string };
  target: { id?: string; name?: string; email?: string };
  details: string;
  createdAt: string;
}

export interface ApiResponse<T = unknown> {
  message?: string;
  error?: string;
  data?: T;
}
