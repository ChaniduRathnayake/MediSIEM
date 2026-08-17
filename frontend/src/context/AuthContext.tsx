import React, { createContext, useContext, useEffect, useReducer, useCallback } from 'react';
import type { User, AuthState, LoginPayload } from '../types';
import { apiLogin, apiGetMe } from '../services/api';
import { apiVerifyMfa } from '../services/authExtrasApi';

// ─── State & Actions ──────────────────────────────────────────────────────────
type Action =
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; token: string } }
  | { type: 'UPDATE_USER'; payload: User }
  | { type: 'LOGOUT' };

const initialState: AuthState = {
  user: null,
  token: localStorage.getItem('medisiem_token'),
  isAuthenticated: false,
  isLoading: true,
};

function authReducer(state: AuthState, action: Action): AuthState {
  switch (action.type) {
    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        isLoading: false,
      };
    case 'UPDATE_USER':
      return { ...state, user: action.payload };
    case 'LOGOUT':
      return { ...initialState, token: null, isLoading: false };
    default:
      return state;
  }
}

// ─── Context ──────────────────────────────────────────────────────────────────
// login() resolves with { mfaRequired: true, mfaToken } instead of
// completing the session when the account has two-factor enabled — the
// caller (LoginPage) shows a second step and calls verifyMfa() to finish.
interface AuthContextValue extends AuthState {
  login: (payload: LoginPayload) => Promise<{ mfaRequired: boolean; mfaToken?: string }>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  // Re-fetches /auth/me — called after enabling/disabling MFA so
  // user.mfaEnabled/mfaSetupRequired reflect the change immediately instead
  // of waiting for the next full page load.
  refreshUser: () => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

// ─── Provider ─────────────────────────────────────────────────────────────────
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Restore session on mount
  useEffect(() => {
    const restore = async () => {
      const token = localStorage.getItem('medisiem_token');
      if (!token) {
        dispatch({ type: 'SET_LOADING', payload: false });
        return;
      }
      try {
        const data = await apiGetMe(token);
        dispatch({ type: 'LOGIN_SUCCESS', payload: { user: data.user, token } });
      } catch {
        localStorage.removeItem('medisiem_token');
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    };
    restore();
  }, []);

  const login = useCallback(async (payload: LoginPayload) => {
    const data = await apiLogin(payload);
    if (data.mfaRequired) {
      return { mfaRequired: true as const, mfaToken: data.mfaToken };
    }
    localStorage.setItem('medisiem_token', data.token);
    dispatch({ type: 'LOGIN_SUCCESS', payload: { user: data.user, token: data.token } });
    return { mfaRequired: false as const };
  }, []);

  const verifyMfa = useCallback(async (mfaToken: string, code: string) => {
    const data = await apiVerifyMfa(mfaToken, code);
    localStorage.setItem('medisiem_token', data.token);
    dispatch({ type: 'LOGIN_SUCCESS', payload: { user: data.user, token: data.token } });
  }, []);

  const refreshUser = useCallback(async () => {
    const token = localStorage.getItem('medisiem_token');
    if (!token) return;
    const data = await apiGetMe(token);
    dispatch({ type: 'UPDATE_USER', payload: data.user });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('medisiem_token');
    dispatch({ type: 'LOGOUT' });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, verifyMfa, refreshUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// ─── Hook ─────────────────────────────────────────────────────────────────────
export const useAuth = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
};
