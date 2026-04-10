import React, { createContext, useContext, useEffect, useReducer, useCallback } from 'react';
import type { User, AuthState, LoginPayload, RegisterPayload } from '../types';
import { apiLogin, apiRegister, apiGetMe } from '../services/api';

// ─── State & Actions ──────────────────────────────────────────────────────────
type Action =
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; token: string } }
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
    case 'LOGOUT':
      return { ...initialState, token: null, isLoading: false };
    default:
      return state;
  }
}

// ─── Context ──────────────────────────────────────────────────────────────────
interface AuthContextValue extends AuthState {
  login: (payload: LoginPayload) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
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
    localStorage.setItem('medisiem_token', data.token);
    dispatch({ type: 'LOGIN_SUCCESS', payload: { user: data.user, token: data.token } });
  }, []);

  const register = useCallback(async (payload: RegisterPayload) => {
    const data = await apiRegister(payload);
    localStorage.setItem('medisiem_token', data.token);
    dispatch({ type: 'LOGIN_SUCCESS', payload: { user: data.user, token: data.token } });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('medisiem_token');
    dispatch({ type: 'LOGOUT' });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout }}>
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
