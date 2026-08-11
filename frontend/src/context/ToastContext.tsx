import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { playAlertSound } from '../utils/sound';

export interface ToastInput {
  title: string;
  message: string;
  severity?: 'critical' | 'info';
}

interface Toast extends ToastInput {
  id: string;
}

interface ToastContextValue {
  showToast: (toast: ToastInput) => void;
  soundEnabled: boolean;
  toggleSound: () => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

const SOUND_STORAGE_KEY = 'medisiem_alert_sound';
const AUTO_DISMISS_MS = 6000;

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SOUND_STORAGE_KEY) !== 'off';
    } catch {
      return true;
    }
  });
  const soundEnabledRef = useRef(soundEnabled);
  soundEnabledRef.current = soundEnabled;

  useEffect(() => {
    try {
      localStorage.setItem(SOUND_STORAGE_KEY, soundEnabled ? 'on' : 'off');
    } catch {
      // localStorage unavailable — preference just won't persist across reloads
    }
  }, [soundEnabled]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback((toast: ToastInput) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setToasts((prev) => [{ ...toast, id }, ...prev].slice(0, 5));
    if (soundEnabledRef.current && toast.severity === 'critical') playAlertSound();
    setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
  }, [dismiss]);

  const toggleSound = useCallback(() => setSoundEnabled((v) => !v), []);

  return (
    <ToastContext.Provider value={{ showToast, soundEnabled, toggleSound }}>
      {children}
      <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 w-full max-w-sm pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="alert"
            className={`pointer-events-auto flex items-start gap-3 p-3.5 rounded-xl shadow-2xl border backdrop-blur-md animate-fade-up ${
              t.severity === 'critical'
                ? 'bg-red-50/95 dark:bg-red-950/90 border-red-300 dark:border-red-500/40'
                : 'bg-white/95 dark:bg-slate-900/90 border-slate-200 dark:border-slate-700'
            }`}
          >
            <AlertTriangle className={`w-4.5 h-4.5 flex-shrink-0 mt-0.5 ${t.severity === 'critical' ? 'text-red-500 dark:text-red-400' : 'text-cyan-500 dark:text-cyan-400'}`} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-slate-900 dark:text-white">{t.title}</p>
              <p className="text-xs text-slate-600 dark:text-slate-300 mt-0.5 truncate">{t.message}</p>
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className="flex-shrink-0 text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
              aria-label="Dismiss"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within a ToastProvider');
  return ctx;
}
