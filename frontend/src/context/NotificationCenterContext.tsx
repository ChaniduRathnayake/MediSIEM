// Persisted notification history — same keyed-dedup pattern as ToastContext, but capped
// and localStorage-backed instead of auto-dismissing.
import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'info';
  createdAt: string;
  read: boolean;
}

const STORAGE_KEY = 'medisiem_notification_history';
const MAX_HISTORY = 100;

interface NotificationCenterContextValue {
  notifications: NotificationItem[];
  unreadCount: number;
  notify: (input: { key?: string; title: string; message: string; severity?: 'critical' | 'high' | 'info' }) => void;
  markAllRead: () => void;
  clear: () => void;
}

const NotificationCenterContext = createContext<NotificationCenterContextValue | undefined>(undefined);

function loadHistory(): NotificationItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as NotificationItem[]) : [];
  } catch {
    return [];
  }
}

export const NotificationCenterProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [notifications, setNotifications] = useState<NotificationItem[]>(loadHistory);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(notifications));
    } catch {
      // Storage full/unavailable (private browsing) — history still works
      // for this session, it just won't survive a reload.
    }
  }, [notifications]);

  const notify = useCallback((input: { key?: string; title: string; message: string; severity?: 'critical' | 'high' | 'info' }) => {
    setNotifications((prev) => {
      const id = input.key ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const existingIdx = input.key ? prev.findIndex((n) => n.id === input.key) : -1;
      const entry: NotificationItem = {
        id,
        title: input.title,
        message: input.message,
        severity: input.severity ?? 'info',
        createdAt: new Date().toISOString(),
        read: existingIdx !== -1 ? prev[existingIdx].read : false,
      };
      if (existingIdx !== -1) {
        const next = [...prev];
        next[existingIdx] = entry;
        return next;
      }
      return [entry, ...prev].slice(0, MAX_HISTORY);
    });
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => (prev.every((n) => n.read) ? prev : prev.map((n) => ({ ...n, read: true }))));
  }, []);

  const clear = useCallback(() => setNotifications([]), []);

  const unreadCount = notifications.reduce((n, item) => n + (item.read ? 0 : 1), 0);

  return (
    <NotificationCenterContext.Provider value={{ notifications, unreadCount, notify, markAllRead, clear }}>
      {children}
    </NotificationCenterContext.Provider>
  );
};

export const useNotificationCenter = (): NotificationCenterContextValue => {
  const ctx = useContext(NotificationCenterContext);
  if (!ctx) throw new Error('useNotificationCenter must be used inside <NotificationCenterProvider>');
  return ctx;
};
