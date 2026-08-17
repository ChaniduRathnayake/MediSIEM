// Persisted CAAP alert notification history — distinct from
// AdminDashboard's NotificationBell (unpersisted raw Wazuh polling); this
// keeps useLiveAlerts.ts's critical-alert toasts around after they disappear.
import React, { useEffect, useRef, useState } from 'react';
import { History, X, CheckCheck, Trash2, AlertCircle } from 'lucide-react';
import { useNotificationCenter } from '../context/NotificationCenterContext';

function timeAgo(iso: string): string {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const NotificationCenterBell: React.FC = () => {
  const { notifications, unreadCount, markAllRead, clear } = useNotificationCenter();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const handleOpen = () => {
    setOpen((o) => !o);
    if (!open && unreadCount > 0) markAllRead();
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={handleOpen}
        title="Notification history"
        aria-label={`Notification history${unreadCount > 0 ? ` — ${unreadCount} unread` : ''}`}
        className="relative p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
      >
        <History className="w-4 h-4" />
        {unreadCount > 0 && (
          <span className="absolute top-1 right-1 min-w-[14px] h-3.5 px-0.5 flex items-center justify-center rounded-full bg-cyan-500 text-[9px] font-bold text-slate-950 leading-none">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-12 w-80 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-2xl shadow-2xl overflow-hidden z-50">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
            <p className="text-sm font-semibold text-slate-900 dark:text-white">Notification history</p>
            <div className="flex items-center gap-2">
              {notifications.length > 0 && (
                <button onClick={clear} title="Clear all" className="text-slate-400 dark:text-slate-500 hover:text-red-500 transition-colors">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
              <button onClick={() => setOpen(false)} aria-label="Close" className="text-slate-400 dark:text-slate-500 hover:text-slate-700 dark:text-slate-300 transition-colors">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {notifications.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-4 py-8 text-slate-400 dark:text-slate-500">
              <CheckCheck className="w-6 h-6" />
              <p className="text-xs">Nothing yet — critical alerts will show up here.</p>
            </div>
          ) : (
            <div className="max-h-96 overflow-y-auto">
              {notifications.map((n) => (
                <div key={n.id} className="flex items-start gap-2.5 px-4 py-3 border-b border-slate-100 dark:border-slate-800/60 last:border-0">
                  <AlertCircle className={`w-3.5 h-3.5 flex-shrink-0 mt-0.5 ${n.severity === 'critical' ? 'text-red-500' : n.severity === 'high' ? 'text-amber-500' : 'text-slate-400 dark:text-slate-500'}`} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-slate-900 dark:text-white truncate">{n.title}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 line-clamp-2">{n.message}</p>
                    <p className="text-[10px] text-slate-400 dark:text-slate-600 mt-1">{timeAgo(n.createdAt)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default NotificationCenterBell;
