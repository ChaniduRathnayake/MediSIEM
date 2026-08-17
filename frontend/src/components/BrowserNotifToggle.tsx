// Opt-in control for native browser notifications — Notification.permission itself is the
// persisted state; never auto-prompts, only asks in direct response to a click.
import React, { useEffect, useState } from 'react';
import { Bell, BellOff, BellRing } from 'lucide-react';

type PermissionState = 'default' | 'granted' | 'denied' | 'unsupported';

function currentPermission(): PermissionState {
  if (typeof Notification === 'undefined') return 'unsupported';
  return Notification.permission as PermissionState;
}

const BrowserNotifToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const [permission, setPermission] = useState<PermissionState>(currentPermission);

  useEffect(() => {
    setPermission(currentPermission());
  }, []);

  if (permission === 'unsupported') return null;

  const request = async () => {
    if (permission !== 'default' || typeof Notification === 'undefined') return;
    const result = await Notification.requestPermission();
    setPermission(result as PermissionState);
  };

  const label =
    permission === 'granted'
      ? 'Browser notifications on for critical alerts — click to see how to turn off'
      : permission === 'denied'
      ? 'Browser notifications blocked — allow them in your browser\'s site settings to enable'
      : 'Turn on browser notifications for critical alerts (works even when this tab is in the background)';

  return (
    <button
      onClick={request}
      title={label}
      aria-label={label}
      className={`p-2 rounded-md transition-colors ${
        permission === 'granted'
          ? 'text-cyan-500 dark:text-cyan-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          : permission === 'denied'
          ? 'text-slate-300 dark:text-slate-600 cursor-default'
          : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800'
      } ${className}`}
    >
      {permission === 'granted' ? <BellRing className="w-4 h-4" /> : permission === 'denied' ? <BellOff className="w-4 h-4" /> : <Bell className="w-4 h-4" />}
    </button>
  );
};

export default BrowserNotifToggle;
