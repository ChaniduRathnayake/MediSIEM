// Loads enriched alerts once via REST, then keeps them live via Socket.IO.
import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { apiGetAlerts, EnrichedAlert, AlertStats } from '../services/alertsApi';
import { BASE_URL } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useNotificationCenter } from '../context/NotificationCenterContext';
import { casToSeverity } from '../utils/chartData';

// BASE_URL is "<origin>/api" — Socket.IO connects to the bare origin.
const SOCKET_URL = import.meta.env.VITE_API_SOCKET_URL || BASE_URL.replace(/\/api\/?$/, '');
const MAX_ALERTS = 200;

// A restarted backend replays its whole historical buffer over `alert:new` — only toast/beep
// for alerts whose own timestamp is genuinely recent, or a stale buffer spams on every restart.
const FRESH_ALERT_WINDOW_MS = 2 * 60 * 1000;

// More than this many CRITICAL toasts within STORM_WINDOW_MS coalesces into one toast
// (sound only on entry) instead of a beep and a stacked toast per alert.
const STORM_WINDOW_MS = 15 * 1000;
const STORM_THRESHOLD = 3;
const STORM_TOAST_KEY = 'critical-alert-storm';

function dedupeById(alerts: EnrichedAlert[]): EnrichedAlert[] {
  const seen = new Set<string>();
  return alerts.filter((a) => (seen.has(a.id) ? false : (seen.add(a.id), true)));
}

const EMPTY_SEVERITY_TOTALS = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

// Best-effort native browser notification for when the tab isn't focused — never calls
// requestPermission() itself, only checks the already-decided value (see BrowserNotifToggle.tsx).
function notifyBrowser(title: string, body: string) {
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  if (typeof document !== 'undefined' && !document.hidden) return; // tab is already visible — the toast is enough
  try {
    new Notification(title, { body, tag: 'medisiem-alert' });
  } catch {
    // Some browsers (mobile Safari, notably) throw constructing Notification
    // directly rather than via a service worker — a missed push is never
    // worth surfacing as an error to the user.
  }
}

// userId (optional) enables @mention delivery — omitted by callers with no mention UI.
export function useLiveAlerts(token: string | null, userId?: string) {
  const [alerts, setAlerts] = useState<EnrichedAlert[]>([]);
  // Unlike `alerts` (capped at MAX_ALERTS), these never shrink.
  const [stats, setStats] = useState<AlertStats>({ totalCount: 0, severityTotals: EMPTY_SEVERITY_TOTALS });
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const { showToast } = useToast();
  const { notify } = useNotificationCenter();
  const criticalToastTimestampsRef = useRef<number[]>([]);
  const highToastTimestampsRef = useRef<number[]>([]);
  // Guards the toast/beep side effect (outside setAlerts's updater) so React 18 StrictMode's
  // double-invoke in dev doesn't double the toast/beep for a single alert.
  const toastedAlertIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    let mounted = true;

    apiGetAlerts(token, MAX_ALERTS)
      .then(({ alerts: initial, totalCount, severityTotals }) => {
        if (mounted) {
          setAlerts(dedupeById(initial));
          setStats({ totalCount, severityTotals });
        }
      })
      .catch((err: unknown) => {
        if (mounted) setError(err instanceof Error ? err.message : 'Failed to load alerts.');
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    const socket = io(SOCKET_URL, { withCredentials: true, auth: { token } });
    socketRef.current = socket;

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('alert:new', (alert: EnrichedAlert) => {
      // A repeat id means alertPipeline.js folded another occurrence into this row —
      // update it in place rather than treating it as unseen.
      setAlerts((prev) => {
        const idx = prev.findIndex((a) => a.id === alert.id);
        if (idx === -1) return [alert, ...prev].slice(0, MAX_ALERTS);
        if (prev[idx] === alert) return prev;
        const next = [...prev];
        next[idx] = alert;
        return next;
      });

      if (toastedAlertIdsRef.current.has(alert.id)) return;
      toastedAlertIdsRef.current.add(alert.id);

      const age = Date.now() - new Date(alert.timestamp).getTime();
      const severity = casToSeverity(alert.CAS);
      if (age >= 0 && age < FRESH_ALERT_WINDOW_MS && severity === 'CRITICAL') {
        const now = Date.now();
        const recent = criticalToastTimestampsRef.current.filter((t) => now - t < STORM_WINDOW_MS);
        recent.push(now);
        criticalToastTimestampsRef.current = recent;

        if (recent.length <= STORM_THRESHOLD) {
          const message = `${alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription} — ${alert.agent} (CAS ${alert.CAS.toFixed(1)})`;
          showToast({ title: 'Critical alert', message, severity: 'critical' });
          notify({ title: 'Critical alert', message, severity: 'critical' });
          notifyBrowser('Critical alert — MediSIEM', message);
        } else {
          const stormMessage = `${recent.length} critical alerts in the last ${Math.round(STORM_WINDOW_MS / 1000)}s — open the Alerts tab rather than reading each one`;
          showToast({
            key: STORM_TOAST_KEY,
            title: 'Critical alert storm',
            message: stormMessage,
            severity: 'critical',
            silent: recent.length > STORM_THRESHOLD + 1,
          });
          notify({ key: STORM_TOAST_KEY, title: 'Critical alert storm', message: stormMessage, severity: 'critical' });
        }
      } else if (age >= 0 && age < FRESH_ALERT_WINDOW_MS && severity === 'HIGH') {
        // Same storm-coalescing, quieter cue, no browser push (CRITICAL only).
        const now = Date.now();
        const recent = highToastTimestampsRef.current.filter((t) => now - t < STORM_WINDOW_MS);
        recent.push(now);
        highToastTimestampsRef.current = recent;

        if (recent.length <= STORM_THRESHOLD) {
          const message = `${alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription} — ${alert.agent} (CAS ${alert.CAS.toFixed(1)})`;
          showToast({ title: 'High-severity alert', message, severity: 'high' });
          notify({ title: 'High-severity alert', message, severity: 'high' });
        } else {
          const stormMessage = `${recent.length} high-severity alerts in the last ${Math.round(STORM_WINDOW_MS / 1000)}s`;
          showToast({
            key: 'high-alert-storm',
            title: 'High-severity alert storm',
            message: stormMessage,
            severity: 'high',
            silent: recent.length > STORM_THRESHOLD + 1,
          });
          notify({ key: 'high-alert-storm', title: 'High-severity alert storm', message: stormMessage, severity: 'high' });
        }
      }
    });
    socket.on('alerts:stats', (next: AlertStats) => setStats(next));

    // Broadcast to every socket, filtered here to the mentioned user(s) — no per-user rooms.
    socket.on('alert:mention', (payload: { alertId: string; alertLabel: string; mentionedUserIds: string[]; from: { id: string; name: string }; text: string }) => {
      if (!userId || !payload.mentionedUserIds.includes(userId)) return;
      const title = `${payload.from.name} mentioned you`;
      const message = `${payload.alertLabel}: ${payload.text}`;
      showToast({ title, message, severity: 'info' });
      notify({ title, message, severity: 'info' });
      notifyBrowser(title, message);
    });

    return () => {
      mounted = false;
      socket.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, userId]);

  return { alerts, connected, loading, error, totalCount: stats.totalCount, severityTotals: stats.severityTotals };
}
