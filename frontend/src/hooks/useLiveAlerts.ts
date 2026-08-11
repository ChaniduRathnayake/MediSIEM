// frontend/src/hooks/useLiveAlerts.ts
//
// Loads enriched alerts once via REST, then keeps them live via Socket.IO —
// no polling needed.

import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { apiGetAlerts, EnrichedAlert, AlertStats } from '../services/alertsApi';
import { BASE_URL } from '../services/api';
import { useToast } from '../context/ToastContext';
import { casToSeverity } from '../utils/chartData';

// BASE_URL is "<origin>/api" — Socket.IO connects to the bare origin.
const SOCKET_URL = import.meta.env.VITE_API_SOCKET_URL || BASE_URL.replace(/\/api\/?$/, '');
const MAX_ALERTS = 200;

// A restarted backend replays its whole historical buffer over `alert:new`
// as it re-catches-up with the indexer (see alertPipeline.js's poll loop) —
// those aren't real-time events, they're old alerts arriving in a burst.
// Only toast/beep for alerts whose own timestamp is genuinely recent, or a
// stale demo buffer would fire dozens of toasts at once on every restart.
const FRESH_ALERT_WINDOW_MS = 2 * 60 * 1000;

function dedupeById(alerts: EnrichedAlert[]): EnrichedAlert[] {
  const seen = new Set<string>();
  return alerts.filter((a) => (seen.has(a.id) ? false : (seen.add(a.id), true)));
}

const EMPTY_SEVERITY_TOTALS = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

export function useLiveAlerts(token: string | null) {
  const [alerts, setAlerts] = useState<EnrichedAlert[]>([]);
  // Cumulative counts since the backend process started — unlike `alerts`
  // (capped at MAX_ALERTS so the list/table stays bounded), these never
  // shrink, so "Total Alerts" / severity-mix stats keep climbing instead of
  // freezing the instant the buffer fills up.
  const [stats, setStats] = useState<AlertStats>({ totalCount: 0, severityTotals: EMPTY_SEVERITY_TOTALS });
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const { showToast } = useToast();

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    let mounted = true;

    // Initial load — CAS-ranked snapshot of whatever's already in the buffer.
    // Deduped by id defensively: the backend buffer itself is deduped now,
    // but a stray repeat here is cheap to guard against and would otherwise
    // show up as a duplicate React key / double-counted stat.
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

    // Live updates — new alerts pushed as they're indexed into caap-alerts.
    const socket = io(SOCKET_URL, { withCredentials: true });
    socketRef.current = socket;

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('alert:new', (alert: EnrichedAlert) => {
      setAlerts((prev) => {
        if (prev.some((a) => a.id === alert.id)) return prev;

        const age = Date.now() - new Date(alert.timestamp).getTime();
        if (age >= 0 && age < FRESH_ALERT_WINDOW_MS && casToSeverity(alert.CAS) === 'CRITICAL') {
          showToast({
            title: 'Critical alert',
            message: `${alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription} — ${alert.agent} (CAS ${alert.CAS.toFixed(1)})`,
            severity: 'critical',
          });
        }

        return [alert, ...prev].slice(0, MAX_ALERTS);
      });
    });
    socket.on('alerts:stats', (next: AlertStats) => setStats(next));

    return () => {
      mounted = false;
      socket.disconnect();
    };
  }, [token]);

  return { alerts, connected, loading, error, totalCount: stats.totalCount, severityTotals: stats.severityTotals };
}
