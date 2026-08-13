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

// More than this many CRITICAL toasts within STORM_WINDOW_MS coalesces into
// a single "N critical alerts" toast (one sound cue on entry, silent
// updates after) instead of stacking a fresh toast — and playing a fresh
// beep — per alert. A real incident (or a demo attack scenario) can easily
// fire a dozen CRITICAL alerts in a few seconds; without this, that's a
// dozen overlapping beeps and a toast stack nobody can actually read.
const STORM_WINDOW_MS = 15 * 1000;
const STORM_THRESHOLD = 3;
const STORM_TOAST_KEY = 'critical-alert-storm';

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
  // Rolling timestamps of CRITICAL toasts shown in the current storm window
  // — see STORM_WINDOW_MS/STORM_THRESHOLD above. Ref, not state: purely an
  // internal rate-limiting counter, never needs to trigger a re-render.
  const criticalToastTimestampsRef = useRef<number[]>([]);
  // Guards the toast/beep side effect specifically (separate from the list's
  // own dedupe below) — needs to live outside setAlerts's updater function,
  // since React 18 StrictMode invokes updater functions twice in dev to
  // surface impure ones, which would otherwise double the toast and beep for
  // every single critical alert.
  const toastedAlertIdsRef = useRef<Set<string>>(new Set());

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
      // Pure — just derives next state from prev, safe to invoke twice
      // (StrictMode does exactly that in dev to catch impure updaters).
      setAlerts((prev) => (prev.some((a) => a.id === alert.id) ? prev : [alert, ...prev].slice(0, MAX_ALERTS)));

      // Toast/beep side effects live outside the updater above and behind
      // their own id-based guard, so they run exactly once per alert no
      // matter how many times React invokes the (pure) updater.
      if (toastedAlertIdsRef.current.has(alert.id)) return;
      toastedAlertIdsRef.current.add(alert.id);

      const age = Date.now() - new Date(alert.timestamp).getTime();
      if (age >= 0 && age < FRESH_ALERT_WINDOW_MS && casToSeverity(alert.CAS) === 'CRITICAL') {
        const now = Date.now();
        const recent = criticalToastTimestampsRef.current.filter((t) => now - t < STORM_WINDOW_MS);
        recent.push(now);
        criticalToastTimestampsRef.current = recent;

        if (recent.length <= STORM_THRESHOLD) {
          showToast({
            title: 'Critical alert',
            message: `${alert.label !== 'Unclassified' ? alert.label : alert.ruleDescription} — ${alert.agent} (CAS ${alert.CAS.toFixed(1)})`,
            severity: 'critical',
          });
        } else {
          // Past the threshold for this window — coalesce into one toast
          // that updates its count instead of stacking another, with the
          // beep only on the transition into storm mode (recent.length
          // === STORM_THRESHOLD + 1), not on every alert after it.
          showToast({
            key: STORM_TOAST_KEY,
            title: 'Critical alert storm',
            message: `${recent.length} critical alerts in the last ${Math.round(STORM_WINDOW_MS / 1000)}s — open the Alerts tab rather than reading each one`,
            severity: 'critical',
            silent: recent.length > STORM_THRESHOLD + 1,
          });
        }
      }
    });
    socket.on('alerts:stats', (next: AlertStats) => setStats(next));

    return () => {
      mounted = false;
      socket.disconnect();
    };
  }, [token]);

  return { alerts, connected, loading, error, totalCount: stats.totalCount, severityTotals: stats.severityTotals };
}
