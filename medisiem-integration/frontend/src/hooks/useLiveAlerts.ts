// frontend/src/hooks/useLiveAlerts.ts
//
// Loads enriched alerts once via REST, then keeps them live via Socket.IO —
// no polling needed. Requires `npm install socket.io-client` in frontend/.

import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { apiGetAlerts, EnrichedAlert } from '../services/alertsApi';

const SOCKET_URL = import.meta.env.VITE_API_SOCKET_URL || 'http://localhost:5000';
const MAX_ALERTS = 200;

export function useLiveAlerts() {
  const [alerts, setAlerts] = useState<EnrichedAlert[]>([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    let mounted = true;

    // Initial load — CAS-ranked snapshot of whatever's already in the buffer.
    apiGetAlerts(MAX_ALERTS)
      .then(({ alerts: initial }) => {
        if (mounted) setAlerts(initial);
      })
      .catch((err) => {
        if (mounted) setError(err.message);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    // Live updates — new alerts pushed as Wazuh → CAAP produces them.
    const socket = io(SOCKET_URL, { withCredentials: true });
    socketRef.current = socket;

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('alert:new', (alert: EnrichedAlert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
    });

    return () => {
      mounted = false;
      socket.disconnect();
    };
  }, []);

  return { alerts, connected, loading, error };
}
