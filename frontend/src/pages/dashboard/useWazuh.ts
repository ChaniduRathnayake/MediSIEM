// frontend/src/pages/dashboard/useWazuh.ts
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  WazuhConfig, WazuhAgent, WazuhStats,
  getStats, getAgents, testConnection,
} from './wazuhApi';

const STORAGE_KEY = 'medisiem_wazuh_cfg';

export interface UseWazuhReturn {
  config:          WazuhConfig | null;
  saveConfig:      (cfg: WazuhConfig) => void;
  clearConfig:     () => void;

  connected:       boolean;
  connecting:      boolean;
  connectStep:     string | null;
  connectionError: string | null;
  apiVersion:      string | null;
  connect:         (cfg?: WazuhConfig) => Promise<boolean>;

  stats:           WazuhStats | null;
  agents:          WazuhAgent[];

  loadingStats:    boolean;
  loadingAgents:   boolean;

  refresh:         () => void;
  lastRefresh:     Date | null;
}

export function useWazuh(): UseWazuhReturn {
  const [config, setConfig] = useState<WazuhConfig | null>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });

  const [connected,       setConnected]       = useState(false);
  const [connecting,      setConnecting]      = useState(false);
  const [connectStep,     setConnectStep]     = useState<string | null>(null);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [apiVersion,      setApiVersion]      = useState<string | null>(null);

  const [stats,  setStats]  = useState<WazuhStats | null>(null);
  const [agents, setAgents] = useState<WazuhAgent[]>([]);

  const [loadingStats,  setLoadingStats]  = useState(false);
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [lastRefresh,   setLastRefresh]   = useState<Date | null>(null);

  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const saveConfig = useCallback((cfg: WazuhConfig) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
    setConfig(cfg);
    setConnectionError(null);
    // Do NOT reset connected here — connect() handles that at its own start
  }, []);

  const clearConfig = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setConfig(null);
    setConnected(false);
    setConnectionError(null);
    setStats(null);
    setAgents([]);
  }, []);

  const fetchAll = useCallback(async (cfg: WazuhConfig) => {
    setLoadingStats(true);
    setLoadingAgents(true);

    // getStats is the auth gate — throws on bad credentials (401 → 502)
    const statsData = await getStats(cfg);
    setStats(statsData);
    setLoadingStats(false);

    await getAgents(cfg).then(setAgents).finally(() => setLoadingAgents(false));

    setLastRefresh(new Date());
  }, []);

  const connect = useCallback(async (cfg?: WazuhConfig): Promise<boolean> => {
    const active = cfg ?? config;
    if (!active) return false;

    setConnecting(true);
    setConnectionError(null);
    setConnected(false);

    try {
      // Step 1: ping — verifies reachability AND credentials before touching data
      setConnectStep('Verifying API connection…');
      const ping = await testConnection(active);
      if (ping.version) setApiVersion(ping.version);

      // Step 2: load dashboard data
      setConnectStep('Loading dashboard data…');
      await fetchAll(active);

      setConnected(true);
      setConnectStep(null);
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      setConnectionError(msg);
      setConnected(false);
      setConnectStep(null);
      setLoadingStats(false);
      setLoadingAgents(false);
      return false;
    } finally {
      setConnecting(false);
    }
  }, [config, fetchAll]);

  const refresh = useCallback(() => {
    if (config && connected) fetchAll(config);
  }, [config, connected, fetchAll]);

  // Auto-connect on mount if config already saved
  useEffect(() => {
    if (config && !connected) connect(config);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-refresh every 30s
  useEffect(() => {
    if (connected && config) {
      timer.current = setInterval(() => fetchAll(config), 30_000);
    }
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [connected, config, fetchAll]);

  return {
    config, saveConfig, clearConfig,
    connected, connecting, connectStep, connectionError, apiVersion, connect,
    stats, agents,
    loadingStats, loadingAgents,
    refresh, lastRefresh,
  };
}