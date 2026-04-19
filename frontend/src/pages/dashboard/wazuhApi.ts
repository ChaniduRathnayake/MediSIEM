// frontend/src/pages/dashboard/wazuhApi.ts
// All calls go via the MediSIEM backend proxy (/api/wazuh/*).
// The backend authenticates to Wazuh using:
//   GET /security/user/authenticate?raw=true  (Basic Auth → raw JWT string)

export interface WazuhConfig {
  host:     string;   // e.g. https://192.168.52.129
  port:     string;   // e.g. 55000
  username: string;   // e.g. wazuh-wui
  password: string;   // e.g. MyS3cr37P450r.*-
}

// ── Well-known defaults for this deployment ───────────────────────────────────
export const WAZUH_DEFAULTS: WazuhConfig = {
  host:     'https://192.168.52.129',
  port:     '55000',
  username: 'wazuh-wui',
  password: 'MyS3cr37P450r.*-',
};

export interface WazuhAgent {
  id:           string;
  name:         string;
  ip?:          string;
  status:       'active' | 'disconnected' | 'never_connected' | 'pending';
  os?:          { platform: string; name: string; version: string };
  version?:     string;
  lastKeepAlive?: string;
  group?:       string[];
}

export interface WazuhAlert {
  id?:        string;
  timestamp?: string;
  rule?:      { id: string; level: number; description: string; groups: string[] };
  agent?:     { id: string; name: string; ip?: string };
  data?:      Record<string, unknown>;
  location?:  string;
  // Manager logs shape (different from alert shape)
  tag?:       string;
  level?:     string;
  description?: string;
}

export interface WazuhVulnerability {
  cve:      string;
  severity: string;
  package:  { name: string; version: string };
  agent:    { id: string; name: string };
}

export interface WazuhStats {
  totalAlerts:        number;
  alertsLast24h:      number;
  criticalAlerts:     number;
  activeAgents:       number;
  disconnectedAgents: number;
  totalAgents:        number;
  vulnerabilities: {
    critical: number;
    high:     number;
    medium:   number;
    low:      number;
  };
}

// ── Internal helper ───────────────────────────────────────────────────────────
const PROXY = '/api/wazuh';

function configHeaders(cfg: WazuhConfig): Record<string, string> {
  return {
    'Content-Type':  'application/json',
    'x-wazuh-host':  cfg.host,
    'x-wazuh-port':  cfg.port,
    'x-wazuh-user':  cfg.username,
    'x-wazuh-pass':  cfg.password,
  };
}

async function proxyGet<T>(path: string, cfg: WazuhConfig): Promise<T> {
  const res = await fetch(`${PROXY}${path}`, {
    headers: configHeaders(cfg),
  });

  const data = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));

  if (!res.ok) {
    throw new Error((data as { message?: string }).message || `HTTP ${res.status}`);
  }

  return data as T;
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function testConnection(cfg: WazuhConfig): Promise<{ ok: boolean; version?: string }> {
  const data = await proxyGet<{ data?: { api_version?: string } }>('/ping', cfg);
  return { ok: true, version: data.data?.api_version };
}

export async function getStats(cfg: WazuhConfig): Promise<WazuhStats> {
  const data = await proxyGet<{ data: WazuhStats }>('/stats', cfg);
  return data.data;
}

export async function getAgents(cfg: WazuhConfig): Promise<WazuhAgent[]> {
  const data = await proxyGet<{ data: { affected_items: WazuhAgent[] } }>('/agents?limit=500', cfg);
  return data.data?.affected_items ?? [];
}

export async function getRecentAlerts(cfg: WazuhConfig, limit = 50): Promise<WazuhAlert[]> {
  const data = await proxyGet<{ data: { affected_items: WazuhAlert[] } }>(`/alerts?limit=${limit}`, cfg);
  return data.data?.affected_items ?? [];
}

export async function getVulnerabilities(cfg: WazuhConfig, agentId = '000'): Promise<WazuhVulnerability[]> {
  const data = await proxyGet<{ data: { affected_items: WazuhVulnerability[] } }>(
    `/vulnerability/${agentId}?limit=100`,
    cfg
  );
  return data.data?.affected_items ?? [];
}
