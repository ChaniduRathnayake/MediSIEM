// All calls go via the MediSIEM backend proxy (/api/wazuh/*), which
// authenticates to Wazuh via GET /security/user/authenticate?raw=true.
import { BASE_URL } from '../../services/api';

export interface WazuhConfig {
  host:     string;   // e.g. https://localhost  or  https://192.168.x.x
  port:     string;   // e.g. 55000
  username: string;   // e.g. wazuh-wui
  password: string;

  // Wazuh Indexer (OpenSearch/Elasticsearch) — separate service, separate
  // credentials. Only needed for the HIPAA/GDPR Compliances views, which
  // query wazuh-alerts-* directly (the manager API above has no structured
  // alert search). Optional: left blank, those views just show a
  // not-connected empty state instead of failing the whole app.
  indexerHost?:     string; // e.g. https://localhost
  indexerPort?:     string; // e.g. 9200
  indexerUsername?: string; // e.g. admin
  indexerPassword?: string;
}

// ── Well-known defaults for Docker-on-Windows / Docker Desktop ────────────────
// When Wazuh runs in Docker Desktop on Windows, the manager is reachable from
// the host (where the Node backend runs) at localhost:55000. Host/port/
// username are just connection targets, not secrets, so they're safe to
// pre-fill for convenience — but passwords are deliberately left blank
// rather than shipping a real-looking credential in the frontend bundle.
// The user can override any of this in the config panel if their setup differs.
export const WAZUH_DEFAULTS: WazuhConfig = {
  host:     'https://localhost',
  port:     '55000',
  username: 'wazuh-wui',
  password: '',

  indexerHost:     'https://localhost',
  indexerPort:     '9200',
  indexerUsername: 'admin',
  indexerPassword: '',
};

export interface WazuhAgent {
  id:           string;
  name:         string;
  ip?:          string;
  // Wazuh's own enum is active | disconnected | never_connected | pending, but kept
  // as `string` here — real responses have been seen with different casing/spacing,
  // so callers should normalize (see normalizeAgentStatus) rather than compare directly.
  status:       string;
  os?:          { platform?: string; name?: string; version?: string; arch?: string; codename?: string };
  version?:     string;
  lastKeepAlive?: string;
  group?:       string[];
  dateAdd?:     string;
  manager?:     string;
  node_name?:   string;
  group_config_status?: string;
}

// ── Status normalization ────────────────────────────────────────────────────────
// Real Wazuh responses have been observed with inconsistent casing/whitespace for
// `status`. Normalize before matching against the known enum so the UI never
// silently falls back to an "unknown" look for what is actually a known state.
export type NormalizedAgentStatus = 'active' | 'disconnected' | 'never_connected' | 'pending';

export function normalizeAgentStatus(raw: string | undefined | null): NormalizedAgentStatus {
  const s = (raw ?? '').trim().toLowerCase().replace(/\s+/g, '_');
  if (s === 'active' || s === 'online' || s === 'connected') return 'active';
  if (s === 'disconnected' || s === 'offline') return 'disconnected';
  if (s === 'never_connected') return 'never_connected';
  if (s === 'pending') return 'pending';
  return 'disconnected'; // unknown/unexpected value — safer to flag as offline than to hide it as "active"
}

// Builds a readable OS string from whatever sub-fields the agent actually reported —
// real agents don't always populate every os.* field, so fall back gracefully instead
// of collapsing to "—" the moment one field is missing.
export function formatOs(os?: WazuhAgent['os']): string {
  if (!os) return '—';
  const parts = [os.name || os.platform, os.version].filter(Boolean);
  return parts.length > 0 ? parts.join(' ') : '—';
}

// ── OS categorization ───────────────────────────────────────────────────────────
// Coarse device labeling derived from whatever OS fields Wazuh reported. This is
// a best-effort classification for display/filtering — a MediSIEM-side manual
// override (see Device.osCategoryOverride) always takes precedence over it.
export type OsCategory = 'windows' | 'linux' | 'macos' | 'network' | 'iot' | 'unknown';

const LINUX_MARKERS = ['ubuntu', 'debian', 'centos', 'rhel', 'redhat', 'red hat', 'fedora', 'suse', 'alpine', 'amzn', 'amazon', 'rocky', 'almalinux', 'linux'];

export function inferOsCategory(os?: WazuhAgent['os']): OsCategory {
  const platform = (os?.platform || os?.name || '').toLowerCase();
  if (!platform) return 'unknown';
  if (platform.includes('windows')) return 'windows';
  if (platform.includes('darwin') || platform.includes('mac')) return 'macos';
  if (LINUX_MARKERS.some((marker) => platform.includes(marker))) return 'linux';
  return 'unknown';
}

export const OS_CATEGORY_LABELS: Record<OsCategory, string> = {
  windows: 'Windows',
  linux:   'Linux',
  macos:   'macOS',
  network: 'Network',
  iot:     'IoT',
  unknown: 'Unknown',
};

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

// ── Per-agent deep details (syscollector + security modules) ───────────────────
// Every section is independently best-effort: a module that isn't enabled on the
// manager (or has no data yet for this agent) reports `ok: false` rather than
// failing the whole request.
export interface WazuhListSection<T> {
  ok: boolean;
  error?: string;
  items: T[];
  total: number;
}

export interface WazuhSingleSection<T> {
  ok: boolean;
  error?: string;
  item: T | null;
}

export interface WazuhHardware {
  board_serial?: string;
  cpu?: { cores?: number; mhz?: number; name?: string };
  ram?: { free?: number; total?: number; usage?: number };
}

export interface WazuhOsInfo {
  architecture?: string;
  hostname?: string;
  os?: { codename?: string; major?: string; minor?: string; name?: string; platform?: string; version?: string };
  release?: string;
  sysname?: string;
  version?: string;
}

export interface WazuhNetIface {
  name?: string;
  adapter?: string;
  state?: string;
  mtu?: number;
  type?: string;
  tx?: { bytes?: number; packets?: number };
  rx?: { bytes?: number; packets?: number };
}

export interface WazuhNetAddr {
  iface?: string;
  proto?: string;
  address?: string;
  netmask?: string;
  broadcast?: string;
}

export interface WazuhNetProto {
  iface?: string;
  gateway?: string;
  dhcp?: string;
  type?: string;
}

export interface WazuhPackage {
  name?: string;
  version?: string;
  vendor?: string;
  architecture?: string;
  format?: string;
  size?: number;
  install_time?: string;
}

export interface WazuhProcess {
  pid?: string | number;
  name?: string;
  cmd?: string;
  state?: string;
  ppid?: number;
  priority?: number;
  nice?: number;
  vm_size?: number;
  start_time?: string;
}

export interface WazuhPort {
  local?: { ip?: string; port?: number };
  remote?: { ip?: string; port?: number };
  state?: string;
  protocol?: string;
  pid?: number;
  process?: string;
}

export interface WazuhScaPolicy {
  policy_id?: string;
  name?: string;
  description?: string;
  pass?: number;
  fail?: number;
  invalid?: number;
  score?: number;
  end_scan?: string;
}

export interface WazuhFimEvent {
  file?: string;
  mtime?: string;
  size?: number;
  uname?: string;
  gname?: string;
  // Unix agents report a permission string (e.g. "644"); Windows agents report a
  // nested ACL object instead — callers must not render this directly.
  perm?: string | Record<string, unknown>;
  sha256?: string;
  md5?: string;
  changes?: number;
  event?: string;
}

export interface WazuhAgentDetails {
  hardware:        WazuhSingleSection<WazuhHardware>;
  os:              WazuhSingleSection<WazuhOsInfo>;
  netiface:        WazuhListSection<WazuhNetIface>;
  netaddr:         WazuhListSection<WazuhNetAddr>;
  netproto:        WazuhListSection<WazuhNetProto>;
  packages:        WazuhListSection<WazuhPackage>;
  processes:       WazuhListSection<WazuhProcess>;
  ports:           WazuhListSection<WazuhPort>;
  vulnerabilities: WazuhListSection<WazuhVulnerability>;
  sca:             WazuhListSection<WazuhScaPolicy>;
  fim:             WazuhListSection<WazuhFimEvent>;
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
// BASE_URL already ends in /api (configurable via VITE_API_URL) — a hardcoded
// relative '/api/wazuh' only worked by accident, via vite.config.ts's dev-only
// server.proxy; the production build is a single portable HTML file
// (vite-plugin-singlefile) that may not share an origin with the backend.
const PROXY = `${BASE_URL}/wazuh`;

function configHeaders(cfg: WazuhConfig): Record<string, string> {
  // Same storage key AuthContext.tsx uses — these routes only ever accepted
  // the caller-supplied Wazuh credentials, with no MediSIEM login required
  // at all, so anyone who had (or guessed) Wazuh creds could hit them
  // without ever signing into this app. Read directly from storage rather
  // than threading a token through every exported function here, since none
  // of them currently take one and this file has a lot of call sites.
  const token = localStorage.getItem('medisiem_token') ?? '';
  return {
    'Content-Type':  'application/json',
    Authorization:   `Bearer ${token}`,
    'x-wazuh-host':  cfg.host,
    'x-wazuh-port':  cfg.port,
    'x-wazuh-user':  cfg.username,
    'x-wazuh-pass':  cfg.password,
  };
}

async function proxyGet<T>(path: string, cfg: WazuhConfig): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${PROXY}${path}`, { headers: configHeaders(cfg) });
  } catch (networkErr) {
    // fetch() itself throws only on network-level failures (backend unreachable)
    throw new Error(
      `Cannot reach MediSIEM backend at ${PROXY}. ` +
      `Make sure the Express server is running on port 5000 and the Vite proxy is configured. ` +
      `(${(networkErr as Error).message})`
    );
  }

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

export async function getVulnerabilities(cfg: WazuhConfig, agentId = '000', limit = 100): Promise<WazuhVulnerability[]> {
  const data = await proxyGet<{ data: { affected_items: WazuhVulnerability[] } }>(
    `/vulnerability/${agentId}?limit=${limit}`,
    cfg
  );
  return data.data?.affected_items ?? [];
}

export async function getAgentDetails(cfg: WazuhConfig, agentId: string): Promise<WazuhAgentDetails> {
  return proxyGet<WazuhAgentDetails>(`/agent-details/${agentId}`, cfg);
}

// Section keys that support pagination beyond the initial agent-details fetch
// (must match SECTION_PATH in backend/routes/wazuh.js).
export type AgentDetailsSection = 'netiface' | 'netaddr' | 'netproto' | 'packages' | 'processes' | 'ports' | 'vulnerabilities' | 'sca' | 'fim';

export async function getAgentDetailsSection<T>(
  cfg: WazuhConfig,
  agentId: string,
  section: AgentDetailsSection,
  offset: number,
  limit = 300
): Promise<WazuhListSection<T>> {
  return proxyGet<WazuhListSection<T>>(`/agent-details/${agentId}/section/${section}?offset=${offset}&limit=${limit}`, cfg);
}

// ── CIS compliance (SCA benchmark rollup) ───────────────────────────────────────
export interface ScaAgentSummary {
  agentId: string;
  ok: boolean;
  error?: string;
  policies?: { policyId?: string; name?: string; pass?: number; fail?: number; invalid?: number; score?: number }[];
  pass?: number;
  fail?: number;
  invalid?: number;
  total?: number;
  score?: number | null; // percentage 0-100, or null if no CIS policy data at all
}

export async function getScaSummary(cfg: WazuhConfig, agentIds: string[]): Promise<ScaAgentSummary[]> {
  if (agentIds.length === 0) return [];
  const data = await proxyGet<{ agents: ScaAgentSummary[] }>(`/sca-summary?agentIds=${agentIds.join(',')}`, cfg);
  return data.agents ?? [];
}

export interface WazuhScaCheck {
  id?: number;
  title?: string;
  description?: string;
  rationale?: string;
  remediation?: string;
  result?: string; // "passed" | "failed" | "not applicable" | ...
  compliance?: unknown;
}

export async function getScaChecks(cfg: WazuhConfig, agentId: string, policyId: string): Promise<WazuhListSection<WazuhScaCheck>> {
  return proxyGet<WazuhListSection<WazuhScaCheck>>(`/sca/${agentId}/checks/${policyId}`, cfg);
}
