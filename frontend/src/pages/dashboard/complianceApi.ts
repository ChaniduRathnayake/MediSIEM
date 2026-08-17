// Client for the Wazuh Indexer proxy (backend/routes/compliance.js) — a
// separate service from the Wazuh manager API wazuhApi.ts talks to. Backs
// the Alerts browser, HIPAA/GDPR views, and FIM change history.

import type { WazuhConfig } from './wazuhApi';
import { BASE_URL } from '../../services/api';

export type ComplianceFramework = 'hipaa' | 'gdpr';

export interface ComplianceAgentSummary {
  agentId: string;
  alertCount: number;
  maxLevel: number | null;
  violatedControls: string[];
}

export interface ComplianceSummary {
  ok: boolean;
  days: number;
  observedControls: string[];
  agents: ComplianceAgentSummary[];
}

export interface ComplianceControlDetail {
  control: string;
  alertCount: number;
  maxLevel: number | null;
  samples: { description: string | null; ruleId: string | null; timestamp: string | null }[];
}

export interface ComplianceAgentDetail {
  ok: boolean;
  days: number;
  agentId: string;
  violatedControls: ComplianceControlDetail[];
}

// See wazuhApi.ts's PROXY comment — same reasoning, same fix.
const PROXY = `${BASE_URL}/compliance`;

function configHeaders(cfg: WazuhConfig): Record<string, string> {
  // Same storage key AuthContext.tsx uses — these routes only ever accepted
  // the caller-supplied Indexer credentials, with no MediSIEM login required
  // at all, so anyone who had (or guessed) Indexer creds could hit them
  // without ever signing into this app. Read directly from storage rather
  // than threading a token through every exported function here, since none
  // of them currently take one and this file has a lot of call sites.
  const token = localStorage.getItem('medisiem_token') ?? '';
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
    'x-indexer-host': cfg.indexerHost ?? '',
    'x-indexer-port': cfg.indexerPort ?? '',
    'x-indexer-user': cfg.indexerUsername ?? '',
    'x-indexer-pass': cfg.indexerPassword ?? '',
  };
}

async function proxyGet<T>(path: string, cfg: WazuhConfig): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${PROXY}${path}`, { headers: configHeaders(cfg) });
  } catch (networkErr) {
    throw new Error(`Cannot reach MediSIEM backend at ${PROXY}. (${(networkErr as Error).message})`);
  }

  const data = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error((data as { message?: string }).message || `HTTP ${res.status}`);
  return data as T;
}

// True only when indexer fields have actually been filled in — HIPAA/GDPR
// views should show a "not connected" state rather than firing requests
// with empty credentials.
export function hasIndexerConfig(cfg: WazuhConfig | null): boolean {
  return !!(cfg?.indexerHost && cfg.indexerPort && cfg.indexerUsername && cfg.indexerPassword);
}

export async function testIndexerConnection(cfg: WazuhConfig): Promise<{ ok: boolean; version: string | null }> {
  return proxyGet<{ ok: boolean; version: string | null }>('/ping', cfg);
}

export async function getComplianceSummary(
  cfg: WazuhConfig,
  framework: ComplianceFramework,
  days: number,
  agentIds?: string[]
): Promise<ComplianceSummary> {
  const qs = new URLSearchParams({ days: String(days) });
  if (agentIds && agentIds.length > 0) qs.set('agentIds', agentIds.join(','));
  return proxyGet<ComplianceSummary>(`/${framework}/summary?${qs.toString()}`, cfg);
}

export async function getComplianceAgentDetail(
  cfg: WazuhConfig,
  framework: ComplianceFramework,
  agentId: string,
  days: number
): Promise<ComplianceAgentDetail> {
  return proxyGet<ComplianceAgentDetail>(`/${framework}/agent/${agentId}?days=${days}`, cfg);
}

// ── Full alert browser (paginated, filterable) ──────────────────────────────
export interface WazuhAlertCompliance {
  hipaa: string[];
  pciDss: string[];
  gdpr: string[];
  nist80053: string[];
  tsc: string[];
  gpg13: string[];
}

export interface WazuhAlertRow {
  id: string;
  timestamp: string | null;
  agentId: string | null;
  agentName: string | null;
  agentIp: string | null;
  ruleId: string | null;
  ruleLevel: number | null;
  ruleDescription: string | null;
  ruleGroups: string[];
  ruleFiredTimes: number | null;
  location: string | null;
  fullLog: string | null;
  data: Record<string, unknown> | null;
  decoder: string | null;
  compliance: WazuhAlertCompliance;
}

export interface AlertSearchResult {
  ok: boolean;
  total: number;
  page: number;
  pageSize: number;
  alerts: WazuhAlertRow[];
}

export interface AlertSearchOptions {
  page: number;
  pageSize?: number;
  agentId?: string;
  agentIp?: string;
  severity?: number;
  q?: string;
}

export async function searchAlerts(cfg: WazuhConfig, opts: AlertSearchOptions): Promise<AlertSearchResult> {
  const qs = new URLSearchParams({ page: String(opts.page), pageSize: String(opts.pageSize ?? 50) });
  if (opts.agentId) qs.set('agentId', opts.agentId);
  if (opts.agentIp) qs.set('agentIp', opts.agentIp);
  if (opts.severity !== undefined) qs.set('severity', String(opts.severity));
  if (opts.q) qs.set('q', opts.q);
  return proxyGet<AlertSearchResult>(`/alerts?${qs.toString()}`, cfg);
}

// ── FIM change history (real before/after diffs, not just current state) ────
export interface FimEvent {
  id: string;
  timestamp: string | null;
  path: string | null;
  event: string | null; // 'added' | 'modified' | 'deleted'
  changedAttributes: string[];
  ruleDescription: string | null;
  ruleLevel: number | null;
  // Raw syscheck fields straight from the Wazuh alert — includes whichever
  // *_before/*_after pairs (size, md5sum, sha1sum, sha256sum, perm, uid, gid,
  // mtime, ...) and optional `diff` (line-level content diff) this event has.
  syscheck: Record<string, unknown>;
}

export interface FimHistoryResult {
  ok: boolean;
  total: number;
  page: number;
  pageSize: number;
  events: FimEvent[];
}

export interface FimHistoryOptions {
  page: number;
  pageSize?: number;
  days?: number;
  path?: string;
}

export async function getFimHistory(cfg: WazuhConfig, agentId: string, opts: FimHistoryOptions): Promise<FimHistoryResult> {
  const qs = new URLSearchParams({ page: String(opts.page), pageSize: String(opts.pageSize ?? 50) });
  if (opts.days !== undefined) qs.set('days', String(opts.days));
  if (opts.path) qs.set('path', opts.path);
  return proxyGet<FimHistoryResult>(`/fim/${agentId}?${qs.toString()}`, cfg);
}
