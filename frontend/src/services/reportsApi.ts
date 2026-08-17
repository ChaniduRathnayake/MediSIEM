// Client for backend/routes/reports.js.
import { BASE_URL } from './api';

export interface ReportRange {
  from?: string; // ISO date
  to?: string; // ISO date
}

async function get<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `Failed to load report (HTTP ${res.status})`);
  return json;
}

function qs(range: ReportRange, extra?: Record<string, string>): string {
  const params = new URLSearchParams();
  if (range.from) params.set('from', range.from);
  if (range.to) params.set('to', range.to);
  if (extra) for (const [k, v] of Object.entries(extra)) if (v) params.set(k, v);
  return params.toString();
}

// ─── Detection accuracy ─────────────────────────────────────────────────────────
export interface DetectionAccuracyLabelRow {
  label: string;
  total: number;
  true_positive: number;
  false_positive: number;
  benign: number;
  uncertain: number;
  unset: number;
  falsePositiveRate: number | null;
}
export interface DetectionAccuracyReport {
  from: string;
  to: string;
  scope: 'mine' | 'all';
  totalClosed: number;
  overall: { true_positive: number; false_positive: number; benign: number; uncertain: number; unset: number };
  byLabel: DetectionAccuracyLabelRow[];
}
export const apiGetDetectionAccuracyReport = (token: string, range: ReportRange, scope: 'mine' | 'all' = 'mine') =>
  get<DetectionAccuracyReport>(`/reports/detection-accuracy?${qs(range, { scope })}`, token);

// ─── Escalation backlog ─────────────────────────────────────────────────────────
export interface EscalationRow {
  alertId: string;
  label: string;
  agent: string | null;
  department: string | null;
  CAS: number | null;
  detectedAt: string;
  claimedAt: string;
  minutesToClaim: number;
  claimedBy: string | null;
}
export interface EscalationBacklogReport {
  from: string;
  to: string;
  scope: 'mine' | 'all';
  count: number;
  avgMinutesToClaim: number | null;
  rows: EscalationRow[];
}
export const apiGetEscalationBacklogReport = (token: string, range: ReportRange, scope: 'mine' | 'all' = 'mine') =>
  get<EscalationBacklogReport>(`/reports/escalation-backlog?${qs(range, { scope })}`, token);

// ─── Off-hours activity ─────────────────────────────────────────────────────────
export interface OffHoursRow {
  alertId: string;
  timestamp: string;
  severity: string | null;
  CAS: number | null;
  agent: string | null;
  department: string | null;
  label: string | null;
}
export interface OffHoursReport {
  from: string;
  to: string;
  totalInRange: number;
  offHoursCount: number;
  offHoursPercentage: number;
  bySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  rows: OffHoursRow[];
}
export const apiGetOffHoursReport = (token: string, range: ReportRange) =>
  get<OffHoursReport>(`/reports/off-hours?${qs(range)}`, token);

// ─── Device risk ─────────────────────────────────────────────────────────────────
export interface DeviceRiskRow {
  agent: string;
  department: string | null;
  deviceType: string | null;
  deviceCriticality: string | null;
  alertCount: number;
  avgCAS: number;
  criticalCount: number;
}
export interface DeviceRiskReport {
  from: string;
  to: string;
  devices: DeviceRiskRow[];
}
export const apiGetDeviceRiskReport = (token: string, range: ReportRange) =>
  get<DeviceRiskReport>(`/reports/device-risk?${qs(range)}`, token);

// ─── Threat summary ──────────────────────────────────────────────────────────────
export interface ThreatSummaryReport {
  from: string;
  to: string;
  totalAlerts: number;
  bySeverity: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  byAction: { Immediate: number; Investigate: number; Monitor: number };
  byDepartment: { department: string; count: number }[];
  topLabels: { label: string; count: number }[];
  topDevices: { agent: string; count: number }[];
}
export const apiGetThreatSummaryReport = (token: string, range: ReportRange) =>
  get<ThreatSummaryReport>(`/reports/threat-summary?${qs(range)}`, token);

// ─── AI assistant narratives (backend/services/aiAssistantService.js) ─────────────
async function post<T>(path: string, token: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `Failed (HTTP ${res.status})`);
  return json;
}

// `summary` is the already-fetched report object (ThreatSummaryReport, or
// ComplianceSummary for the narrative below) sent back as-is — the backend
// doesn't re-query, it just narrates what the browser already has.
export const apiGenerateThreatNarrative = (token: string, summary: ThreatSummaryReport) =>
  post<{ narrative: string }>('/reports/threat-summary/narrative', token, { summary });

export const apiGenerateComplianceNarrative = (token: string, summary: unknown, framework: 'hipaa' | 'gdpr') =>
  post<{ narrative: string }>('/reports/compliance-narrative', token, { summary, framework });

// ─── Trending devices (data-only — no AI) ──────────────────────────────────────────
export interface TrendingDevice {
  agent: string;
  department: string | null;
  deviceType: string | null;
  deviceCriticality: string | null;
  alertCount: number;
  earlierAvgCas: number;
  recentAvgCas: number;
  maxCas: number;
}
export const apiGetTrendingDevices = (token: string) =>
  get<{ windowMinutes: number; devices: TrendingDevice[] }>('/reports/trending-devices', token);

// ─── Rule health (data-only — false-positive rate per detection rule) ─────────────
export interface RuleHealthRow {
  rule: string;
  total: number;
  true_positive: number;
  false_positive: number;
  benign: number;
  uncertain: number;
  unset: number;
  falsePositiveRate: number | null;
}
export const apiGetRuleHealth = (token: string, range: ReportRange) =>
  get<{ from: string; to: string; rules: RuleHealthRow[] }>(`/reports/rule-health?${qs(range)}`, token);
