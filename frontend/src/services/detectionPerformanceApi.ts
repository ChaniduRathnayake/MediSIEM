import { BASE_URL } from './api';

export interface DetectionPerformanceScores {
  alertRankingAccuracy: Record<string, number | null>; // keys "5"/"10"/"20"
  meanTimeToCritical: number | null;
  falsePositiveRateTop10: number | null;
}

export interface AnalystFeedback {
  totalJudged: number;
  counts: { true_positive: number; false_positive: number; benign: number; uncertain: number };
  falsePositiveRate: number | null;
}

export interface DetectionPerformance {
  sampleSize: number;
  lifeCriticalCount: number;
  caap: DetectionPerformanceScores;
  ruleLevelOnly: DetectionPerformanceScores;
  analystFeedback: AnalystFeedback;
  methodology: string;
}

export async function apiGetDetectionPerformance(token: string): Promise<DetectionPerformance> {
  const res = await fetch(`${BASE_URL}/detection-performance`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to fetch detection performance metrics');
  return json;
}

// Mirrors the JSON shape ai_server/check_drift.py writes to
// reports/drift_report_<date>.json — see that script for exactly what
// z_score / out_of_range_fraction mean and don't mean.
export interface DriftFeatureReport {
  train_mean: number;
  train_std: number;
  live_mean: number;
  live_std: number;
  z_score: number;
  out_of_range_fraction: number;
  drifted: boolean;
}

export interface DriftReport {
  generated_at: string;
  input_file: string;
  input_rows: number;
  baseline_trained_at: string | null;
  status: 'ok' | 'insufficient_rows';
  z_threshold?: number;
  out_of_range_threshold?: number;
  drift_rate?: number;
  drifted_features?: string[];
  features?: Record<string, DriftFeatureReport>;
  min_rows_required?: number;
}

// Absent (404) until someone has actually run check_drift.py at least once
// — a script-generated report, not something the backend computes itself.
export async function apiGetDriftReport(token: string): Promise<{ filename: string; report: DriftReport } | null> {
  const res = await fetch(`${BASE_URL}/detection-performance/drift-report`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to fetch drift report');
  return json;
}

export interface KevStatus {
  loaded: boolean;
  count: number;
  lastUpdated: string | null;
  lastError: string | null;
}

export async function apiGetKevStatus(token: string): Promise<KevStatus> {
  const res = await fetch(`${BASE_URL}/threat-intel/kev-status`, {
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || 'Failed to fetch KEV status');
  return json;
}
