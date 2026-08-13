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
