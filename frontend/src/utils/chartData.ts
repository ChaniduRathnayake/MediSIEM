// Pure data-shaping helpers shared by every chart widget. Kept framework-
// agnostic (no React, no recharts types) so they're trivial to unit-reason
// about and reusable between the CAS-based live alert feed (EnrichedAlert)
// and the Wazuh-Indexer-based historical browser (WazuhAlertRow).

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ef4444', // red-500
  HIGH: '#f97316',     // orange-500
  MEDIUM: '#f59e0b',   // amber-500
  LOW: '#3b82f6',      // blue-500
};

// EnrichedAlert.CAS is 0-10 (see backend CAS = TR*0.25 + CC*0.30 + TS*0.25 + AE*0.10 + TC*0.10)
export function casToSeverity(cas: number): Severity {
  if (cas >= 8) return 'CRITICAL';
  if (cas >= 6) return 'HIGH';
  if (cas >= 4) return 'MEDIUM';
  return 'LOW';
}

// Wazuh rule.level is 0-16; thresholds match AlertsBrowser's existing severityClass()
export function levelToSeverity(level: number): Severity {
  if (level >= 12) return 'CRITICAL';
  if (level >= 8) return 'HIGH';
  if (level >= 5) return 'MEDIUM';
  return 'LOW';
}

export function actionToStatus(action: 'Immediate' | 'Investigate' | 'Monitor'): 'Open' | 'Investigating' | 'Resolved' {
  return action === 'Immediate' ? 'Open' : action === 'Investigate' ? 'Investigating' : 'Resolved';
}

export interface SeverityCount {
  name: Severity;
  value: number;
  color: string;
}

export function severityCounts<T>(items: T[], severityOf: (item: T) => Severity): SeverityCount[] {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const item of items) counts[severityOf(item)]++;
  return SEVERITY_ORDER.map((name) => ({ name, value: counts[name], color: SEVERITY_COLORS[name] }));
}

export interface TimeBucket {
  time: string; // short label, e.g. "14:00"
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

// The most recent valid timestamp actually present in `items`, falling back
// to wall-clock now when there's nothing to anchor to (empty list, or every
// timestamp is missing/unparsable). Used as the reference point for any
// "trailing N hours" window — a live feed's newest item is ~now anyway, so
// this is a no-op there, but a buffer with no fresh traffic (demo data, an
// indexer that's fallen behind) would otherwise make every "last 24h" stat
// read as zero even though it's full of real alerts, just not from the
// last hour relative to the wall clock.
export function latestTimestamp<T>(items: T[], getTime: (item: T) => string | null | undefined): number {
  let anchor = Date.now();
  let anchorFound = false;
  for (const item of items) {
    const raw = getTime(item);
    if (!raw) continue;
    const t = new Date(raw).getTime();
    if (Number.isNaN(t)) continue;
    if (!anchorFound || t > anchor) { anchor = t; anchorFound = true; }
  }
  return anchor;
}

// Buckets items into `hours` hourly slots stacked by severity, ending at
// latestTimestamp(items). Items with an unparsable/missing timestamp are
// skipped rather than silently lumped into the anchor — a bad timestamp
// shouldn't distort the trend.
export function bucketAlertsByHour<T>(
  items: T[],
  getTime: (item: T) => string | null | undefined,
  severityOf: (item: T) => Severity,
  hours = 24
): TimeBucket[] {
  const bucketMs = 60 * 60 * 1000;
  const anchor = latestTimestamp(items, getTime);

  const buckets: TimeBucket[] = Array.from({ length: hours }, (_, i) => {
    const bucketStart = anchor - (hours - 1 - i) * bucketMs;
    return {
      time: new Date(bucketStart).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
    };
  });

  for (const item of items) {
    const raw = getTime(item);
    if (!raw) continue;
    const t = new Date(raw).getTime();
    if (Number.isNaN(t)) continue;
    const age = anchor - t;
    if (age < 0 || age > hours * bucketMs) continue;
    const idx = hours - 1 - Math.floor(age / bucketMs);
    if (idx < 0 || idx >= hours) continue;
    buckets[idx][severityOf(item)]++;
  }

  return buckets;
}

export interface CountEntry {
  label: string;
  value: number;
}

// Generic "top N by frequency" — used for department/agent/rule breakdowns.
export function countBy<T>(items: T[], keyOf: (item: T) => string | null | undefined, topN = 6): CountEntry[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const key = keyOf(item);
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, topN);
}
