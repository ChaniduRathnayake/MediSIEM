import { describe, test, expect } from 'vitest';
import { casToSeverity, levelToSeverity, actionToStatus, severityCounts, countBy, latestTimestamp, bucketAlertsByHour } from '../chartData';
import type { Severity } from '../chartData';

describe('casToSeverity', () => {
  test('matches the documented 0-10 thresholds exactly at their boundaries', () => {
    expect(casToSeverity(8)).toBe('CRITICAL');
    expect(casToSeverity(7.9)).toBe('HIGH');
    expect(casToSeverity(6)).toBe('HIGH');
    expect(casToSeverity(5.9)).toBe('MEDIUM');
    expect(casToSeverity(4)).toBe('MEDIUM');
    expect(casToSeverity(3.9)).toBe('LOW');
    expect(casToSeverity(0)).toBe('LOW');
  });

  // These thresholds are duplicated (by necessity — frontend/backend are
  // separate module graphs) in backend/services/alertPipeline.js's
  // casToSeverity() — kept identical there too, see that file's own test.
});

describe('levelToSeverity', () => {
  test('matches Wazuh rule.level thresholds (0-16 scale, different from CAS)', () => {
    expect(levelToSeverity(12)).toBe('CRITICAL');
    expect(levelToSeverity(8)).toBe('HIGH');
    expect(levelToSeverity(5)).toBe('MEDIUM');
    expect(levelToSeverity(0)).toBe('LOW');
  });
});

describe('actionToStatus', () => {
  test('maps each CAAP action to its case-status equivalent', () => {
    expect(actionToStatus('Immediate')).toBe('Open');
    expect(actionToStatus('Investigate')).toBe('Investigating');
    expect(actionToStatus('Monitor')).toBe('Resolved');
  });
});

describe('severityCounts', () => {
  test('buckets items by severity and preserves SEVERITY_ORDER', () => {
    const items: Severity[] = ['CRITICAL', 'HIGH', 'CRITICAL', 'LOW'];
    const result = severityCounts(items, (s) => s);
    expect(result.map((r) => r.name)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
    expect(result.find((r) => r.name === 'CRITICAL')?.value).toBe(2);
    expect(result.find((r) => r.name === 'MEDIUM')?.value).toBe(0);
  });
});

describe('countBy', () => {
  test('sorts descending by frequency and caps at topN', () => {
    const items = ['a', 'b', 'a', 'c', 'a', 'b'];
    const result = countBy(items, (x) => x, 2);
    expect(result).toEqual([{ label: 'a', value: 3 }, { label: 'b', value: 2 }]);
  });

  test('skips null/undefined keys rather than counting them as a group', () => {
    const items = ['a', null, undefined, 'a'];
    const result = countBy(items, (x) => x);
    expect(result).toEqual([{ label: 'a', value: 2 }]);
  });
});

describe('latestTimestamp', () => {
  test('returns the most recent valid timestamp among items', () => {
    const items = [{ t: '2025-01-01T00:00:00Z' }, { t: '2025-06-01T00:00:00Z' }, { t: '2025-03-01T00:00:00Z' }];
    const anchor = latestTimestamp(items, (i) => i.t);
    expect(anchor).toBe(new Date('2025-06-01T00:00:00Z').getTime());
  });

  test('skips unparsable/missing timestamps rather than letting them win', () => {
    const items = [{ t: 'not-a-date' }, { t: '2025-06-01T00:00:00Z' }, { t: null }];
    const anchor = latestTimestamp(items, (i) => i.t);
    expect(anchor).toBe(new Date('2025-06-01T00:00:00Z').getTime());
  });

  test('falls back to roughly "now" when there is nothing to anchor to', () => {
    const before = Date.now();
    const anchor = latestTimestamp([], () => null);
    const after = Date.now();
    expect(anchor).toBeGreaterThanOrEqual(before);
    expect(anchor).toBeLessThanOrEqual(after);
  });
});

describe('bucketAlertsByHour', () => {
  test('produces the requested number of hourly buckets', () => {
    const buckets = bucketAlertsByHour([], () => null, () => 'LOW', 6);
    expect(buckets).toHaveLength(6);
  });

  test('places an item in the correct bucket relative to the anchor and counts its severity', () => {
    const anchor = new Date('2025-06-01T12:00:00Z');
    const items = [{ t: new Date('2025-06-01T11:30:00Z').toISOString(), sev: 'CRITICAL' as Severity }];
    const buckets = bucketAlertsByHour(items, (i) => i.t, (i) => i.sev, 3);
    // 3 buckets ending at the anchor hour: [-2h, -1h, anchor-hour]; 11:30 is 30 minutes before noon, so it lands in the last bucket.
    const totalCritical = buckets.reduce((sum, b) => sum + b.CRITICAL, 0);
    expect(totalCritical).toBe(1);
    expect(buckets[buckets.length - 1].CRITICAL).toBe(1);
    void anchor; // anchor is derived internally from items, this just documents intent
  });

  test('skips items outside the requested window instead of overflowing into bucket 0', () => {
    // A single old item would define its own anchor (latestTimestamp picks
    // the newest timestamp present) and trivially land in-window — the
    // window only excludes anything once there's a newer item to anchor
    // against instead.
    const items = [
      { t: new Date('2025-06-01T12:00:00Z').toISOString(), sev: 'HIGH' as Severity },
      { t: new Date('2020-01-01T00:00:00Z').toISOString(), sev: 'LOW' as Severity },
    ];
    const buckets = bucketAlertsByHour(items, (i) => i.t, (i) => i.sev, 24);
    const totalLow = buckets.reduce((sum, b) => sum + b.LOW, 0);
    expect(totalLow).toBe(0);
  });
});
