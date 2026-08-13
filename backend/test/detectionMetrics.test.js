import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ranks, alertRankingAccuracy, meanTimeToCritical, falsePositiveRateTopN } from '../services/detectionMetrics.js';

const scoreOf = (a) => a.score;

describe('ranks', () => {
  test('ranks descending by score, 1-indexed', () => {
    const alerts = [{ score: 5 }, { score: 9 }, { score: 1 }];
    assert.deepEqual(ranks(alerts, scoreOf), [2, 1, 3]);
  });

  test('breaks ties by original order (stable)', () => {
    const alerts = [{ score: 5 }, { score: 5 }, { score: 5 }];
    assert.deepEqual(ranks(alerts, scoreOf), [1, 2, 3]);
  });
});

describe('alertRankingAccuracy', () => {
  test('is null when there are no life-critical alerts to rank (nothing to measure)', () => {
    const alerts = [{ score: 9, deviceCriticality: 'low' }];
    const r = ranks(alerts, scoreOf);
    const ara = alertRankingAccuracy(alerts, r, [5]);
    assert.equal(ara[5], null);
  });

  test('100% when every life-critical alert lands inside top-N', () => {
    const alerts = [
      { score: 9, deviceCriticality: 'critical' },
      { score: 8, deviceCriticality: 'critical' },
      { score: 1, deviceCriticality: 'low' },
    ];
    const r = ranks(alerts, scoreOf);
    const ara = alertRankingAccuracy(alerts, r, [2]);
    assert.equal(ara[2], 100);
  });

  test('drops below 100% when a life-critical alert is ranked outside top-N', () => {
    const alerts = [
      { score: 9, deviceCriticality: 'low' },
      { score: 8, deviceCriticality: 'low' },
      { score: 1, deviceCriticality: 'critical' }, // ranked last
    ];
    const r = ranks(alerts, scoreOf);
    const ara = alertRankingAccuracy(alerts, r, [2]);
    assert.equal(ara[2], 0);
  });
});

describe('meanTimeToCritical', () => {
  test('is the average rank of life-critical alerts — lower is better', () => {
    const alerts = [
      { score: 9, deviceCriticality: 'critical' }, // rank 1
      { score: 5, deviceCriticality: 'critical' }, // rank 2
      { score: 1, deviceCriticality: 'low' },       // rank 3
    ];
    const r = ranks(alerts, scoreOf);
    assert.equal(meanTimeToCritical(alerts, r), 1.5);
  });

  test('is null when there are no life-critical alerts', () => {
    const alerts = [{ score: 1, deviceCriticality: 'low' }];
    const r = ranks(alerts, scoreOf);
    assert.equal(meanTimeToCritical(alerts, r), null);
  });
});

describe('falsePositiveRateTopN', () => {
  test('divides by the actual window size, not a fixed n, when the buffer has fewer than n alerts', () => {
    // Regression test: this used to divide by the fixed `n` (10) even when
    // the live buffer had far fewer alerts than that, understating the
    // true rate right after every pipeline restart — 1 low-risk alert out
    // of 3 total used to read as 10%, not the real ~33%.
    const alerts = [
      { score: 9, deviceCriticality: 'critical' },
      { score: 5, deviceCriticality: 'low' },
      { score: 1, deviceCriticality: 'medium' },
    ];
    const r = ranks(alerts, scoreOf);
    assert.equal(falsePositiveRateTopN(alerts, r, 10), 100 / 3);
  });

  test('is null on an empty buffer rather than dividing by zero', () => {
    assert.equal(falsePositiveRateTopN([], [], 10), null);
  });

  test('uses the fixed n once the buffer is at least that large', () => {
    const alerts = Array.from({ length: 20 }, (_, i) => ({ score: 20 - i, deviceCriticality: i < 3 ? 'low' : 'high' }));
    const r = ranks(alerts, scoreOf);
    // 3 low-risk alerts, all ranked in the top 10 (they're first 3 by score)
    assert.equal(falsePositiveRateTopN(alerts, r, 10), 30);
  });
});
