import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isMalicious, MALICIOUS_SCORE_THRESHOLD } from '../services/ipReputationService.js';

describe('isMalicious', () => {
  test('true at and above the threshold', () => {
    assert.equal(isMalicious(MALICIOUS_SCORE_THRESHOLD), true);
    assert.equal(isMalicious(100), true);
  });

  test('false below the threshold', () => {
    assert.equal(isMalicious(MALICIOUS_SCORE_THRESHOLD - 1), false);
    assert.equal(isMalicious(0), false);
  });

  test('false for null/undefined — "no signal" is never treated as "malicious"', () => {
    assert.equal(isMalicious(null), false);
    assert.equal(isMalicious(undefined), false);
  });
});
