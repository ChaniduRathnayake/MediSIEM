import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { casToSeverity, conditionMatches } from '../services/alertPipeline.js';

describe('casToSeverity', () => {
  test('matches the documented 0-10 thresholds exactly at their boundaries', () => {
    assert.equal(casToSeverity(8), 'CRITICAL');
    assert.equal(casToSeverity(7.9), 'HIGH');
    assert.equal(casToSeverity(6), 'HIGH');
    assert.equal(casToSeverity(5.9), 'MEDIUM');
    assert.equal(casToSeverity(4), 'MEDIUM');
    assert.equal(casToSeverity(3.9), 'LOW');
    assert.equal(casToSeverity(0), 'LOW');
  });
});

describe('conditionMatches (detection rule engine)', () => {
  const alert = { ruleDescription: 'Brute force detected', ruleLevel: 10, CAS: 8.5, agent: 'ICU Ventilator' };

  test('contains — case-insensitive substring match', () => {
    assert.equal(conditionMatches(alert, { field: 'ruleDescription', operator: 'contains', value: 'brute' }), true);
    assert.equal(conditionMatches(alert, { field: 'ruleDescription', operator: 'contains', value: 'ransomware' }), false);
  });

  test('equals — numeric fields compare numerically even when value arrives as a string', () => {
    assert.equal(conditionMatches(alert, { field: 'ruleLevel', operator: 'equals', value: '10' }), true);
    assert.equal(conditionMatches(alert, { field: 'ruleLevel', operator: 'equals', value: 11 }), false);
  });

  test('equals — string fields compare case-insensitively', () => {
    assert.equal(conditionMatches(alert, { field: 'agent', operator: 'equals', value: 'icu ventilator' }), true);
  });

  test('gte/lte/gt/lt — numeric comparisons', () => {
    assert.equal(conditionMatches(alert, { field: 'CAS', operator: 'gte', value: 8 }), true);
    assert.equal(conditionMatches(alert, { field: 'CAS', operator: 'gt', value: 8.5 }), false);
    assert.equal(conditionMatches(alert, { field: 'CAS', operator: 'lte', value: 8.5 }), true);
    assert.equal(conditionMatches(alert, { field: 'CAS', operator: 'lt', value: 8 }), false);
  });

  test('returns false when the field is missing on the alert, never throws', () => {
    assert.equal(conditionMatches(alert, { field: 'department', operator: 'contains', value: 'ICU' }), false);
  });

  test('returns false for a non-numeric comparison on a non-numeric field rather than coercing wrongly', () => {
    assert.equal(conditionMatches(alert, { field: 'agent', operator: 'gte', value: 5 }), false);
  });

  test('unknown operator falls through to false (fixed whitelist, no scripting/eval surface)', () => {
    assert.equal(conditionMatches(alert, { field: 'ruleLevel', operator: '__proto__', value: 1 }), false);
  });
});
