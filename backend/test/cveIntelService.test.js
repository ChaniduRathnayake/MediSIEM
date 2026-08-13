import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { extractCveIds, assessExploitation, isKnownExploited, getKevStatus } from '../services/cveIntelService.js';

describe('extractCveIds', () => {
  test('extracts a CVE from data.vulnerability.cve', () => {
    const alert = { data: { vulnerability: { cve: 'CVE-2021-44228' } } };
    assert.deepEqual(extractCveIds(alert), ['CVE-2021-44228']);
  });

  test('extracts a CVE mentioned in free text (rule.description / full_log)', () => {
    const alert = { rule: { description: 'Exploit attempt for CVE-2021-44228 (Log4Shell) detected' } };
    assert.deepEqual(extractCveIds(alert), ['CVE-2021-44228']);
  });

  test('is case-insensitive and normalizes to uppercase', () => {
    const alert = { full_log: 'blocked cve-2023-12345 payload' };
    assert.deepEqual(extractCveIds(alert), ['CVE-2023-12345']);
  });

  test('dedupes when the same CVE appears in multiple fields', () => {
    const alert = {
      rule: { description: 'CVE-2021-44228 exploit' },
      full_log: 'CVE-2021-44228 CVE-2021-44228',
    };
    assert.deepEqual(extractCveIds(alert), ['CVE-2021-44228']);
  });

  test('returns an empty array when there is no CVE anywhere on the alert', () => {
    const alert = { rule: { description: 'Generic SSH brute force' } };
    assert.deepEqual(extractCveIds(alert), []);
  });

  test('never throws on a missing/malformed alert shape', () => {
    assert.deepEqual(extractCveIds({}), []);
    assert.deepEqual(extractCveIds(undefined), []);
  });
});

describe('assessExploitation', () => {
  // The KEV catalog is only ever populated by initCveIntel()'s real network
  // fetch (never called in tests, and the lab network these alerts come
  // from is documented as isolated/offline-by-default) — so kevSet is
  // empty here, same as it realistically is whenever KEV hasn't loaded.
  // This exercises exactly that fallback path, not a hypothetical one.
  test('falls back to the MITRE-technique heuristic when KEV has not loaded, even with a CVE present', () => {
    const alert = {
      data: { vulnerability: { cve: 'CVE-2021-44228' } },
      rule: { mitre: { id: ['T1190'] } },
    };
    const result = assessExploitation(alert);
    assert.equal(result.basis, 'mitre');
    assert.equal(result.exploited, true);
    assert.deepEqual(result.cveIds, ['CVE-2021-44228']);
  });

  test('is false with basis "none" when there is neither a CVE nor a MITRE mapping', () => {
    const result = assessExploitation({ rule: { description: 'Generic alert' } });
    assert.equal(result.exploited, false);
    assert.equal(result.basis, 'none');
  });

  test('isKnownExploited fails closed (false) when the catalog is not loaded, never assumes exploitation', () => {
    assert.equal(isKnownExploited(['CVE-2021-44228']), false);
  });

  test('getKevStatus reports not-loaded honestly rather than a stale/default true', () => {
    const status = getKevStatus();
    assert.equal(status.loaded, false);
    assert.equal(status.count, 0);
  });
});
