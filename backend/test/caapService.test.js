import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ruleLevelToTrScore, CRITICALITY_TO_CC, lookupAe, shiftForHour, lookupTc, resolveScenarioKey } from '../services/caapService.js';

describe('ruleLevelToTrScore', () => {
  // Must land on app.py's 1-10 scale (doubled from the plan's 1-5 table —
  // see app.py:48) — this was the exact site of a prior bug where the
  // fallback stayed on the old 1-5 scale and CAS could never cross the
  // CRITICAL threshold (8) no matter how severe the underlying rule was.
  test('rescales Wazuh rule.level (0-15) onto a 1-10 ceiling, not 1-5', () => {
    assert.equal(ruleLevelToTrScore(15), 10);
    assert.equal(ruleLevelToTrScore(12), 10);
    assert.equal(ruleLevelToTrScore(9), 8);
    assert.equal(ruleLevelToTrScore(6), 6);
    assert.equal(ruleLevelToTrScore(3), 4);
    assert.equal(ruleLevelToTrScore(0), 2);
  });

  test('defaults to the lowest band when level is omitted', () => {
    assert.equal(ruleLevelToTrScore(), 2);
  });
});

describe('CRITICALITY_TO_CC', () => {
  // 5-tier FDA-device-class hierarchy (21 CFR 860.3) — see
  // MediSIEM_Medical_Device_Criticality_Ranking. 'elevated' (Tier 3,
  // Clinical Data & Informatics — PACS/EHR/LIS/clinical DB servers) sits
  // between 'medium' (Tier 2, IT infrastructure) and 'high' (Tier 4, direct
  // patient monitoring/diagnostic-therapeutic) on the same 10/8/6/4/2 scale
  // device_profiles already used in shared/cas_config.json.
  test('maps every MedicalDevice.criticality value onto the same 1-10 CC scale app.py uses', () => {
    assert.equal(CRITICALITY_TO_CC.critical, 10);
    assert.equal(CRITICALITY_TO_CC.high, 8);
    assert.equal(CRITICALITY_TO_CC.elevated, 6);
    assert.equal(CRITICALITY_TO_CC.medium, 4);
    assert.equal(CRITICALITY_TO_CC.low, 2);
  });
});

describe('CAS fallback formula (0.25 TR + 0.30 CC + 0.25 TS + 0.10 AE + 0.10 TC)', () => {
  // Mirrors the exact computation in caapService.js's enrichAlert() catch
  // branch — reproduced here rather than imported, since enrichAlert()
  // itself requires a live Mongo connection via lookupDevice(). This is
  // the regression test for the original bug: that branch used to assign
  // `CAS: tr` directly, discarding CC/TS/AE/TC entirely, which silently
  // capped every AI-outage alert at MEDIUM severity regardless of how
  // life-critical the device was.
  // TC (Temporal Context) only ever needed a clock, not the AI server —
  // matches app.py's lookup_tc(): night shift (fewer staff on duty) scores
  // higher than day shift. hour is a test parameter rather than reading the
  // real clock so this stays deterministic regardless of when it's run.
  function computeFallbackCas({ ruleLevel, criticality, knownExploited, hour = 12 }) {
    const tr = ruleLevelToTrScore(ruleLevel);
    const cc = CRITICALITY_TO_CC[criticality] ?? 4;
    const ts = 3;
    const ae = knownExploited ? 10 : 2;
    const tc = (hour < 6 || hour >= 22) ? 8 : 4;
    return Math.round((0.25 * tr + 0.3 * cc + 0.25 * ts + 0.1 * ae + 0.1 * tc) * 10) / 10;
  }

  test('a severe rule level against a life-critical device during night shift can reach CRITICAL (>= 8)', () => {
    const cas = computeFallbackCas({ ruleLevel: 15, criticality: 'critical', knownExploited: true, hour: 2 });
    assert.ok(cas >= 8, `expected CAS >= 8, got ${cas}`);
  });

  test('the same scenario during day shift lands just under CRITICAL — the fallback is deliberately conservative without real anomaly detection (TS)', () => {
    const cas = computeFallbackCas({ ruleLevel: 15, criticality: 'critical', knownExploited: true, hour: 12 });
    assert.ok(cas >= 6 && cas < 8, `expected a HIGH-band CAS (6-8), got ${cas}`);
  });

  test('the same rule level against a low-criticality device stays well below CRITICAL', () => {
    const cas = computeFallbackCas({ ruleLevel: 15, criticality: 'low', knownExploited: false, hour: 2 });
    assert.ok(cas < 8, `expected CAS < 8, got ${cas}`);
  });

  test('device criticality alone moves the score — this is what the old `CAS: tr` bug could never do', () => {
    const critical = computeFallbackCas({ ruleLevel: 6, criticality: 'critical', knownExploited: false });
    const low = computeFallbackCas({ ruleLevel: 6, criticality: 'low', knownExploited: false });
    assert.ok(critical > low, 'a life-critical device must score higher than a low-criticality one at the same rule level');
  });
});

describe('lookupAe (attack-type-aware AE — shared/cas_config.json ae_table)', () => {
  test('varies by predicted attack type instead of being binary', () => {
    // Previously app.py's lookup_ae() only looked at cve_known_exploited (2
    // or 10 flat) — every non-CVE alert scored identically regardless of
    // what the RF actually classified. These must now differ.
    const dos = lookupAe('DoS_TCP', false);
    const recon = lookupAe('Recon', false);
    const benign = lookupAe('Benign', false);
    assert.ok(dos > recon, `DoS_TCP (${dos}) must outrank Recon (${recon})`);
    assert.ok(recon > benign, `Recon (${recon}) must outrank Benign (${benign})`);
    assert.equal(benign, 0);
  });

  test('a known-exploited CVE/IP-reputation hit still always boosts to the ceiling', () => {
    assert.equal(lookupAe('Recon', true), 10);
    assert.equal(lookupAe('Benign', true), 10);
  });

  test('an unseen label falls to the shared default rather than crashing', () => {
    assert.equal(lookupAe('SomeNewAttackType', false), 4);
  });
});

describe('shiftForHour / lookupTc (3-tier temporal context, matches test.py current_shift())', () => {
  test('day 07-15, evening 15-23, else night', () => {
    assert.equal(shiftForHour(10), 'day');
    assert.equal(shiftForHour(18), 'evening');
    assert.equal(shiftForHour(2), 'night');
    assert.equal(shiftForHour(23), 'night');
  });

  test('night scores highest, day scores lowest', () => {
    const night = lookupTc(2);
    const evening = lookupTc(18);
    const day = lookupTc(10);
    assert.ok(night > evening && evening > day, `expected night (${night}) > evening (${evening}) > day (${day})`);
  });
});

describe('resolveScenarioKey (department -> scenario profile)', () => {
  test('ICU-family departments resolve to icu_critical_care', () => {
    assert.equal(resolveScenarioKey('ICU'), 'icu_critical_care');
    assert.equal(resolveScenarioKey('NICU'), 'icu_critical_care');
  });

  test('compound department strings match by substring', () => {
    assert.equal(resolveScenarioKey('Cardiology / Remote'), 'icu_critical_care');
    assert.equal(resolveScenarioKey('ICU / General Ward'), 'icu_critical_care');
  });

  test('an unrecognised department falls to the blended default rather than throwing', () => {
    assert.equal(resolveScenarioKey('Some New Department'), 'hospital_wide_mixed');
    assert.equal(resolveScenarioKey(undefined), 'hospital_wide_mixed');
  });
});
