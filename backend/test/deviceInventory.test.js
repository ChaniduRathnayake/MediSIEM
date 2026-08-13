import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { resolveDeviceKey } from '../config/deviceInventory.js';

describe('resolveDeviceKey', () => {
  test('resolves by IP even when a truthy-but-wrong name is also present (regression: the flow_consumer.py path bug)', () => {
    // flow_consumer.py stuffs the device TYPE ("Infusion Pump") into
    // agent.name, not a unique identifier — a Mongo cache keyed by the
    // real device id ("inf-pump-12") should still resolve via agent.ip,
    // not silently fall through to DEFAULT_DEVICE because "infusion pump"
    // matched nothing.
    const cache = new Map([
      ['192.168.16.132', { device_type: 'Infusion Pump', department: 'ICU', criticality: 'critical' }],
    ]);
    const result = resolveDeviceKey(cache, { name: 'Infusion Pump', ip: '192.168.16.132' });
    assert.equal(result.criticality, 'critical');
    assert.equal(result.department, 'ICU');
  });

  test('falls back to name when ip is absent or unmatched (real Wazuh HIDS path)', () => {
    const cache = new Map([
      ['icu-workstation-02', { device_type: 'Workstation', department: 'ICU', criticality: 'low' }],
    ]);
    const result = resolveDeviceKey(cache, { name: 'ICU-Workstation-02' });
    assert.equal(result.criticality, 'low');
  });

  test('is case-insensitive on both ip and name keys', () => {
    const cache = new Map([['ICU-VENT-04'.toLowerCase(), { device_type: 'ICU Ventilator', department: 'ICU', criticality: 'critical' }]]);
    const result = resolveDeviceKey(cache, { name: 'ICU-Vent-04' });
    assert.equal(result.criticality, 'critical');
  });

  test('returns the default device when nothing matches', () => {
    const cache = new Map([['known-device', { device_type: 'X', department: 'Y', criticality: 'high' }]]);
    const result = resolveDeviceKey(cache, { name: 'totally-unknown', ip: '10.0.0.99' });
    assert.equal(result.device_type, 'Unknown Device');
    assert.equal(result.criticality, 'medium');
  });

  test('returns the default device when the cache itself is empty/missing', () => {
    const result = resolveDeviceKey(null, { name: 'anything' });
    assert.equal(result.device_type, 'Unknown Device');
  });
});
