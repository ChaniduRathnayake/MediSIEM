// Maps a Wazuh agent (by name or IP) to clinical metadata the CAAP model
// needs for the Clinical Criticality (CC) dimension: device_type + department.
// Backed by the `MedicalDevice` Mongo collection, cached in memory for a short
// TTL since lookupDevice() runs once per alert — call
// invalidateDeviceInventoryCache() after any write to pick up changes immediately.
import MedicalDevice from '../models/MedicalDevice.js';

const DEFAULT_DEVICE = { device_type: 'Unknown Device', department: 'General', criticality: 'medium' };
const CACHE_TTL_MS = 60_000;

let cache = null; // Map<key, { device_type, department, criticality }>
let cacheLoadedAt = 0;
let loadingPromise = null;

async function loadCache() {
  const devices = await MedicalDevice.find().select('key deviceType department criticality').lean();
  const map = new Map();
  for (const d of devices) {
    map.set(d.key, { device_type: d.deviceType, department: d.department, criticality: d.criticality || 'medium' });
  }
  cache = map;
  cacheLoadedAt = Date.now();
  return map;
}

export function invalidateDeviceInventoryCache() {
  cache = null;
  loadingPromise = null;
}

/**
 * Pure resolution step, split out from lookupDevice() so it's unit-testable
 * without a Mongo connection: given an already-loaded cache Map and an
 * agent, which entry (if any) matches.
 *
 * Tries `agent.ip` before `agent.name` — for the real ML path
 * (ml-pipeline/flow_consumer.py), `agent.name` holds the device TYPE
 * ("ICU Ventilator"), not a unique identifier, since flow_consumer.py's own
 * device_map.json already resolved the type before this doc was built. Only
 * `agent.ip` is actually unique per device on that path, so trying `name`
 * first (the old behavior) meant it always won on a truthy-but-wrong match
 * and `ip` was never even attempted. The raw Wazuh HIDS path (where
 * `agent.name` genuinely is a per-device hostname) still resolves correctly
 * here since it falls through to the name check when the ip lookup misses.
 * @param {Map<string, {device_type: string, department: string, criticality: string}>} deviceCache
 * @param {{name?: string, ip?: string}} agent
 */
export function resolveDeviceKey(deviceCache, agent = {}) {
  const ipKey = (agent.ip || '').toLowerCase();
  const nameKey = (agent.name || '').toLowerCase();
  return deviceCache?.get(ipKey) || deviceCache?.get(nameKey) || DEFAULT_DEVICE;
}

/**
 * Look up clinical metadata for a Wazuh agent.
 * @param {{name?: string, ip?: string}} agent
 */
export async function lookupDevice(agent = {}) {
  if (!cache || Date.now() - cacheLoadedAt > CACHE_TTL_MS) {
    if (!loadingPromise) loadingPromise = loadCache().finally(() => { loadingPromise = null; });
    try {
      await loadingPromise;
    } catch (err) {
      console.error('[deviceInventory] failed to load medical device inventory:', err.message);
      return resolveDeviceKey(cache, agent);
    }
  }

  return resolveDeviceKey(cache, agent);
}
