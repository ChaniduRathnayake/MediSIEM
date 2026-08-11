// backend/config/deviceInventory.js
//
// Maps a Wazuh agent (by name or IP) to clinical metadata the CAAP model needs
// for the Clinical Criticality (CC) dimension: device_type + department.
//
// Backed by the `MedicalDevice` Mongo collection (managed from the admin
// Devices tab — onboard/edit/tag/decommission), not hardcoded. Since
// lookupDevice() is called once per alert on the polling pipeline, results
// are cached in memory for a short TTL rather than hitting Mongo per-alert;
// call invalidateDeviceInventoryCache() after any write so mutations are
// picked up on the very next lookup instead of waiting out the TTL.
import MedicalDevice from '../models/MedicalDevice.js';

const DEFAULT_DEVICE = { device_type: 'Unknown Device', department: 'General' };
const CACHE_TTL_MS = 60_000;

let cache = null; // Map<key, { device_type, department }>
let cacheLoadedAt = 0;
let loadingPromise = null;

async function loadCache() {
  const devices = await MedicalDevice.find().select('key deviceType department').lean();
  const map = new Map();
  for (const d of devices) {
    map.set(d.key, { device_type: d.deviceType, department: d.department });
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
 * Look up clinical metadata for a Wazuh agent.
 * @param {{name?: string, ip?: string}} agent
 */
export async function lookupDevice(agent = {}) {
  const key = (agent.name || agent.ip || '').toLowerCase();

  if (!cache || Date.now() - cacheLoadedAt > CACHE_TTL_MS) {
    if (!loadingPromise) loadingPromise = loadCache().finally(() => { loadingPromise = null; });
    try {
      await loadingPromise;
    } catch (err) {
      console.error('[deviceInventory] failed to load medical device inventory:', err.message);
      return cache?.get(key) || DEFAULT_DEVICE;
    }
  }

  return cache.get(key) || DEFAULT_DEVICE;
}
