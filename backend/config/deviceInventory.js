// Maps a Wazuh agent (by name or IP) to clinical metadata the CAAP model
// needs for the Clinical Criticality (CC) dimension: device_type + department.
// Backed by the `MedicalDevice` Mongo collection, cached in memory for a short
// TTL since lookupDevice() runs once per alert — call
// invalidateDeviceInventoryCache() after any write to pick up changes immediately.
import MedicalDevice from '../models/MedicalDevice.js';
import Device from '../models/Device.js';

const DEFAULT_DEVICE = { device_type: 'Unknown Device', department: 'General', criticality: 'medium' };
const CACHE_TTL_MS = 60_000;

let cache = null; // { byKey: Map<key, meta>, byAgentId: Map<wazuhAgentId, meta> }
let cacheLoadedAt = 0;
let loadingPromise = null;

async function loadCache() {
  // Independent queries — run concurrently rather than serializing two round
  // trips on every cache rebuild (this blocks lookupDevice() on the alert
  // fallback-scoring path whenever the 60s TTL has expired).
  const [devices, tags] = await Promise.all([
    MedicalDevice.find().select('key deviceType department criticality').lean(),
    // Manual per-agent tags (Devices page "Tag Medical Device") — an admin
    // explicitly linking a Wazuh agent to a clinical asset, for agents whose
    // hostname/IP doesn't happen to match a MedicalDevice.key.
    Device.find({ medicalDeviceId: { $ne: null } }).select('agentId medicalDeviceId').lean(),
  ]);
  const byKey = new Map();
  const byMedicalDeviceId = new Map();
  for (const d of devices) {
    const meta = { device_type: d.deviceType, department: d.department, criticality: d.criticality || 'medium' };
    byKey.set(d.key, meta);
    byMedicalDeviceId.set(String(d._id), meta);
  }

  const byAgentId = new Map();
  for (const t of tags) {
    const meta = byMedicalDeviceId.get(String(t.medicalDeviceId));
    if (meta) byAgentId.set(String(t.agentId), meta);
  }

  cache = { byKey, byAgentId };
  cacheLoadedAt = Date.now();
  return cache;
}

export function invalidateDeviceInventoryCache() {
  cache = null;
  loadingPromise = null;
}

/**
 * Pure resolution step, split out from lookupDevice() so it's unit-testable
 * without a Mongo connection: given an already-loaded cache and an agent,
 * which entry (if any) matches.
 *
 * Checks `agent.id` against the manual per-agent tag map first — a deliberate
 * admin tag beats any heuristic. Only then falls through to key matching,
 * trying `agent.ip` before `agent.name` — for the real ML path
 * (ml-pipeline/flow_consumer.py), `agent.name` holds the device TYPE
 * ("ICU Ventilator"), not a unique identifier, since flow_consumer.py's own
 * device_map.json already resolved the type before this doc was built. Only
 * `agent.ip` is actually unique per device on that path, so trying `name`
 * first (the old behavior) meant it always won on a truthy-but-wrong match
 * and `ip` was never even attempted. The raw Wazuh HIDS path (where
 * `agent.name` genuinely is a per-device hostname) still resolves correctly
 * here since it falls through to the name check when the ip lookup misses.
 * @param {{byKey: Map<string, {device_type: string, department: string, criticality: string}>, byAgentId: Map<string, {device_type: string, department: string, criticality: string}>}} deviceCache
 * @param {{id?: string|number, name?: string, ip?: string}} agent
 */
export function resolveDeviceKey(deviceCache, agent = {}) {
  const agentId = agent.id !== undefined && agent.id !== null ? String(agent.id) : '';
  if (agentId && deviceCache?.byAgentId?.has(agentId)) return deviceCache.byAgentId.get(agentId);

  const ipKey = (agent.ip || '').toLowerCase();
  const nameKey = (agent.name || '').toLowerCase();
  return deviceCache?.byKey?.get(ipKey) || deviceCache?.byKey?.get(nameKey) || DEFAULT_DEVICE;
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
