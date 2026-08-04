// backend/services/alertPipeline.js
//
// The live loop: poll the Indexer for new alerts → use them as-is if already
// enriched by flow_consumer.py (real RF + Isolation Forest + K-Means), or
// fall back to caapService's rule.level estimate only if they aren't → keep
// an in-memory buffer for REST reads → push each new one over Socket.IO so
// the dashboard updates in real time without polling.

import { fetchNewAlerts } from './wazuhIndexerService.js';
import { enrichAlert } from './caapService.js';
import { lookupDevice } from '../config/deviceInventory.js';

const {
  ALERT_POLL_INTERVAL_MS = '5000',
  ALERT_BUFFER_SIZE = '500',
} = process.env;

const BUFFER_SIZE = parseInt(ALERT_BUFFER_SIZE, 10);
const POLL_INTERVAL = parseInt(ALERT_POLL_INTERVAL_MS, 10);

let buffer = []; // newest first
let lastTimestamp = null;
let io = null; // set via init()
let pollHandle = null;

function toDisplayAlert(raw, enrichment) {
  // flow_consumer.py already stamps agent.department (real ML path). The
  // rule.level fallback path doesn't have that on the raw Wazuh doc, so look
  // it up the same way caapService.js does — same clinical inventory either way.
  const department = raw.agent?.department || lookupDevice(raw.agent || {}).department;

  // `enrichment` is often just the raw indexed doc minus `id` (the
  // already-enriched fast path), which still carries its OWN raw `agent`
  // object/`flow`/etc. Spread it FIRST so the explicit fields below always
  // win — otherwise `...enrichment` clobbers the flattened `agent` string
  // with the original {name, ip, department} object, and React throws
  // "Objects are not valid as a React child" the instant it tries to render it.
  return {
    ...enrichment,
    id: raw.id,
    timestamp: raw['@timestamp'],
    agent: raw.agent?.name || raw.agent?.ip || 'unknown',
    department,
    ruleDescription: raw.rule?.description || 'Unknown event',
    ruleLevel: raw.rule?.level ?? null,
  };
}

async function pollOnce() {
  try {
    const rawAlerts = await fetchNewAlerts(lastTimestamp);
    if (!rawAlerts.length) return;

    for (const raw of rawAlerts) {
      // caap-alerts documents are already fully scored by flow_consumer.py
      // (real RF + Isolation Forest + K-Means via /predict) — use them as-is.
      // Only alerts with no CAS field at all (e.g. polling a raw
      // wazuh-alerts-* index instead) fall back to enrichAlert(), which
      // itself only produces a rule.level estimate, not an ML classification.
      let enrichment;
      if (raw.CAS !== undefined) {
        const { id, ...rest } = raw;
        enrichment = rest;
      } else {
        console.warn(
          `[alertPipeline] ⚠ ALERT ${raw.id} HAS NO CAS FIELD — this index isn't pre-enriched by flow_consumer.py. ` +
            'Falling back to a rule.level estimate, which is NOT a real RF/IsolationForest/K-Means classification. ' +
            'Point WAZUH_INDEXER_INDEX at caap-alerts (populated by ml-pipeline/flow_consumer.py) for genuine ML detections.'
        );
        const result = await enrichAlert(raw);
        if (!result.ok) {
          console.warn(`[alertPipeline] ⚠ CAAP AI server unreachable for alert ${raw.id}: ${result.error}`);
        }
        enrichment = result.enrichment;
      }

      const displayAlert = toDisplayAlert(raw, enrichment);
      buffer.unshift(displayAlert);
      if (buffer.length > BUFFER_SIZE) buffer.pop();

      if (io) io.emit('alert:new', displayAlert);
      lastTimestamp = raw['@timestamp'] || lastTimestamp;
    }
  } catch (err) {
    console.error('[alertPipeline] poll failed:', err.message);
  }
}

/** Start the polling loop. Call once from server.js after Socket.IO is set up. */
export function startPipeline(socketIoInstance) {
  io = socketIoInstance;
  if (pollHandle) return; // already running
  console.log(`🔄  Alert pipeline polling every ${POLL_INTERVAL}ms`);
  pollOnce(); // fire immediately, then on interval
  pollHandle = setInterval(pollOnce, POLL_INTERVAL);
}

export function stopPipeline() {
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = null;
}

/** Current buffer, newest first, for the REST endpoint / initial page load. */
export function getBufferedAlerts({ limit = 100, sortByCas = false } = {}) {
  const alerts = sortByCas ? [...buffer].sort((a, b) => (b.CAS ?? 0) - (a.CAS ?? 0)) : buffer;
  return alerts.slice(0, limit);
}

export default { startPipeline, stopPipeline, getBufferedAlerts };
