// backend/services/alertPipeline.js
//
// The live loop: poll Wazuh Indexer for new alerts → enrich each via CAAP →
// keep an in-memory buffer for REST reads → push each new one over
// Socket.IO so the dashboard updates in real time without polling.

import { fetchNewAlerts } from './wazuhIndexerService.js';
import { enrichAlert } from './caapService.js';

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
  return {
    id: raw.id,
    timestamp: raw['@timestamp'],
    agent: raw.agent?.name || raw.agent?.ip || 'unknown',
    ruleDescription: raw.rule?.description || 'Unknown event',
    ruleLevel: raw.rule?.level ?? null,
    ...enrichment,
  };
}

async function pollOnce() {
  try {
    const rawAlerts = await fetchNewAlerts(lastTimestamp);
    if (!rawAlerts.length) return;

    for (const raw of rawAlerts) {
      // caap-alerts documents are already fully scored by flow_consumer.py
      // (real RF + Isolation Forest + K-Means via /predict) — use them as-is.
      // Only alerts with no CAS field at all (e.g. you're polling a raw
      // wazuh-alerts-* index instead) fall back to enrichAlert(), which
      // itself only produces a rule.level estimate, not an ML classification.
      let enrichment;
      if (raw.CAS !== undefined) {
        const { id, ...rest } = raw;
        enrichment = rest;
      } else {
        console.warn(
          `[alertPipeline] alert ${raw.id} has no CAS field — this index isn't pre-enriched. ` +
            'Falling back to a rule.level estimate, which is NOT an ML classification. ' +
            'Point WAZUH_INDEXER_INDEX at caap-alerts (populated by flow_consumer.py) for real detections.'
        );
        const result = await enrichAlert(raw);
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
