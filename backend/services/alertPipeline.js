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
import DetectionRule from '../models/DetectionRule.js';

const {
  ALERT_POLL_INTERVAL_MS = '5000',
  ALERT_BUFFER_SIZE = '500',
} = process.env;

const BUFFER_SIZE = parseInt(ALERT_BUFFER_SIZE, 10);
const POLL_INTERVAL = parseInt(ALERT_POLL_INTERVAL_MS, 10);

let buffer = []; // newest first
let bufferedIds = new Set(); // mirrors buffer's ids — O(1) dedup check, see pollOnce()
let lastTimestamp = null;
let io = null; // set via init()
let pollHandle = null;

// Cumulative counters — unlike `buffer` (capped at BUFFER_SIZE, oldest
// evicted to bound memory), these only ever grow for the life of the
// process. The buffer is what the alert *list* is drawn from; these are
// what "Total Alerts" / severity-mix stats should be drawn from, so those
// numbers don't freeze the instant the buffer fills up.
let totalCount = 0;
const severityTotals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

function casToSeverity(cas) {
  if (cas >= 8) return 'CRITICAL';
  if (cas >= 6) return 'HIGH';
  if (cas >= 4) return 'MEDIUM';
  return 'LOW';
}

// ─── Rule evaluation ────────────────────────────────────────────────────────
// Fixed field/operator whitelist — no scripting, no eval — evaluated against
// the same flattened alert shape toDisplayAlert() produces below. All
// conditions in a rule must match (AND only, see DetectionRule.js).
function conditionMatches(alert, { field, operator, value }) {
  const actual = alert[field];
  if (actual === undefined || actual === null) return false;

  if (operator === 'contains') {
    return String(actual).toLowerCase().includes(String(value).toLowerCase());
  }
  if (operator === 'equals') {
    // Numeric fields compare numerically even if `value` arrived as a string
    // from a form input; string fields compare case-insensitively.
    return typeof actual === 'number' ? Number(actual) === Number(value) : String(actual).toLowerCase() === String(value).toLowerCase();
  }
  const a = Number(actual);
  const v = Number(value);
  if (Number.isNaN(a) || Number.isNaN(v)) return false;
  if (operator === 'gte') return a >= v;
  if (operator === 'lte') return a <= v;
  if (operator === 'gt') return a > v;
  if (operator === 'lt') return a < v;
  return false;
}

function evaluateRules(alert, rules) {
  return rules
    .filter((rule) => rule.conditions.every((cond) => conditionMatches(alert, cond)))
    .map((rule) => ({ id: rule._id.toString(), name: rule.name }));
}

// Re-fetched once per poll cycle rather than cached indefinitely — cheap for
// a small collection, and means a rule edited in the UI takes effect on the
// very next poll without a separate cache-invalidation path.
async function getEnabledRules() {
  try {
    return await DetectionRule.find({ enabled: true });
  } catch (err) {
    console.error('[alertPipeline] failed to load detection rules:', err.message);
    return [];
  }
}

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

    // Loaded once per poll cycle, not per-alert — same rule set applies to
    // every alert in this batch.
    const rules = await getEnabledRules();

    for (const raw of rawAlerts) {
      // The Indexer's `@timestamp gt lastTimestamp` cursor can re-return an
      // alert already in the buffer — e.g. when several documents share the
      // same timestamp at millisecond precision and the range query's
      // boundary handling doesn't exclude all of them cleanly. Guard here
      // instead of trusting the query to never repeat itself: without this,
      // a re-fetched alert both duplicates the React key on the frontend
      // AND re-evaluates/re-emits as if it were new.
      if (bufferedIds.has(raw.id)) {
        lastTimestamp = raw['@timestamp'] || lastTimestamp;
        continue;
      }

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
      displayAlert.matchedRules = evaluateRules(displayAlert, rules);
      buffer.unshift(displayAlert);
      bufferedIds.add(displayAlert.id);
      if (buffer.length > BUFFER_SIZE) {
        const evicted = buffer.pop();
        bufferedIds.delete(evicted.id);
      }

      totalCount += 1;
      severityTotals[casToSeverity(displayAlert.CAS ?? 0)] += 1;

      if (io) {
        io.emit('alert:new', displayAlert);
        io.emit('alerts:stats', { totalCount, severityTotals });
      }
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

/** Cumulative counts since this process started — never shrinks, unlike the bounded buffer. */
export function getAlertStats() {
  return { totalCount, severityTotals: { ...severityTotals } };
}

export default { startPipeline, stopPipeline, getBufferedAlerts, getAlertStats };
