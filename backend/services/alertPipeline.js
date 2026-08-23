// The live loop: poll the Indexer for new alerts, enrich via caapService if not already
// scored, buffer in memory for REST reads, and push each new one over Socket.IO.

import { fetchNewAlerts } from './wazuhIndexerService.js';
import { enrichAlert } from './caapService.js';
import { lookupDevice } from '../config/deviceInventory.js';
import DetectionRule from '../models/DetectionRule.js';
import { sendImmediateCasAlert } from './notificationService.js';
import AlertLog from '../models/AlertLog.js';

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

// Guards against the Indexer's `@timestamp gt lastTimestamp` cursor re-returning an
// already-processed document (millisecond-boundary overlap between polls).
const RECENT_RAW_ID_WINDOW_MS = 5 * 60 * 1000;
const recentRawIds = new Map(); // rawId -> seenAt

function pruneRecentRawIds(now) {
  for (const [id, seenAt] of recentRawIds) {
    if (now - seenAt >= RECENT_RAW_ID_WINDOW_MS) recentRawIds.delete(id);
  }
}

// Collapses repeats of the same rule+device+source within this window into one buffered
// entry with a running duplicateCount, instead of a row per repeat.
const DEDUP_WINDOW_MS = 2 * 60 * 1000;
const dedupSignatures = new Map(); // dedupKey -> { alertId, lastSeen }

function dedupKey(displayAlert) {
  return `${displayAlert.ruleDescription || ''}|${displayAlert.agent || ''}|${displayAlert.src_ip || ''}`;
}

function pruneStaleSignatures(now) {
  for (const [key, sig] of dedupSignatures) {
    if (now - sig.lastSeen >= DEDUP_WINDOW_MS) dedupSignatures.delete(key);
  }
}

// Unlike `buffer` (capped, oldest evicted), these only ever grow — what "Total Alerts" /
// severity-mix stats draw from, so they don't freeze once the buffer fills up.
let totalCount = 0;
const severityTotals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

export function casToSeverity(cas) {
  if (cas >= 8) return 'CRITICAL';
  if (cas >= 6) return 'HIGH';
  if (cas >= 4) return 'MEDIUM';
  return 'LOW';
}

// Fixed field/operator whitelist — no scripting/eval. All conditions in a rule must match.
export function conditionMatches(alert, { field, operator, value }) {
  const actual = alert[field];
  if (actual === undefined || actual === null) return false;

  if (operator === 'contains') {
    return String(actual).toLowerCase().includes(String(value).toLowerCase());
  }
  if (operator === 'equals') {
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

// Re-fetched each poll (not cached) so a rule edited in the UI takes effect next poll.
async function getEnabledRules() {
  try {
    return await DetectionRule.find({ enabled: true });
  } catch (err) {
    console.error('[alertPipeline] failed to load detection rules:', err.message);
    return [];
  }
}

async function toDisplayAlert(raw, enrichment) {
  // flow_consumer.py stamps agent.department and reuses agent.name for device TYPE (not
  // hostname); the rule.level fallback path has neither, so resolve both from inventory.
  const deviceMeta = await lookupDevice(raw.agent || {});
  const department = raw.agent?.department || deviceMeta.department;
  const deviceType = raw.agent?.department ? (raw.agent?.name || deviceMeta.device_type) : deviceMeta.device_type;

  // Spread enrichment FIRST so the explicit fields below win — otherwise it clobbers the
  // flattened `agent` string with the original {name, ip, department} object.
  return {
    ...enrichment,
    id: raw.id,
    timestamp: raw['@timestamp'],
    agent: raw.agent?.name || raw.agent?.ip || 'unknown',
    department,
    deviceType,
    deviceCriticality: deviceMeta.criticality,
    ruleDescription: raw.rule?.description || 'Unknown event',
    ruleLevel: raw.rule?.level ?? null,
    mitre: raw.rule?.mitre
      ? { id: raw.rule.mitre.id || [], tactic: raw.rule.mitre.tactic || [], technique: raw.rule.mitre.technique || [] }
      : null,
  };
}

async function pollOnce() {
  try {
    const rawAlerts = await fetchNewAlerts(lastTimestamp);
    if (!rawAlerts.length) return;

    const rules = await getEnabledRules();
    const now = Date.now();
    pruneStaleSignatures(now);
    pruneRecentRawIds(now);

    for (const raw of rawAlerts) {
      // Guards against the same millisecond-boundary re-return the window above prunes.
      if (recentRawIds.has(raw.id)) {
        lastTimestamp = raw['@timestamp'] || lastTimestamp;
        continue;
      }

      // caap-alerts docs are already scored by flow_consumer.py — use as-is. Only alerts
      // with no CAS field fall back to enrichAlert()'s rule.level estimate.
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

      const displayAlert = await toDisplayAlert(raw, enrichment);
      displayAlert.matchedRules = evaluateRules(displayAlert, rules);

      // If the same signature is still "live", fold into it (bump duplicateCount, re-emit
      // under the SAME id) instead of adding a new row.
      const key = dedupKey(displayAlert);
      const signature = dedupSignatures.get(key);
      const existing = signature && now - signature.lastSeen < DEDUP_WINDOW_MS
        ? buffer.find((a) => a.id === signature.alertId)
        : null;

      totalCount += 1;
      severityTotals[casToSeverity(displayAlert.CAS ?? 0)] += 1;
      recentRawIds.set(raw.id, now); // the raw alert has been consumed either way — never re-process it

      if (existing) {
        // Refresh every field from this occurrence's re-scoring (CAS, CVSS, action,
        // label, dimension scores, SHAP, matchedRules...) rather than freezing the
        // display on whatever the FIRST occurrence looked like — a long-lived dedup
        // group (same signature repeating for hours) was otherwise stuck showing
        // permanently stale data, e.g. missing a field (like CVSS) added to the
        // scoring pipeline after the group started. `id` and the accumulated count
        // are the only two things that must survive from the prior occurrence.
        const duplicateCount = (existing.duplicateCount || 1) + 1;
        Object.assign(existing, displayAlert, { id: existing.id, duplicateCount });
        signature.lastSeen = now;
        if (io) {
          io.emit('alert:new', existing);
          io.emit('alerts:stats', { totalCount, severityTotals });
        }
        // No notification here — the first occurrence already triggered one.
      } else {
        displayAlert.duplicateCount = 1;
        buffer.unshift(displayAlert);
        if (buffer.length > BUFFER_SIZE) buffer.pop();
        dedupSignatures.set(key, { alertId: displayAlert.id, lastSeen: now });

        if (io) {
          io.emit('alert:new', displayAlert);
          io.emit('alerts:stats', { totalCount, severityTotals });
        }
        sendImmediateCasAlert(displayAlert).catch((err) =>
          console.warn('[alertPipeline] Immediate-CAS notification failed:', err.message)
        );

        // Fire-and-forget — a slow Mongo write should never delay the live push above.
        AlertLog.findOneAndUpdate(
          { alertId: displayAlert.id },
          {
            alertId: displayAlert.id,
            timestamp: displayAlert.timestamp,
            CAS: displayAlert.CAS ?? null,
            action: displayAlert.action ?? null,
            severity: casToSeverity(displayAlert.CAS ?? 0),
            department: displayAlert.department ?? null,
            agent: displayAlert.agent ?? null,
            deviceType: displayAlert.deviceType ?? null,
            deviceCriticality: displayAlert.deviceCriticality ?? null,
            label: displayAlert.label ?? null,
            ruleDescription: displayAlert.ruleDescription ?? null,
            mitreTactic: displayAlert.mitre?.tactic ?? [],
            matchedRuleNames: (displayAlert.matchedRules ?? []).map((r) => r.name),
          },
          { upsert: true }
        ).catch((err) => console.warn('[alertPipeline] AlertLog write failed:', err.message));
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
