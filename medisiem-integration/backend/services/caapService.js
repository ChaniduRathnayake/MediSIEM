// backend/services/caapService.js
//
// Bridges a raw Wazuh alert to the CAAP Flask AI server (src/app.py, /predict)
// and returns an enriched alert with CAS score + action.
//
// IMPORTANT CAVEAT: the RF/IsolationForest/K-Means models were trained on
// network-flow features (Flow Bytes/s, IAT Mean, etc. — the CIC IoMT schema).
// Wazuh HIDS alerts (auth.log, Windows Event IDs, syslog) don't carry those
// fields. Two consequences:
//   1. If you're also ingesting Suricata/NetFlow data into the same Wazuh
//      Indexer, alerts that DO have those fields get passed through as-is —
//      see extractFlowFeatures() below — and get a real RF classification.
//   2. Alerts without flow data get zero-filled features, so the RF label/
//      confidence is not meaningful. In that case we derive TR directly from
//      Wazuh's own rule.level (0–15) instead of trusting RF confidence, so
//      the CAS score still reflects something real rather than model noise.
//      Swap this out once every source alert type is instrumented with flow
//      features.

import { lookupDevice } from '../config/deviceInventory.js';

const { CAAP_AI_URL = 'http://localhost:5001' } = process.env;

// The 44 flow feature names the model expects — keep in sync with
// FEATURE_COLUMNS in src/app.py.
const FLOW_FEATURE_KEYS = [
  'flow_bytes_s',
  'flow_packets_s',
  'iat_mean',
  'pkt_length_mean',
  // ...remaining flow feature columns from FEATURE_COLUMNS in src/app.py
];

/** Pull flow features out of a Wazuh alert doc if a Suricata/NetFlow decoder attached them. */
function extractFlowFeatures(alert) {
  const flow = alert.data?.flow || alert.data?.netflow || null;
  if (!flow) return null;

  const features = {};
  let found = 0;
  for (const key of FLOW_FEATURE_KEYS) {
    if (flow[key] !== undefined) {
      features[key] = Number(flow[key]);
      found += 1;
    } else {
      features[key] = 0.0;
    }
  }
  return found > 0 ? features : null;
}

/** Wazuh rule.level (0–15) → a 1–5 TR score, used when we have no flow features. */
function ruleLevelToTrScore(level = 0) {
  if (level >= 12) return 5;
  if (level >= 9) return 4;
  if (level >= 6) return 3;
  if (level >= 3) return 2;
  return 1;
}

/**
 * Build the payload CAAP's /predict endpoint expects from a raw Wazuh alert.
 */
function buildPredictPayload(alert) {
  const device = lookupDevice(alert.agent || {});
  const timestamp = alert['@timestamp'] ? new Date(alert['@timestamp']) : new Date();
  const flowFeatures = extractFlowFeatures(alert);

  const baseFeatures = flowFeatures || Object.fromEntries(FLOW_FEATURE_KEYS.map((k) => [k, 0.0]));

  return {
    ...baseFeatures,
    device_type: device.device_type,
    department: device.department,
    hour_of_day: timestamp.getHours(),
    cve_known_exploited: Boolean(alert.rule?.mitre?.id?.length),
    // stash a marker so we know downstream whether RF output is trustworthy
    __hasFlowFeatures: Boolean(flowFeatures),
    __ruleLevel: alert.rule?.level ?? 0,
  };
}

/**
 * Enrich a single raw Wazuh alert by calling the CAAP Flask server.
 * Falls back to a rule.level-derived score if the AI server is unreachable
 * or the alert has no flow features to classify meaningfully.
 */
export async function enrichAlert(alert) {
  const payload = buildPredictPayload(alert);
  const { __hasFlowFeatures, __ruleLevel, ...predictBody } = payload;

  try {
    const res = await fetch(`${CAAP_AI_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(predictBody),
    });

    if (!res.ok) throw new Error(`CAAP AI server responded ${res.status}`);
    const prediction = await res.json();

    // If there were no real flow features, RF's label/confidence is a guess —
    // override TR with the rule.level-derived score and recompute CAS the
    // same way src/app.py does (0.25 TR + 0.30 CC + 0.25 TS + 0.10 AE + 0.10 TC).
    if (!__hasFlowFeatures) {
      const tr = ruleLevelToTrScore(__ruleLevel);
      const cas =
        0.25 * tr +
        0.3 * prediction.CC_score +
        0.25 * prediction.TS_score +
        0.1 * prediction.AE_score +
        0.1 * prediction.TC_score;
      prediction.TR_score = tr;
      prediction.CAS = Math.round(cas * 10) / 10;
      prediction.action = cas >= 8 ? 'Immediate' : cas >= 5 ? 'Investigate' : 'Monitor';
      prediction.label = alert.rule?.description || prediction.label;
      prediction.confidence = null; // not meaningful without flow features
      prediction.explanation = 'Derived from Wazuh rule.level (no flow features available)';
    }

    return { ok: true, enrichment: prediction };
  } catch (err) {
    // CAAP server unreachable — degrade gracefully with a rule.level-only score
    // rather than dropping the alert.
    const tr = ruleLevelToTrScore(__ruleLevel);
    const device = lookupDevice(alert.agent || {});
    return {
      ok: false,
      error: err.message,
      enrichment: {
        label: alert.rule?.description || 'Unclassified',
        confidence: null,
        TR_score: tr,
        TS_score: 3,
        CC_score: 3,
        AE_score: 1,
        TC_score: 1,
        cluster: 'unknown',
        CAS: tr, // best-effort estimate only
        action: tr >= 4 ? 'Investigate' : 'Monitor',
        explanation: `CAAP AI server unreachable (${err.message}) — showing rule.level fallback only`,
      },
    };
  }
}

export default { enrichAlert };
