// backend/services/caapService.js
//
// Bridges a raw Wazuh alert to the CAAP Flask AI server (ai_server/src/app.py,
// /predict) and returns an enriched alert with CAS score + action.
//
// IMPORTANT CAVEAT: the RF/IsolationForest/K-Means models were trained on the
// CIC IoMT-2024 flow-feature schema (Header_Length, Protocol Type, Rate,
// Srate, Drate, flag counts, per-protocol one-hot flags, Tot sum/Min/Max/AVG/
// Std/Tot size/IAT/Number/Magnitue/Radius/Covariance/Variance/Weight — see
// FLOW_FEATURE_KEYS below, kept in sync with FEATURE_COLUMNS in app.py).
// Wazuh HIDS alerts (auth.log, Windows Event IDs, syslog) don't carry those
// fields. Two consequences:
//   1. If you're also ingesting flow records with this schema into the same
//      Wazuh Indexer, alerts that DO have those fields get passed through as
//      extractFlowFeatures() below — and get a real RF classification.
//   2. Alerts without flow data get zero-filled features, so the RF label/
//      confidence is not meaningful. In that case we derive TR directly from
//      Wazuh's own rule.level (0–15) instead of trusting RF confidence, so
//      the CAS score still reflects something real rather than model noise.
//
// THIS PATH IS A FALLBACK ONLY. The primary path is ml-pipeline/flow_consumer.py
// writing already-enriched documents (real CAS) straight into the caap-alerts
// index — alertPipeline.js only calls enrichAlert() here when an alert has no
// CAS field, and it logs a loud warning every time that happens.

import { lookupDevice } from '../config/deviceInventory.js';
import { assessExploitation } from './cveIntelService.js';

const { CAAP_AI_URL = 'http://localhost:5001' } = process.env;

// device criticality (MedicalDevice.criticality, admin-managed) -> a CC score
// on the same 1-10 scale as app.py's CC_LOOKUP (see its comment: doubled from
// the plan's 1-5 table). Used only when we have no live model response to
// pull a real CC_score from — i.e. the CAAP AI server is unreachable.
export const CRITICALITY_TO_CC = { critical: 10, high: 7, medium: 4, low: 2 };

// The 45 flow feature names the model expects, in the CIC IoMT-2024 schema —
// keep in sync with FEATURE_COLUMNS in ai_server/models/feature_cols.pkl
// (verify with ai_server/verify_feature_cols.py).
const FLOW_FEATURE_KEYS = [
  'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
  'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number',
  'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
  'ack_count', 'syn_count', 'fin_count', 'rst_count',
  'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP',
  'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC',
  'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number',
  'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight',
];

/** Pull flow features out of a Wazuh alert doc if a flow-record decoder attached them. */
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

/**
 * Wazuh rule.level (0–15) → a TR score on the SAME 1-10 scale app.py's
 * rf_to_tr_score() produces (see app.py:48 — CC/TR/TS/AE/TC were all
 * rescaled 1-10, doubled from the plan's original 1-5 table, so CAS reaches
 * a real 10 ceiling). Used when we have no flow features to classify.
 */
export function ruleLevelToTrScore(level = 0) {
  if (level >= 12) return 10;
  if (level >= 9) return 8;
  if (level >= 6) return 6;
  if (level >= 3) return 4;
  return 2;
}

/**
 * Build the payload CAAP's /predict endpoint expects from a raw Wazuh alert.
 */
async function buildPredictPayload(alert) {
  const device = await lookupDevice(alert.agent || {});
  const timestamp = alert['@timestamp'] ? new Date(alert['@timestamp']) : new Date();
  const flowFeatures = extractFlowFeatures(alert);
  // Real "actively exploited" signal (CISA KEV) when the alert references a
  // CVE, falling back to "does this rule carry a MITRE technique" only when
  // there's no CVE to check against — see cveIntelService.js.
  const exploitation = assessExploitation(alert);

  const baseFeatures = flowFeatures || Object.fromEntries(FLOW_FEATURE_KEYS.map((k) => [k, 0.0]));

  return {
    ...baseFeatures,
    device_type: device.device_type,
    department: device.department,
    hour_of_day: timestamp.getHours(),
    cve_known_exploited: exploitation.exploited,
    // stash markers so we know downstream whether RF output is trustworthy,
    // and have a real device-criticality/exploitation basis on hand if the
    // AI server turns out to be unreachable and we have to fall back below.
    __hasFlowFeatures: Boolean(flowFeatures),
    __ruleLevel: alert.rule?.level ?? 0,
    __criticality: device.criticality,
    __exploitationBasis: exploitation.basis,
  };
}

/**
 * Enrich a single raw Wazuh alert by calling the CAAP Flask server.
 * Falls back to a rule.level-derived score if the AI server is unreachable
 * or the alert has no flow features to classify meaningfully.
 */
export async function enrichAlert(alert) {
  const payload = await buildPredictPayload(alert);
  const { __hasFlowFeatures, __ruleLevel, __criticality, __exploitationBasis, ...predictBody } = payload;

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
    // same way app.py does (0.25 TR + 0.30 CC + 0.25 TS + 0.10 AE + 0.10 TC).
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
      prediction.explanation = 'Derived from Wazuh rule.level (no flow features available) — NOT a real ML classification.';
    }

    return { ok: true, enrichment: prediction };
  } catch (err) {
    // CAAP server unreachable — degrade gracefully with a rule.level-only score
    // rather than dropping the alert. Every dimension below is still a real
    // signal (device inventory criticality, CISA KEV/MITRE exploitation
    // check, rule.level) — just not the RF/IsolationForest/K-Means output.
    const tr = ruleLevelToTrScore(__ruleLevel);
    const tsScore = 3; // no Isolation Forest anomaly signal available offline
    const ccScore = CRITICALITY_TO_CC[__criticality] ?? 4;
    const aeScore = payload.cve_known_exploited ? 10 : 2;
    // Unlike TS (needs live Isolation Forest inference we don't have here),
    // TC only ever needed a clock — matching app.py's lookup_tc() exactly
    // (night shift = higher weight, fewer staff on duty) rather than a
    // hardcoded placeholder that was inconsistent with the "reachable but
    // no flow features" branch above, which gets a real TC_score from the
    // live model. Uses the alert's own timestamp, same as buildPredictPayload().
    const alertHour = (alert['@timestamp'] ? new Date(alert['@timestamp']) : new Date()).getHours();
    const tcScore = (alertHour < 6 || alertHour >= 22) ? 8 : 4;
    // Same weighted formula as the "reachable but no flow features" branch
    // above (and app.py's compute_cas) — CAS must be the weighted blend of
    // all five dimensions, not just TR alone, or device-agnostic low-level
    // alerts and genuinely device-critical ones score identically and never
    // cross the CRITICAL threshold (this previously assigned `CAS: tr`
    // directly, silently capping every AI-outage alert at MEDIUM at best).
    const cas =
      0.25 * tr + 0.3 * ccScore + 0.25 * tsScore + 0.1 * aeScore + 0.1 * tcScore;
    return {
      ok: false,
      error: err.message,
      enrichment: {
        label: alert.rule?.description || 'Unclassified',
        confidence: null,
        TR_score: tr,
        TS_score: tsScore,
        CC_score: ccScore,
        AE_score: aeScore,
        TC_score: tcScore,
        cluster: 'unknown',
        CAS: Math.round(cas * 10) / 10,
        action: cas >= 8 ? 'Immediate' : cas >= 5 ? 'Investigate' : 'Monitor',
        explanation:
          `CAAP AI server unreachable (${err.message}) — showing a rule.level + device-criticality ` +
          `fallback (exploitation basis: ${__exploitationBasis}), NOT a real ML classification.`,
      },
    };
  }
}

export default { enrichAlert };
