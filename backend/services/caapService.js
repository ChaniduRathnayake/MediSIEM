// Bridges a raw Wazuh alert to the CAAP Flask AI server (/predict) and returns an
// enriched alert with CAS score + action. Fallback path only — the primary path is
// ml-pipeline/flow_consumer.py writing pre-enriched docs straight into caap-alerts;
// this only runs when an alert has no CAS field, using zero-filled features (and a
// rule.level-derived TR instead of RF confidence) when there's no real flow data.

import { lookupDevice } from '../config/deviceInventory.js';
import { assessExploitation } from './cveIntelService.js';
import { checkIpReputation, isMalicious } from './ipReputationService.js';

const { CAAP_AI_URL = 'http://localhost:5001' } = process.env;

// Device criticality -> CC score (1-10 scale, matches app.py's CC_LOOKUP), used when
// the CAAP AI server is unreachable and there's no live model response to pull one from.
export const CRITICALITY_TO_CC = { critical: 10, high: 7, medium: 4, low: 2 };

// Keep in sync with FEATURE_COLUMNS in ai_server/models/feature_cols.pkl (verify_feature_cols.py).
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

// Wazuh rule.level (0-15) -> TR score, same 1-10 scale as app.py's rf_to_tr_score().
export function ruleLevelToTrScore(level = 0) {
  if (level >= 12) return 10;
  if (level >= 9) return 8;
  if (level >= 6) return 6;
  if (level >= 3) return 4;
  return 2;
}

// Builds the payload CAAP's /predict endpoint expects from a raw Wazuh alert.
async function buildPredictPayload(alert) {
  const device = await lookupDevice(alert.agent || {});
  const timestamp = alert['@timestamp'] ? new Date(alert['@timestamp']) : new Date();
  const flowFeatures = extractFlowFeatures(alert);
  // CISA KEV when the alert references a CVE, else "does this rule carry a MITRE technique".
  const exploitation = assessExploitation(alert);

  // Second, independent exploitation signal: is the source IP known-malicious per AbuseIPDB?
  const srcIp = alert.data?.srcip || alert.data?.src_ip || null;
  const ipReputationScore = await checkIpReputation(srcIp);
  const ipFlaggedMalicious = isMalicious(ipReputationScore);

  const baseFeatures = flowFeatures || Object.fromEntries(FLOW_FEATURE_KEYS.map((k) => [k, 0.0]));

  return {
    ...baseFeatures,
    device_type: device.device_type,
    department: device.department,
    // Real, admin-configured criticality — app.py's lookup_cc() prefers this
    // over its own tiny device_type -> CC table when present, so a device
    // type outside that hardcoded list still gets a real CC score instead of
    // silently falling to the lowest band.
    device_criticality: device.criticality,
    hour_of_day: timestamp.getHours(),
    cve_known_exploited: exploitation.exploited || ipFlaggedMalicious,
    // Markers for the fallback branch below if the AI server turns out unreachable.
    __hasFlowFeatures: Boolean(flowFeatures),
    // Carried through to the returned enrichment (below) so a closed, verdict-tagged
    // case with real flow data is eligible for training-feedback-export — otherwise
    // this alert would score correctly but be permanently invisible to that export,
    // since pickSnapshotFields()/training-feedback-export both key off alert.flow.
    __flowFeatures: flowFeatures,
    __ruleLevel: alert.rule?.level ?? 0,
    __criticality: device.criticality,
    __exploitationBasis: exploitation.exploited ? exploitation.basis : ipFlaggedMalicious ? 'ip_reputation' : exploitation.basis,
    __ipReputationScore: ipReputationScore,
  };
}

// Enrich a raw Wazuh alert via the CAAP Flask server, falling back to a rule.level-derived
// score if the AI server is unreachable or the alert has no flow features.
export async function enrichAlert(alert) {
  const payload = await buildPredictPayload(alert);
  const { __hasFlowFeatures, __flowFeatures, __ruleLevel, __criticality, __exploitationBasis, __ipReputationScore, ...predictBody } = payload;
  // Carried on the returned enrichment too, so the analyst can see the signal AE_score used.
  const srcIp = alert.data?.srcip || alert.data?.src_ip || null;

  try {
    const res = await fetch(`${CAAP_AI_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(predictBody),
    });

    if (!res.ok) throw new Error(`CAAP AI server responded ${res.status}`);
    const prediction = await res.json();

    // No real flow features -> RF's label/confidence is a guess; override TR and recompute
    // CAS the same way app.py does (0.25 TR + 0.30 CC + 0.25 TS + 0.10 AE + 0.10 TC).
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
      delete prediction.shap_top_features; // drop the now-meaningless SHAP breakdown from zero-filled features
    }

    if (srcIp) prediction.src_ip = srcIp;
    if (__ipReputationScore !== null && __ipReputationScore !== undefined) prediction.ipReputationScore = __ipReputationScore;
    if (__flowFeatures) prediction.flow = __flowFeatures;

    return { ok: true, enrichment: prediction };
  } catch (err) {
    // CAAP server unreachable — degrade gracefully with a rule.level-only score rather
    // than dropping the alert (device criticality, CISA KEV/MITRE, and rule.level are
    // all still real signals; just not the RF/IsolationForest/K-Means output).
    const tr = ruleLevelToTrScore(__ruleLevel);
    const tsScore = 3; // no Isolation Forest anomaly signal available offline
    const ccScore = CRITICALITY_TO_CC[__criticality] ?? 4;
    const aeScore = payload.cve_known_exploited ? 10 : 2;
    // Matches app.py's lookup_tc() (night shift = higher weight, fewer staff on duty).
    const alertHour = (alert['@timestamp'] ? new Date(alert['@timestamp']) : new Date()).getHours();
    const tcScore = (alertHour < 6 || alertHour >= 22) ? 8 : 4;
    // Same weighted blend as app.py's compute_cas — not TR alone, or device-agnostic and
    // device-critical alerts would score identically and never cross the CRITICAL threshold.
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
        ...(srcIp ? { src_ip: srcIp } : {}),
        ...(__ipReputationScore !== null && __ipReputationScore !== undefined ? { ipReputationScore: __ipReputationScore } : {}),
        ...(__flowFeatures ? { flow: __flowFeatures } : {}),
      },
    };
  }
}

export default { enrichAlert };
