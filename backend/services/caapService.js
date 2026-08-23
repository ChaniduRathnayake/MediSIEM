// Bridges a raw Wazuh alert to the CAAP Flask AI server (/predict) and returns an
// enriched alert with CAS score + action. Fallback path only — the primary path is
// ml-pipeline/flow_consumer.py writing pre-enriched docs straight into caap-alerts;
// this only runs when an alert has no CAS field, using zero-filled features (and a
// rule.level-derived TR instead of RF confidence) when there's no real flow data.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { lookupDevice } from '../config/deviceInventory.js';
import { assessExploitation } from './cveIntelService.js';
import { checkIpReputation, isMalicious } from './ipReputationService.js';
import SystemSettings from '../models/SystemSettings.js';

const { CAAP_AI_URL = 'http://localhost:5001' } = process.env;

// ─── Shared CAS config — single source of truth also loaded by ai_server's
// cas_config.py (app.py's live /predict, cas_engine.py's offline research
// engine). Do not hardcode weights/AE/CC tables here — edit
// shared/cas_config.json instead so all three runtimes stay in sync.
const _SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const CAS_CONFIG_PATH = path.join(_SCRIPT_DIR, '..', '..', 'shared', 'cas_config.json');
const CAS_CONFIG = JSON.parse(readFileSync(CAS_CONFIG_PATH, 'utf-8'));

// Device criticality -> CC score (1-10 scale, matches app.py's CC_LOOKUP), used when
// the CAAP AI server is unreachable and there's no live model response to pull one from.
export const CRITICALITY_TO_CC = CAS_CONFIG.criticality_to_cc;

const AE_TABLE = CAS_CONFIG.ae_table;
const DEFAULT_AE = CAS_CONFIG.default_ae;
const TC_TABLE = CAS_CONFIG.tc_table;
const SHIFT_HOURS = CAS_CONFIG.shift_hours;
const DEFAULT_WEIGHTS = CAS_CONFIG.default_weights;
const CVSS_BASE_BY_LABEL = CAS_CONFIG.cvss_base_by_label;
const DEFAULT_CVSS = CAS_CONFIG.default_cvss;

// Attack-type base severity (varies by what the RF actually classified),
// boosted to the ceiling by an independent known-exploited-CVE/IP-reputation
// hit — mirrors ai_server's cas_config.lookup_ae() exactly.
export function lookupAe(predictedLabel, cveKnownExploited) {
  const base = Number(AE_TABLE[predictedLabel] ?? DEFAULT_AE);
  return Math.max(base, cveKnownExploited ? 10 : 0);
}

// CVSS-equivalent baseline, shown alongside CAS on the dashboard for direct
// comparison — mirrors ai_server's cas_config.lookup_cvss() exactly. Only used
// on the fallback paths below; when the AI server is reachable, its /predict
// response already includes a real CVSS field this module just forwards.
export function lookupCvss(predictedLabel) {
  return Number(CVSS_BASE_BY_LABEL[predictedLabel] ?? DEFAULT_CVSS);
}

// Same day/evening/night hour boundaries as ai_server's cas_config.shift_for_hour()
// / test.py's current_shift() — day 07-15, evening 15-23, else night.
export function shiftForHour(hourOfDay) {
  const h = ((Number(hourOfDay) % 24) + 24) % 24;
  const [dayStart, dayEnd] = SHIFT_HOURS.day;
  const [eveStart, eveEnd] = SHIFT_HOURS.evening;
  if (h >= dayStart && h < dayEnd) return 'day';
  if (h >= eveStart && h < eveEnd) return 'evening';
  return 'night';
}

export function lookupTc(hourOfDay) {
  return Number(TC_TABLE[shiftForHour(hourOfDay)] ?? TC_TABLE.day);
}

function weightsSumValid(weights, tol = 0.01) {
  if (!weights) return false;
  const total = ['TR', 'CC', 'TS', 'AE', 'TC'].reduce((sum, k) => sum + (Number(weights[k]) || 0), 0);
  return Math.abs(total - 1) <= tol;
}

// ─── Scenario resolution — MedicalDevice.department (free text) -> one of
// CAS_CONFIG.scenario_weight_profiles' keys. Mirrors cas_config.py's
// resolve_scenario_key() exactly (exact match, then substring containment,
// else the blended hospital-wide default).
const DEPT_TO_SCENARIO = new Map();
for (const [scenarioKey, depts] of Object.entries(CAS_CONFIG.scenario_department_map)) {
  for (const d of depts) DEPT_TO_SCENARIO.set(d.trim().toLowerCase(), scenarioKey);
}

// Whole-token match on compound strings (e.g. "ICU / General Ward" -> tokens
// "icu","general","ward") — NOT raw substring containment, since short
// abbreviations like "IT"/"ENT" would otherwise false-positive against an
// unrelated word (e.g. "ent" inside "department").
export function resolveScenarioKey(department) {
  if (!department) return 'hospital_wide_mixed';
  const deptL = String(department).trim().toLowerCase();
  if (DEPT_TO_SCENARIO.has(deptL)) return DEPT_TO_SCENARIO.get(deptL);
  for (const token of deptL.split(/[^a-z0-9]+/).filter(Boolean)) {
    if (DEPT_TO_SCENARIO.has(token)) return DEPT_TO_SCENARIO.get(token);
  }
  return 'hospital_wide_mixed';
}

// ─── CAS weight resolution — short-TTL cache, same pattern as
// deviceInventory.js's loadCache(), since this runs once per alert. Admin's
// scenario override wins, else admin's edited default, else the built-in
// AHP-justified vector from shared/cas_config.json.
const CAS_WEIGHTS_CACHE_TTL_MS = 60_000;
let casSettingsCache; // undefined = not loaded yet; null = loaded, none configured
let casSettingsCacheLoadedAt = 0;
let casSettingsLoadingPromise = null;

async function loadCasSettingsCache() {
  const settings = await SystemSettings.findOne().select('casWeights').lean();
  casSettingsCache = settings?.casWeights || null;
  casSettingsCacheLoadedAt = Date.now();
  return casSettingsCache;
}

export function invalidateCasWeightsCache() {
  casSettingsCache = undefined;
  casSettingsLoadingPromise = null;
}

export async function resolveCasWeights(department) {
  const scenario = resolveScenarioKey(department);
  if (casSettingsCache === undefined || Date.now() - casSettingsCacheLoadedAt > CAS_WEIGHTS_CACHE_TTL_MS) {
    if (!casSettingsLoadingPromise) casSettingsLoadingPromise = loadCasSettingsCache().finally(() => { casSettingsLoadingPromise = null; });
    try {
      await casSettingsLoadingPromise;
    } catch (err) {
      console.error('[caapService] failed to load CAS weight settings, using built-in defaults:', err.message);
      casSettingsCache = null;
    }
  }

  const scenarioOverride = casSettingsCache?.scenarios?.[scenario];
  if (weightsSumValid(scenarioOverride)) return { weights: scenarioOverride, scenario };

  const defaultOverride = casSettingsCache?.default;
  if (weightsSumValid(defaultOverride)) return { weights: defaultOverride, scenario };

  const builtIn = CAS_CONFIG.scenario_weight_profiles[scenario] || DEFAULT_WEIGHTS;
  return { weights: builtIn, scenario };
}

function weightedCas(tr, cc, ts, ae, tc, weights) {
  const w = weights || DEFAULT_WEIGHTS;
  const cas = w.TR * tr + w.CC * cc + w.TS * ts + w.AE * ae + w.TC * tc;
  return Math.round(cas * 10) / 10;
}

// A flow classified Benign never escalates past Monitor, no matter how
// critical the device — mirrors app.py's cas_to_action() Benign guard.
function actionFor(cas, label) {
  if (label === 'Benign') return 'Monitor';
  return cas >= 8 ? 'Immediate' : cas >= 5 ? 'Investigate' : 'Monitor';
}

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

// Raw flow-record column names for destination port / protocol — same
// candidate list as ml-pipeline/flow_consumer.py's
// DST_PORT_CANDIDATES, so the CC dimension's port-based device-profile
// lookup (app.py's lookup_cc()) gets real device signal on this path too,
// not just the primary flow_consumer.py path.
const DST_PORT_CANDIDATES = ['Dst Port', 'Destination Port', 'dst_port', 'dstPort'];
const PROTOCOL_CANDIDATES = ['Protocol Type', 'Protocol', 'protocol_type', 'protocol'];

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

/** Destination port / protocol (rule-based CC signal, not an ML feature) — never
 * zero-filled like extractFlowFeatures() above, since a fabricated port would
 * feed a wrong device profile into the CC lookup rather than just a weaker one. */
function extractDstPortProtocol(alert) {
  const flow = alert.data?.flow || alert.data?.netflow || null;
  if (!flow) return {};
  const out = {};
  for (const c of DST_PORT_CANDIDATES) {
    if (flow[c] !== undefined && flow[c] !== null && flow[c] !== '') {
      out['Dst Port'] = Number(flow[c]);
      break;
    }
  }
  for (const c of PROTOCOL_CANDIDATES) {
    if (flow[c] !== undefined && flow[c] !== null && flow[c] !== '') {
      out['Protocol Type'] = flow[c];
      break;
    }
  }
  return out;
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
  const portProtoFields = extractDstPortProtocol(alert);
  // CISA KEV when the alert references a CVE, else "does this rule carry a MITRE technique".
  const exploitation = assessExploitation(alert);

  // Second, independent exploitation signal: is the source IP known-malicious per AbuseIPDB?
  const srcIp = alert.data?.srcip || alert.data?.src_ip || null;
  const ipReputationScore = await checkIpReputation(srcIp);
  const ipFlaggedMalicious = isMalicious(ipReputationScore);

  const baseFeatures = flowFeatures || Object.fromEntries(FLOW_FEATURE_KEYS.map((k) => [k, 0.0]));

  // Resolved client-side (independent of whether the Flask AI server is
  // reachable) so both the live /predict call AND this module's own
  // fallback paths below use the exact same admin-configured/scenario
  // weight vector — see resolveCasWeights().
  const { weights: casWeights, scenario } = await resolveCasWeights(device.department);

  return {
    ...baseFeatures,
    ...portProtoFields,
    device_type: device.device_type,
    department: device.department,
    // Real, admin-configured criticality — app.py's lookup_cc() prefers this
    // over its own tiny device_type -> CC table when present, so a device
    // type outside that hardcoded list still gets a real CC score instead of
    // silently falling to the lowest band.
    device_criticality: device.criticality,
    hour_of_day: timestamp.getHours(),
    cve_known_exploited: exploitation.exploited || ipFlaggedMalicious,
    cas_weights: casWeights,
    scenario,
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
    // CAS the same way app.py does (resolved weights, attack-type-aware AE, Benign guard).
    // CC_score/AE_score/TS_score/TC_score/scenario/weights_used are still Flask's own —
    // only TR (meaningless without real flow data) and the CAS/action it produced change.
    if (!__hasFlowFeatures) {
      const tr = ruleLevelToTrScore(__ruleLevel);
      const predictedLabel = prediction.label; // real RF label, before being overwritten below
      const cas = weightedCas(tr, prediction.CC_score, prediction.TS_score, prediction.AE_score, prediction.TC_score, prediction.weights_used || payload.cas_weights);
      prediction.TR_score = tr;
      prediction.CAS = cas;
      prediction.action = actionFor(cas, predictedLabel);
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
    // all still real signals; just not the RF/IsolationForest/K-Means output). No real
    // predicted label exists offline, so AE falls to the shared DEFAULT_AE rather than
    // a per-attack-type value — there's no attack-type signal to look one up with here.
    const tr = ruleLevelToTrScore(__ruleLevel);
    const tsScore = 3; // no Isolation Forest anomaly signal available offline
    const ccScore = CRITICALITY_TO_CC[__criticality] ?? 4;
    const aeScore = lookupAe(null, payload.cve_known_exploited);
    const tcScore = lookupTc(new Date(alert['@timestamp'] || Date.now()).getHours());
    const weights = payload.cas_weights;
    const cas = weightedCas(tr, ccScore, tsScore, aeScore, tcScore, weights);
    // No real RF label exists offline either, so CVSS (which depends only on
    // attack type) falls to the same shared default AE does above.
    const cvssScore = lookupCvss(null);
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
        CAS: cas,
        CVSS: cvssScore,
        action: actionFor(cas, null),
        scenario: payload.scenario,
        weights_used: weights,
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
