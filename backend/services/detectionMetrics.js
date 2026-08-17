// Live analogs of the three offline evaluation metrics in
// ai_server/src/hospital_scenarios.py (alert ranking accuracy / mean time to
// critical / false positive rate @N), run against the live in-memory alert
// buffer instead of the synthetic scenario dataset — `deviceCriticality`
// stands in for that script's `patient_dependency` label. A live monitoring
// signal, not a replacement for the offline evaluation, so every response
// carries `sampleSize` and a `methodology` string the UI must show alongside it.
import { getBufferedAlerts } from './alertPipeline.js';
import AlertClosure from '../models/AlertClosure.js';

const LIFE_CRITICAL = new Set(['critical']);
const LOW_RISK = new Set(['low']);

// 1-indexed rank, descending by score, ties broken by original buffer order
// (stable) — mirrors hospital_scenarios.py's _ranks() tie-break note: this
// matters most for the rule-level-only comparator, which has far fewer
// distinct values than CAS and so ties constantly.
export function ranks(alerts, scoreOf) {
  const withScore = alerts.map((a, i) => ({ i, score: scoreOf(a) }));
  withScore.sort((a, b) => b.score - a.score || a.i - b.i);
  const rank = new Array(alerts.length);
  withScore.forEach((entry, idx) => { rank[entry.i] = idx + 1; });
  return rank;
}

export function alertRankingAccuracy(alerts, r, nValues = [5, 10, 20]) {
  const lcIdx = alerts.map((a, i) => (LIFE_CRITICAL.has(a.deviceCriticality) ? i : -1)).filter((i) => i >= 0);
  const totalLc = lcIdx.length;
  const out = {};
  for (const n of nValues) {
    out[n] = totalLc ? (100 * lcIdx.filter((i) => r[i] <= n).length) / totalLc : null;
  }
  return out;
}

export function meanTimeToCritical(alerts, r) {
  const lcRanks = alerts.map((a, i) => (LIFE_CRITICAL.has(a.deviceCriticality) ? r[i] : null)).filter((v) => v !== null);
  if (!lcRanks.length) return null;
  return lcRanks.reduce((s, v) => s + v, 0) / lcRanks.length;
}

// hospital_scenarios.py's offline false_positive_rate_top_n() always divides
// by the fixed n, since its labeled dataset is guaranteed >= n rows. The
// live buffer isn't — right after a pipeline restart it can have far fewer
// than n alerts, and dividing by a fixed 10 there understates the true rate
// (e.g. 1 low-risk alert out of 3 total reads as 10%, not the real ~33%),
// which is exactly the moment this panel's sampleSize/methodology caveat is
// meant to warn about. Dividing by the actual top-N window size fixes that.
export function falsePositiveRateTopN(alerts, r, n = 10) {
  if (!alerts.length) return null;
  const windowSize = Math.min(n, alerts.length);
  const lowRiskInTopN = alerts.filter((a, i) => r[i] <= n && LOW_RISK.has(a.deviceCriticality)).length;
  return (100 * lowRiskInTopN) / windowSize;
}

function scoreAlerts(alerts, scoreOf) {
  const r = ranks(alerts, scoreOf);
  return {
    alertRankingAccuracy: alertRankingAccuracy(alerts, r),
    meanTimeToCritical: meanTimeToCritical(alerts, r),
    falsePositiveRateTop10: falsePositiveRateTopN(alerts, r, 10),
  };
}

const casScore = (a) => a.CAS ?? 0;
// The "what a generic, device-blind severity score alone would have
// surfaced" comparator — CAS's whole pitch is weighing device criticality
// in; raw Wazuh rule.level has no such term, making it the closest live
// analog to hospital_scenarios.py's CVSS-equivalent baseline without
// re-deriving CVSS itself.
const ruleLevelScore = (a) => a.ruleLevel ?? 0;

const VERDICT_KEYS = ['true_positive', 'false_positive', 'benign', 'uncertain'];

/**
 * The one piece of real ground truth this system captures about its own
 * accuracy: what analysts actually judged when closing a case (see
 * AlertClosure.verdict / CloseAlertModal.tsx), as opposed to every other
 * metric here and in hospital_scenarios.py, which either uses synthetic
 * labels or device-criticality as a proxy for "should this have ranked
 * high". Unlike the buffer-derived metrics above, this reads all-time from
 * MongoDB — closures are permanent, so this doesn't reset when an alert
 * ages out of the in-memory buffer.
 */
async function getAnalystFeedback() {
  const closures = await AlertClosure.find({ verdict: { $ne: null } }).select('verdict').lean();
  const counts = { true_positive: 0, false_positive: 0, benign: 0, uncertain: 0 };
  for (const c of closures) {
    if (VERDICT_KEYS.includes(c.verdict)) counts[c.verdict] += 1;
  }
  const totalJudged = closures.length;
  return {
    totalJudged,
    counts,
    // Specifically "the model flagged this and an analyst determined it
    // shouldn't have" — deliberately excludes `benign` (correctly flagged,
    // turned out harmless) and `uncertain`, which are different findings.
    falsePositiveRate: totalJudged ? (100 * counts.false_positive) / totalJudged : null,
  };
}

/**
 * Live-buffer analog of hospital_scenarios.py's build_caap_vs_cvss_table() —
 * CAS's ranking quality vs. a severity-only baseline, computed against
 * whatever's in the buffer right now rather than the labeled offline
 * evaluation set.
 */
export async function getDetectionPerformance() {
  const alerts = getBufferedAlerts({ limit: 500 });
  const lifeCriticalCount = alerts.filter((a) => LIFE_CRITICAL.has(a.deviceCriticality)).length;

  return {
    sampleSize: alerts.length,
    lifeCriticalCount,
    caap: scoreAlerts(alerts, casScore),
    ruleLevelOnly: scoreAlerts(alerts, ruleLevelScore),
    analystFeedback: await getAnalystFeedback(),
    methodology:
      "Live-buffer analog of the offline evaluation in ai_server/src/hospital_scenarios.py — same rank-based " +
      "ARA/MTCAI/FPR definitions, computed against the current in-memory alert buffer instead of the labeled " +
      "synthetic scenario dataset. deviceCriticality (admin-managed inventory) stands in for the offline " +
      "evaluation's patient_dependency label. analystFeedback is the exception — real ground truth from closed " +
      "cases, read all-time from MongoDB, not a proxy. Neither replaces the full offline evaluation.",
  };
}
