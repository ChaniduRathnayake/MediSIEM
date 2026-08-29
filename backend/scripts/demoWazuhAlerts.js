#!/usr/bin/env node
// demoWazuhAlerts.js — indexes ten synthetic alert documents straight into the
// Wazuh Indexer's "caap-alerts" index (the same index/shape
// ml-pipeline/flow_consumer.py writes real ML-scored flow alerts into), one
// every DELAY_MS.
//
// This is the actual front door of MediSIEM's live pipeline:
//   OpenSearch (caap-alerts) -> backend/services/alertPipeline.js's 5s poll
//     -> in-memory buffer + Socket.IO "alert:new"  (shows up on the Alerts page)
//     -> (same loop iteration, fire-and-forget) pushToLifeCriticalEngine()
//        -> AlertLog + SoarAction in Mongo                (shows up in the
//                                                            Playbooks/SOAR tab)
//
// An earlier version of this script called pushToLifeCriticalEngine()
// directly, which skipped straight to the Playbook step — the alerts never
// touched the Alerts page because that page reads alertPipeline.js's
// in-memory buffer, not Mongo. Indexing into caap-alerts instead lets the
// backend's own already-running pipeline do both steps itself, in the
// correct order, exactly like a real alert.
//
// Ten scenarios cover every branch of the decision engine's classifier
// (life-critical-orchestration/engine/src/decision/classifier.py) — see
// that file's own header comment for the CAS/criticality band boundaries.
// Note: cas_score in this codebase is 0-10, not 0-1 (docs/alert-schema.md).
// Five of the ten are Tier 3, each reaching "extreme" a different way:
//   1. numeric threshold + ransomware category together (cas_score >= 8 AND
//      the category hard override both fire at once)
//   2. category hard override ALONE (active_exploitation) while cas_score
//      stays under 8 — the override still fires independent of the number
//   3. numeric threshold ALONE (cas_score >= 8) with no extreme-listed
//      category — the mirror image of #2
//   4. the fail-safe path: criticality_score is omitted entirely (an
//      unregistered/unrecognized device), which the engine substitutes with
//      score=10/life_critical/fail_safe_applied=true — combined with a
//      ransomware category so it still needs an extreme threat to reach
//      Tier 3, same as every other protected asset
//   5. category override again, but on a clinical_support-band asset
//      (criticality_score 5-7, NOT life_critical 8-10) — both protected
//      bands take the identical Tier 2/3 split (docs/alert-schema.md), this
//      is the demo proof that the lower band isn't treated differently
//
// Each scenario gets its own unique source IP instead of a handful being
// reused across scenarios — every decision engine push uses agent.ip as its
// asset_id (see lifeCriticalBridgeService.js's buildEnrichedAlert), so
// reusing an IP across scenarios used to bucket unrelated decisions under the
// same asset in the Playbooks tab / IP Reputation view. The first seven use
// 192.168.16.132-.139 (the lab subnet); .132/.134/.139 stay pinned to their
// real lab VM roles (ml-pipeline/device_map.json: Infusion Pump/ICU, ICU
// Ventilator/ICU, CT/MRI System/Radiology respectively) — every OTHER
// scenario that shares a device type with one of those gets a fresh
// never-reused address instead of that device type's real IP a second time.
// .133 is the one address in that range left unassigned. The three newest
// scenarios use 192.168.16.40-.42 — a different address entirely (not a real
// lab VM), close to it in the .40s. Each scenario's own CC_score is picked to
// hit its intended classifier branch, independent of that device's real
// clinical role — e.g. the Tier 1 (non-critical) scenarios deliberately use a
// low CC_score on a real clinical device for demo-branch coverage, not
// because that device is actually non-critical.
//
// Prerequisites:
//   - Wazuh Indexer (OpenSearch) reachable at WAZUH_INDEXER_URL
//   - Backend server running with its alert-pipeline poll loop active, and
//     the decision engine reachable, so the alerts actually get processed
//   - Alert timestamps must be fresh: alertPipeline.js's isStaleAlert() (2 min
//     threshold) skips the life-critical push + notifications for anything
//     older, so this script stamps @timestamp at the moment each doc is sent
//
// NOTE: because this goes through the real pipeline, a Tier 2/3 result will
// also trigger MediSIEM's real notifications (email/Slack/Teams, if
// configured) — same as a genuine alert would. That's intentional for a
// live demo of the full response chain, but worth knowing before running.
//
// Usage (from backend/):
//   node scripts/demoWazuhAlerts.js        # 10s between alerts (default)
//   node scripts/demoWazuhAlerts.js 5      # 5s between alerts
//   npm run demo:wazuh-alerts

import 'dotenv/config';
import { Agent, fetch } from 'undici';

const {
  WAZUH_INDEXER_URL = 'https://localhost:9200',
  WAZUH_INDEXER_USER = 'admin',
  WAZUH_INDEXER_PASS = 'changeme',
  WAZUH_INDEXER_INDEX = 'wazuh-alerts-*',
  WAZUH_INDEXER_VERIFY_SSL = 'false',
} = process.env;

const DELAY_MS = (Number(process.argv[2]) || 10) * 1000;

const dispatcher = new Agent({
  connect: { rejectUnauthorized: WAZUH_INDEXER_VERIFY_SSL === 'true' },
});
const authHeader = 'Basic ' + Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASS}`).toString('base64');

// Shape mirrors ml-pipeline/flow_consumer.py's indexed doc (agent/src_ip/dst_ip
// + the AI server's /predict response spread at top level) plus an optional
// `rule` block (a real Wazuh-rule alert would carry one; a pure ML-flow alert
// normally doesn't, but alertPipeline.js's toDisplayAlert() reads it
// generically either way, and it makes the Alerts page row far more readable
// than the flow-only path's usual "Unknown event").
function buildDoc({ srcIp, dstIp, dstPort, deviceType, department, ruleId, ruleDescription, ruleLevel, ruleGroups, cveKnownExploited, label, confidence, TR_score, TS_score, CC_score, AE_score, TC_score, shift, CAS, CVSS, action }) {
  return {
    // @timestamp is intentionally NOT set here — this object is built once,
    // synchronously, while the `scenarios` array literal below is evaluated
    // at script startup, long before the delayed sends happen. Stamping it
    // here would freeze every scenario to the same instant. alertPipeline.js
    // uses `@timestamp > lastTimestamp` (strictly greater than) as its poll
    // cursor, so multiple alerts sharing one timestamp value all get
    // collapsed onto the same side of that cursor — the first poll to catch
    // any of them advances the cursor to that exact value, and every other
    // alert with the identical timestamp then permanently fails the `>`
    // check on every later poll. Each doc gets its own fresh timestamp in
    // main(), right before it's actually sent.
    src_ip: srcIp,
    dst_ip: dstIp ?? '',
    agent: { name: deviceType, ip: srcIp, department },
    rule: { id: ruleId, description: ruleDescription, level: ruleLevel, groups: ruleGroups ?? [] },
    flow: dstPort != null ? { 'Dst Port': dstPort } : undefined,
    // Read by lifeCriticalBridgeService.js's resolveCategory() — camelCase
    // exactly, since this doc's fields reach it unmodified (no snake_case
    // conversion happens on this path; that only occurs inside
    // caapService.js's enrichAlert() fallback, which a doc carrying its own
    // CAS never goes through). Triggers the category-based "extreme" hard
    // override (EXTREME_THREAT_CATEGORIES includes 'active_exploitation')
    // independent of cas_score.
    cveKnownExploited: cveKnownExploited || undefined,
    label,
    confidence,
    TR_score,
    TS_score,
    CC_score,
    AE_score,
    TC_score,
    shift,
    CAS,
    CVSS,
    action,
    cluster: 'demo',
    model_version: 'demo-1.0.0',
  };
}

// The three real lab VMs (ml-pipeline/device_map.json) — each scenario below
// that shares a device type with one of these gets a distinct address
// instead (see the file-header comment for why), never one of these three.
const IP_INFUSION_PUMP = '192.168.16.132'; // Infusion Pump, ICU
const IP_ICU_VENTILATOR = '192.168.16.134'; // ICU Ventilator, ICU
const IP_CT_MRI = '192.168.16.139'; // CT/MRI System, Radiology

// Extra addresses in the same /24, one per scenario that would otherwise
// have repeated a real VM's IP a second or third time.
const IP_CT_MRI_2 = '192.168.16.135'; // CT/MRI System, Radiology (2nd unit)
const IP_INFUSION_PUMP_2 = '192.168.16.136'; // Infusion Pump, ICU (2nd unit)
const IP_ICU_VENTILATOR_2 = '192.168.16.137'; // ICU Ventilator, ICU (2nd unit)
const IP_CT_MRI_3 = '192.168.16.138'; // CT/MRI System, Radiology (3rd unit)

// A different address entirely — not one of the .132-.139 lab-VM addresses
// above, just close to it — for the three newest scenarios.
const IP_DIALYSIS = '192.168.16.40'; // Dialysis Machine, Nephrology
const IP_UNREGISTERED = '192.168.16.41'; // unregistered/unrecognized device
const IP_ANESTHESIA = '192.168.16.42'; // Anesthesia Machine, Surgery

const scenarios = [
  {
    title: 'Tier 1 - log_only (non-critical asset, low CAS)',
    doc: buildDoc({
      srcIp: IP_CT_MRI, deviceType: 'CT/MRI System', department: 'Radiology',
      ruleId: '5710', ruleDescription: 'Multiple connection attempts from same source', ruleLevel: 5,
      label: 'Port Scan', confidence: 0.9, TR_score: 2.0, TS_score: 1.5, CC_score: 3, AE_score: 1.0, TC_score: 2.0,
      shift: 'day', CAS: 2.1, CVSS: 3.1, action: 'Monitor',
    }),
  },
  {
    title: 'Tier 1 - block_port (non-critical asset, medium CAS)',
    doc: buildDoc({
      srcIp: IP_INFUSION_PUMP, dstIp: '198.51.100.23', dstPort: 445, deviceType: 'Infusion Pump', department: 'ICU',
      ruleId: '31151', ruleDescription: 'Suspicious outbound SMB traffic to unfamiliar host', ruleLevel: 8,
      label: 'Lateral Movement', confidence: 0.85, TR_score: 5.0, TS_score: 3.0, CC_score: 4, AE_score: 4.5, TC_score: 3.0,
      shift: 'day', CAS: 5.4, CVSS: 5.8, action: 'Investigate',
    }),
  },
  {
    title: 'Tier 1 - isolate_host (non-critical asset, high CAS)',
    doc: buildDoc({
      srcIp: IP_ICU_VENTILATOR, deviceType: 'ICU Ventilator', department: 'ICU',
      ruleId: '87104', ruleDescription: 'Known malware signature detected: Trojan.GenericKD', ruleLevel: 12,
      // CAS must clear classifier.py's CAS_MEDIUM_MAX (8.0) to land in isolate_host
      // rather than block_port — 8.5 keeps a safety margin above that boundary.
      label: 'Malware', confidence: 0.95, TR_score: 8.0, TS_score: 4.0, CC_score: 2, AE_score: 7.5, TC_score: 5.0,
      shift: 'evening', CAS: 8.5, CVSS: 8.2, action: 'Immediate',
    }),
  },
  {
    title: 'Tier 2 - throttle (protected asset, non-extreme, destination flagged)',
    doc: buildDoc({
      srcIp: IP_CT_MRI_2, dstIp: '203.0.113.55', dstPort: 445, deviceType: 'CT/MRI System', department: 'Radiology',
      ruleId: '92053', ruleDescription: 'Outbound connection to unfamiliar external host', ruleLevel: 9,
      label: 'Brute Force', confidence: 0.88, TR_score: 6.0, TS_score: 4.5, CC_score: 6, AE_score: 5.5, TC_score: 4.0,
      shift: 'night', CAS: 6.5, CVSS: 6.9, action: 'Investigate',
    }),
  },
  {
    title: 'Tier 2 - monitored_mode (protected asset, non-extreme, no destination)',
    doc: buildDoc({
      srcIp: IP_INFUSION_PUMP_2, deviceType: 'Infusion Pump', department: 'ICU',
      ruleId: '92052', ruleDescription: 'Multiple authentication failures from same source IP', ruleLevel: 10,
      label: 'Brute Force', confidence: 0.9, TR_score: 5.0, TS_score: 4.8, CC_score: 7, AE_score: 3.5, TC_score: 4.5,
      shift: 'night', CAS: 5.0, CVSS: 5.5, action: 'Investigate',
    }),
  },
  {
    title: 'Tier 3 (1 of 5) - await_clinician_approval via CAS >= 8 AND ransomware category',
    doc: buildDoc({
      srcIp: IP_ICU_VENTILATOR_2, deviceType: 'ICU Ventilator', department: 'ICU',
      ruleId: '100340', ruleDescription: 'Multiple file modifications consistent with ransomware encryption pattern', ruleLevel: 15,
      ruleGroups: ['ransomware'],
      label: 'Ransomware', confidence: 0.97, TR_score: 9.5, TS_score: 4.9, CC_score: 9, AE_score: 9.0, TC_score: 4.5,
      shift: 'night', CAS: 9.6, CVSS: 9.8, action: 'Immediate',
    }),
  },
  {
    // Second Tier 3 example, deliberately triggered a different way: CAS
    // stays at 7.5 (under classifier.py's EXTREME_CAS_THRESHOLD of 8.0) — it's
    // the 'active_exploitation' category hard override alone that pushes this
    // to Tier 3, per classifier.py's documented "known-dangerous category
    // always escalates, even if the numeric score landed just under
    // threshold". cveKnownExploited=true is what resolveCategory() reads to
    // assign that category (see buildDoc's comment above).
    title: 'Tier 3 (2 of 5) - await_clinician_approval via known-exploited-CVE category override alone',
    doc: buildDoc({
      srcIp: IP_CT_MRI_3, deviceType: 'CT/MRI System', department: 'Radiology',
      ruleId: '100512', ruleDescription: 'Active exploitation of known critical RCE vulnerability (CVE-2026-11542) on imaging console', ruleLevel: 15,
      cveKnownExploited: true,
      label: 'Active Exploitation', confidence: 0.93, TR_score: 8.5, TS_score: 4.6, CC_score: 8, AE_score: 10.0, TC_score: 4.5,
      shift: 'night', CAS: 7.5, CVSS: 9.1, action: 'Immediate',
    }),
  },
  {
    // Mirror image of the previous scenario: no ransomware/active_exploitation
    // category anywhere on this alert — it's the numeric threshold ALONE
    // (cas_score >= classifier.py's EXTREME_CAS_THRESHOLD of 8.0) that pushes
    // a protected, life_critical-band (CC_score 9) asset to Tier 3.
    title: 'Tier 3 (3 of 5) - await_clinician_approval via CAS >= 8 alone, no extreme category',
    doc: buildDoc({
      srcIp: IP_DIALYSIS, deviceType: 'Dialysis Machine', department: 'Nephrology',
      ruleId: '100601', ruleDescription: 'Large-volume outbound data transfer to unrecognized external host', ruleLevel: 13,
      label: 'Data Exfiltration', confidence: 0.91, TR_score: 8.0, TS_score: 4.2, CC_score: 9, AE_score: 6.0, TC_score: 4.0,
      shift: 'night', CAS: 8.7, CVSS: 8.0, action: 'Immediate',
    }),
  },
  {
    // The fail-safe path: CC_score is deliberately OMITTED below (not just
    // low) — an unrecognized device with no clinical_context.criticality_score
    // at all. lifeCriticalBridgeService.js's clampCriticality() passes that
    // through as genuinely absent (not defaulted), so the engine substitutes
    // score=10/life_critical/fail_safe_applied=true (classifier.py's
    // _resolve_criticality). deviceType/department are ALSO omitted — with no
    // agent.department, toDisplayAlert() falls through to deviceInventory.js's
    // lookup, which won't match this never-before-seen IP and lands on
    // DEFAULT_DEVICE ("Unknown Device" / "General") — the Alerts page shows
    // this exactly like a real never-registered device would look. The
    // fail-safe alone only forces the *protected* band, though — Tier 3 still
    // needs a genuinely extreme threat on top of it, same as every other
    // protected asset, hence the ransomware category here too.
    title: 'Tier 3 (4 of 5) - await_clinician_approval via fail-safe (missing criticality_score) + ransomware',
    doc: buildDoc({
      srcIp: IP_UNREGISTERED,
      ruleId: '100799', ruleDescription: 'Ransomware-style mass file encryption detected on unregistered network host', ruleLevel: 15,
      ruleGroups: ['ransomware'],
      label: 'Ransomware', confidence: 0.9, TR_score: 9.0, TS_score: 4.5, AE_score: 8.5, TC_score: 4.5,
      shift: 'night', CAS: 9.2, CVSS: 9.5, action: 'Immediate',
    }),
  },
  {
    // Category override again, but this time on a clinical_support-band asset
    // (CC_score 6, i.e. 5-7 — NOT life_critical's 8-10) with CAS deliberately
    // under the 8.0 numeric threshold. docs/alert-schema.md is explicit that
    // both protected bands take the identical Tier 2/3 split; this scenario
    // is the demo proof the lower band isn't secretly treated differently.
    title: 'Tier 3 (5 of 5) - await_clinician_approval on a clinical_support-band asset (CC 5-7, not life_critical)',
    doc: buildDoc({
      srcIp: IP_ANESTHESIA, deviceType: 'Anesthesia Machine', department: 'Surgery',
      ruleId: '100888', ruleDescription: 'Active exploitation of known critical vulnerability on anesthesia delivery console', ruleLevel: 15,
      cveKnownExploited: true,
      label: 'Active Exploitation', confidence: 0.92, TR_score: 8.0, TS_score: 4.4, CC_score: 6, AE_score: 9.5, TC_score: 4.0,
      shift: 'evening', CAS: 7.0, CVSS: 9.0, action: 'Immediate',
    }),
  },
];

async function indexDoc(doc) {
  const res = await fetch(`${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}/_doc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: authHeader },
    body: JSON.stringify(doc),
    dispatcher,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`indexer responded ${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

async function main() {
  console.log(`Indexing into ${WAZUH_INDEXER_URL}/${WAZUH_INDEXER_INDEX}`);
  console.log(`Firing ${scenarios.length} demo alerts, ${DELAY_MS / 1000}s apart...`);
  console.log('The backend\'s alert pipeline will pick each one up on its next poll (~5s) and show it on the Alerts page, then push it to the decision engine for the Playbooks tab.\n');

  for (const [i, { title, doc }] of scenarios.entries()) {
    process.stdout.write(`[${i + 1}/${scenarios.length}] ${title} ... `);
    doc['@timestamp'] = new Date().toISOString();
    try {
      const result = await indexDoc(doc);
      console.log(`indexed (_id=${result._id})`);
    } catch (err) {
      console.log(`FAILED: ${err.message}`);
    }
    if (i < scenarios.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
    }
  }

  console.log('\nDone. Watch the Alerts page — each one should appear within ~5s, then move into the Playbooks tab shortly after.');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
