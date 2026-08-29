// Thin authenticated proxy in front of the life-critical-orchestration decision
// engine (FastAPI, life-critical-orchestration/engine). The engine itself has no
// auth (see the Technical Integration Guide's §5.3) — routing every call through
// here means MediSIEM's real RBAC gates the one endpoint that can trigger a real
// isolate_host escalation (/clinician-decision), instead of exposing the engine
// directly to the browser.
import express from 'express';
import { protect, allowRoles } from '../middleware/auth.js';
import { getLifeCriticalBridgeStats } from '../services/lifeCriticalBridgeService.js';
import SoarAction from '../models/SoarAction.js';
import AlertLog from '../models/AlertLog.js';

const router = express.Router();

const {
  LIFE_CRITICAL_ENGINE_URL = 'http://localhost:8000',
  LIFE_CRITICAL_SHUFFLE_SIM_URL = 'http://localhost:8002',
} = process.env;

async function fetchJson(base, path, options) {
  const res = await fetch(`${base}${path}`, options);
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(body?.detail || `${base} responded ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return body;
}

const engineFetch = (path, options) => fetchJson(LIFE_CRITICAL_ENGINE_URL, path, options);
const shuffleFetch = (path, options) => fetchJson(LIFE_CRITICAL_SHUFFLE_SIM_URL, path, options);

// Engine reachability + this bridge's own push stats — lets the Playbooks
// panel show "engine offline" instead of a silent empty feed.
router.get('/status', protect, async (req, res) => {
  const bridge = getLifeCriticalBridgeStats();
  try {
    const health = await engineFetch('/health');
    res.json({ engineReachable: true, health, bridge });
  } catch (err) {
    res.json({ engineReachable: false, error: err.message, bridge });
  }
});

// Classify one alert on demand — mirrors the standalone SOC console's stub
// picker: clicking a bundled sample alert that hasn't been seen this session
// POSTs it here for a real classification, exactly like POST /decide on the
// engine itself. Not used by MediSIEM's own live pipeline (that goes through
// lifeCriticalBridgeService.js) — this is for the ported console's manual
// alert-feed interaction only.
router.post('/decide', protect, async (req, res) => {
  try {
    const decision = await engineFetch('/decide', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    res.json(decision);
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// Recent classified alerts + their decisions, newest first — the engine's own
// ring buffer (see engine/src/main.py's /alerts/recent), not MediSIEM's
// AlertLog, since the engine's copy carries the full rationale text and
// decision_id the panel needs and AlertLog only mirrors three summary fields.
router.get('/recent-decisions', protect, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const items = await engineFetch(`/alerts/recent?limit=${limit}`);
    res.json({ items });
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// alertSnapshot (backend/models/SoarAction.js) only started being written
// once buildEnrichedAlert's payload was added to the SoarAction write in
// lifeCriticalBridgeService.js — every SoarAction doc written before that
// has alertSnapshot: null forever (it was never captured, so there's nothing
// to backfill). Hard-filtering those out of /decisions-history and
// /pending-approvals made the entire pre-existing Playbooks history vanish
// from the UI the moment that field shipped, which is exactly backwards: the
// decisions themselves are still real and still in Mongo. Falls back to
// MediSIEM's own AlertLog (keyed by alertId) for CAS/department/label/rule
// text instead — AlertLog has carried those since alertPipeline.js's dedup
// path, independently of alertSnapshot, so most history is recoverable.
async function buildAlertLogMap(docs) {
  const missingIds = [...new Set(docs.filter((d) => !d.alertSnapshot).map((d) => d.alertId))];
  if (!missingIds.length) return {};
  const logs = await AlertLog.find({ alertId: { $in: missingIds } });
  return Object.fromEntries(logs.map((l) => [l.alertId, l]));
}

// Shared by /decisions-history and /pending-approvals below — reconstructs a
// {alert, decision} pair (the shape the frontend already renders via the
// engine's own /alerts/recent) from a durable SoarAction doc instead of the
// engine's in-memory ring buffer. `raw` is the fallback for the decision half
// on the rare doc where it's missing; every doc has always carried the
// individual fields it's built from here. When alertSnapshot itself is
// missing (see buildAlertLogMap above), a best-effort alert stub is built
// from AlertLog instead of dropping the entry entirely — some display fields
// (hostname, ip, cas_breakdown, indicators) genuinely don't exist in AlertLog
// and stay blank, but the decision is never hidden just because that one
// payload wasn't captured yet.
function soarActionToItem(d, alertLogByAlertId = {}) {
  const log = alertLogByAlertId[d.alertId];
  return {
    alert: d.alertSnapshot || {
      alert_id: d.alertId,
      timestamp: log?.timestamp || d.decidedAt,
      source: { rule_description: log?.ruleDescription ?? undefined },
      threat: {
        category: log?.label ?? undefined,
        cas_score: typeof log?.CAS === 'number' ? log.CAS : undefined,
      },
      asset: { asset_id: d.assetId ?? undefined, department: log?.department ?? undefined },
      clinical_context: { criticality_score: d.effectiveCriticalityScore ?? undefined },
    },
    decision: d.raw || {
      decision_id: d.decisionId,
      decided_at: d.decidedAt,
      alert_id: d.alertId,
      asset_id: d.assetId,
      tier: d.tier,
      action: d.action,
      rationale: d.rationale,
      matched_rule: d.matchedRule,
      fail_safe_applied: d.failSafeApplied,
      effective_criticality: d.effectiveCriticality,
      effective_criticality_score: d.effectiveCriticalityScore,
      extreme_threat: d.extremeThreat,
      proposed_action_if_approved: d.proposedActionIfApproved,
      block_dest: d.blockDest,
      block_ports: d.blockPorts,
    },
  };
}

// Durable equivalent of /recent-decisions — reads MediSIEM's own SoarAction
// mirror instead of the engine's in-memory ring buffer, so the Playbooks feed
// (1) survives an engine restart (the ring buffer doesn't) and (2) never
// misses a decision the engine made on a repeat occurrence of an alert
// signature that alertPipeline.js's own dedup folded into an existing buffer
// entry — that path never gave the engine's ring buffer a place to be joined
// against, which is why some CRITICAL alerts visible on the Alerts page were
// never appearing here even though the engine had genuinely decided on them.
// Every SoarAction doc is included, not just ones with an alertSnapshot —
// see buildAlertLogMap/soarActionToItem above for how older docs degrade.
router.get('/decisions-history', protect, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const docs = await SoarAction.find({}).sort({ decidedAt: -1 }).limit(limit);
    const alertLogByAlertId = await buildAlertLogMap(docs);
    res.json({ items: docs.map((d) => soarActionToItem(d, alertLogByAlertId)) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Tier 3 alerts still awaiting a clinician response. Was: join /alerts/recent
// (tier === 3) against /clinician-decisions server-side — same ephemeral-ring-
// buffer weakness as /recent-decisions above, except here it meant a real
// pending containment approval could silently vanish from the tray across an
// engine restart with no record a clinician ever needed to act on it. Reads
// SoarAction's own `status` field instead, which is durable and updated in
// place by /clinician-decision below regardless of engine uptime.
router.get('/pending-approvals', protect, async (req, res) => {
  try {
    const docs = await SoarAction.find({ status: 'pending' }).sort({ decidedAt: -1 });
    const alertLogByAlertId = await buildAlertLogMap(docs);
    res.json({ pending: docs.map((d) => soarActionToItem(d, alertLogByAlertId)) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Phase B of the engine's two-phase Tier 3 flow — approve escalates to
// isolate_host, deny keeps the asset in Monitored Mode (FR-06). Restricted to
// roles with a real stake in a containment decision; auditor is read-only by
// design so it's deliberately excluded here. 'clinician' is the dedicated
// single-purpose role for this exact call — see models/User.js.
//
// Calls the Shuffle sim first, not the engine directly: the sim is what
// actually performs enforcement (a real `docker network disconnect` for the
// emulated device, see playbooks/shuffle_sim/enforcement.py) AND calls back
// into the engine's own audit log afterward — so one call updates both. If
// the sim is unreachable, fall back to hitting the engine directly so the
// decision still gets recorded (just without live enforcement); the response
// shapes are compatible (the engine's is a strict subset of the sim's).
router.post('/clinician-decision', protect, allowRoles('admin', 'user', 'biomed', 'clinician'), async (req, res) => {
  const { decisionId, assetId, approved } = req.body || {};
  if (!decisionId || !assetId || typeof approved !== 'boolean') {
    return res.status(400).json({ error: 'decisionId (string), assetId (string) and approved (boolean) are required.' });
  }
  try {
    let result;
    try {
      result = await shuffleFetch('/clinician-decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision_id: decisionId, asset_id: assetId, approved, clinician_id: req.user.email }),
      });
    } catch (simErr) {
      console.warn(`[lifeCriticalOrchestration] Shuffle sim unreachable for clinician-decision, falling back to the engine directly (no live enforcement): ${simErr.message}`);
      result = await engineFetch('/clinician-decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision_id: decisionId, approved, clinician_id: req.user.email }),
      });
    }

    // Record who resolved this Tier 3 decision and how — the call above
    // already succeeded, so a failure here only loses the durable Mongo
    // mirror, never the real approve/deny action itself.
    SoarAction.findOneAndUpdate(
      { decisionId },
      {
        $set: {
          status: approved ? 'approved' : 'denied',
          clinicianDecision: {
            approved,
            by: { id: req.user.id, name: req.user.name, email: req.user.email },
            decidedAt: new Date(),
            enforcement: result.enforcement ?? null,
          },
        },
      },
      { upsert: true }
    ).catch((err) => console.warn('[lifeCriticalOrchestration] SoarAction clinician-decision write failed:', err.message));

    res.json(result);
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// Durable SOAR history straight from Mongo — unlike /audit and
// /recent-decisions this supports filtering (assetId/status) since it's the
// Node-side mirror (backend/models/SoarAction.js) rather than a proxy onto
// the engine's own state. /recent-decisions now also survives an engine
// restart (the engine persists its ring buffer to disk), but only this one
// supports querying by asset/status.
router.get('/soar-history', protect, async (req, res) => {
  try {
    const { assetId, status, limit } = req.query;
    const query = {};
    if (assetId) query.assetId = assetId;
    if (status) query.status = status;

    const items = await SoarAction.find(query)
      .sort({ createdAt: -1 })
      .limit(Math.min(Number(limit) || 100, 500));
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Hash-chain integrity check — surfaced next to the panel's audit feed so
// tampering (or a broken chain from manual data-file edits) is visible
// without needing to curl the engine directly.
router.get('/audit-verify', protect, async (req, res) => {
  try {
    const result = await engineFetch('/audit/verify');
    res.json(result);
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// Most-recent clinician followup per decision_id — lets the detail view show
// "Approved by X" / "Denied by X" for an already-resolved Tier 3 instead of
// re-offering Approve/Deny buttons for a decision that's already settled.
router.get('/clinician-decisions', protect, async (req, res) => {
  try {
    const byDecisionId = await engineFetch('/clinician-decisions');
    res.json({ byDecisionId });
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// The engine's durable, hash-chained audit log (GET /audit) — this is the
// tamper-evident record and what a real "Audit Timeline" view needs.
// /alerts/recent is now also persisted to disk, but it's a plain JSONL
// display cache (no hash chain, and only holds the last
// RECENT_ALERTS_BUFFER_SIZE entries), not this endpoint's full history.
// Includes both original decisions and clinician-response followups.
router.get('/audit', protect, async (req, res) => {
  try {
    const entries = await engineFetch('/audit');
    res.json({ entries });
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

// Playbook steps the Shuffle sim actually ran for one asset — what "Monitored
// Mode" / "Tier 3 dispatch" / enforcement concretely did. Gracefully reports
// unreachable rather than erroring, since the sim is optional (an engine
// without SHUFFLE_WEBHOOK_URL set works fine, just with no playbook layer).
router.get('/shuffle-actions', protect, async (req, res) => {
  const assetId = req.query.assetId;
  if (!assetId) return res.status(400).json({ error: 'assetId query param is required.' });
  try {
    const actions = await shuffleFetch(`/actions/by-asset?asset_id=${encodeURIComponent(assetId)}&limit=50`);
    res.json({ reachable: true, actions });
  } catch (err) {
    res.json({ reachable: false, actions: [], error: err.message });
  }
});

export default router;
