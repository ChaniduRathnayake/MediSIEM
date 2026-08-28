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

// Tier 3 alerts still awaiting a clinician response — joins /alerts/recent
// (tier === 3) against /clinician-decisions (already-resolved decision_ids)
// server-side so the frontend gets a ready-to-render list.
router.get('/pending-approvals', protect, async (req, res) => {
  try {
    const [recent, resolved] = await Promise.all([
      engineFetch('/alerts/recent?limit=200'),
      engineFetch('/clinician-decisions'),
    ]);
    const pending = recent.filter(
      (item) => item.decision?.tier === 3 && !resolved[item.decision?.decision_id]
    );
    res.json({ pending });
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
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
// /recent-decisions this survives an engine restart and supports filtering,
// since it's the Node-side mirror (backend/models/SoarAction.js) rather than
// a proxy onto the engine's own state.
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

// The engine's durable, hash-chained audit log (GET /audit) — unlike
// /alerts/recent (an in-memory ring buffer that resets on engine restart),
// this survives restarts and is what a real "Audit Timeline" view needs.
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
