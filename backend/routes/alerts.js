import express from 'express';
import { protect, allowRoles } from '../middleware/auth.js';
import { getBufferedAlerts, getAlertStats } from '../services/alertPipeline.js';
import AlertAssignment from '../models/AlertAssignment.js';
import AlertClosure from '../models/AlertClosure.js';
import User from '../models/User.js';
import { logAudit } from '../utils/auditLog.js';

const router = express.Router();

// A CRITICAL alert that's sat unassigned this long gets flagged `escalated`
// so it can't quietly age out of the buffer unattended — an analyst working
// top-down by CAS should still catch it, but a busy shift or a rules-only
// (non-critical-looking-at-a-glance) triage pass might not.
const ESCALATION_THRESHOLD_MS = 10 * 60 * 1000;

// Cap on how many historical assignments/closures GET / will pull in to
// reconstruct buffer-evicted cases — bounds the query the same way the
// live buffer itself is bounded, rather than an unbounded collection scan
// as this collection grows over the life of a deployment.
const HISTORY_LIMIT = 500;

// Lean fields worth keeping a permanent copy of — deliberately not the
// whole EnrichedAlert (skips e.g. the 45-field flow vector, matchedRules,
// TR/CC/TS/AE/TC breakdown): just enough for a case-list row to render
// correctly forever, not a full forensic record (the Indexer/caap-alerts
// index remains the source of truth for that).
function pickSnapshotFields(alert) {
  if (!alert) return null;
  return {
    timestamp: alert.timestamp,
    agent: alert.agent,
    department: alert.department,
    deviceType: alert.deviceType,
    deviceCriticality: alert.deviceCriticality,
    ruleDescription: alert.ruleDescription,
    label: alert.label,
    CAS: alert.CAS,
    action: alert.action,
    mitre: alert.mitre ?? null,
  };
}

// ─── GET /api/alerts  — CAS-ranked enriched alerts (initial load / fallback for polling clients) ──
router.get('/', protect, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const sortByCas = req.query.sort !== 'time'; // default: rank by CAS like the CAAP dashboard should
    const bufferedAlerts = getBufferedAlerts({ limit, sortByCas });
    const bufferedIds = new Set(bufferedAlerts.map((a) => a.id));

    // Alerts live in the in-memory buffer (sourced from the Indexer), not
    // MongoDB — assignment and closure are the durable state we keep per
    // alert, keyed by the Indexer doc id. Pulled unfiltered (bounded by
    // HISTORY_LIMIT, newest first) rather than `{ alertId: { $in: bufferedIds } }`
    // like before, specifically so a case whose underlying alert has aged
    // out of the BUFFER_SIZE-capped buffer doesn't just vanish from Case
    // Status / My Alerts / Closed Cases the moment that happens — its
    // record is reconstructed below from alertSnapshot instead.
    const [assignments, closures] = await Promise.all([
      AlertAssignment.find().sort({ updatedAt: -1 }).limit(HISTORY_LIMIT),
      AlertClosure.find().sort({ createdAt: -1 }).limit(HISTORY_LIMIT),
    ]);
    const assignedByAlertId = new Map(assignments.map((a) => [a.alertId, a.analyst]));
    const closureByAlertId = new Map(closures.map((c) => [c.alertId, c]));

    // Reconstruct rows for closures/assignments whose alert isn't in the
    // live buffer anymore, from their snapshot — same shape as a real
    // buffered alert (minus fields no snapshot keeps, like `cluster` or
    // `confidence`), enough for every case-list view to render them.
    const reconstructed = new Map();
    for (const c of closures) {
      if (bufferedIds.has(c.alertId) || reconstructed.has(c.alertId) || !c.alertSnapshot) continue;
      reconstructed.set(c.alertId, { id: c.alertId, ...c.alertSnapshot });
    }
    for (const a of assignments) {
      if (bufferedIds.has(a.alertId) || reconstructed.has(a.alertId) || !a.alertSnapshot) continue;
      reconstructed.set(a.alertId, { id: a.alertId, ...a.alertSnapshot });
    }

    const now = Date.now();
    const toRow = (a) => {
      const assignedTo = assignedByAlertId.get(a.id) ?? null;
      const closure = closureByAlertId.get(a.id) ?? null;
      const escalated =
        (a.CAS ?? 0) >= 8 && !assignedTo && !closure && now - new Date(a.timestamp).getTime() >= ESCALATION_THRESHOLD_MS;
      return { ...a, assignedTo, closure, escalated };
    };

    const withAssignments = [...bufferedAlerts.map(toRow), ...[...reconstructed.values()].map(toRow)];

    res.json({ alerts: withAssignments, count: withAssignments.length, ...getAlertStats() });
  } catch (err) {
    console.error('[getAlerts]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PATCH /api/alerts/:id/assign  — assign/unassign an alert to an analyst ───
// Case management stays admin + SOC analyst only — biomed/auditor are
// documented as unable to touch SOC case state (see User.js's role
// comment), and unlike /close (which is self-gated by assignment
// ownership), this route has no other check that would stop them.
router.patch('/:id/assign', protect, allowRoles('admin', 'user'), async (req, res) => {
  try {
    const { analystId } = req.body;
    const alertId = req.params.id;

    if (!analystId) {
      const existing = await AlertAssignment.findOne({ alertId });
      await AlertAssignment.deleteOne({ alertId });
      if (existing) {
        logAudit({
          action: 'unassign_alert',
          actor: { id: req.user.id, name: req.user.name, email: req.user.email },
          target: { id: alertId, name: existing.analyst?.name },
          details: `Unassigned from ${existing.analyst?.name ?? 'analyst'}`,
        });
      }
      return res.json({ assignedTo: null });
    }

    const analyst = await User.findById(analystId);
    if (!analyst) {
      return res.status(404).json({ error: 'Analyst not found.' });
    }
    if (analyst.role !== 'user') {
      return res.status(400).json({ error: 'Alerts can only be assigned to SOC analysts, not admins.' });
    }

    // Snapshot the alert's own data at assignment time so this record
    // outlives it in the live buffer — see pickSnapshotFields()' comment.
    const alertData = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);

    const assignment = await AlertAssignment.findOneAndUpdate(
      { alertId },
      {
        alertId,
        analyst: { id: analyst._id.toString(), name: analyst.name, email: analyst.email },
        assignedBy: { id: req.user.id, name: req.user.name },
        ...(alertData ? { alertSnapshot: pickSnapshotFields(alertData) } : {}),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    logAudit({
      action: 'assign_alert',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId, name: analyst.name, email: analyst.email },
      details: `Assigned to ${analyst.name}`,
    });

    res.json({ assignedTo: assignment.analyst });
  } catch (err) {
    console.error('[assignAlert]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

const VALID_VERDICTS = ['true_positive', 'false_positive', 'benign', 'uncertain'];

// ─── PATCH /api/alerts/:id/close  — close a case with a reason + evidence ─────
// Restricted to the analyst the alert is currently assigned to, or an admin —
// an analyst can't close another analyst's case, and can't close an
// unassigned one (it isn't theirs to inspect yet).
router.patch('/:id/close', protect, async (req, res) => {
  try {
    const alertId = req.params.id;
    const reason = (req.body.reason || '').trim();
    const evidence = (req.body.evidence || '').trim();
    const verdict = req.body.verdict || null;

    if (!reason || !evidence) {
      return res.status(400).json({ error: 'Both a reason and supporting evidence are required to close a case.' });
    }
    if (verdict && !VALID_VERDICTS.includes(verdict)) {
      return res.status(400).json({ error: `Verdict must be one of: ${VALID_VERDICTS.join(', ')}.` });
    }

    if (req.user.role !== 'admin') {
      const assignment = await AlertAssignment.findOne({ alertId });
      if (!assignment || assignment.analyst.id !== req.user.id) {
        return res.status(403).json({ error: 'You can only close cases assigned to you.' });
      }
    }

    // Snapshot the alert's own data at closure time — see
    // pickSnapshotFields()'s comment. Falls back to an existing assignment's
    // snapshot if the alert has already aged out of the buffer by the time
    // it's closed (rare, but possible for a slow-moving case).
    const alertData = getBufferedAlerts({ limit: 500 }).find((a) => a.id === alertId);
    const snapshot = pickSnapshotFields(alertData) ?? (await AlertAssignment.findOne({ alertId }))?.alertSnapshot ?? null;

    const closure = await AlertClosure.findOneAndUpdate(
      { alertId },
      {
        alertId,
        reason,
        evidence,
        verdict,
        closedBy: { id: req.user.id, name: req.user.name, email: req.user.email },
        ...(snapshot ? { alertSnapshot: snapshot } : {}),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
    );

    logAudit({
      action: 'close_alert',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: alertId },
      details: `Closed${verdict ? ` as ${verdict.replace('_', ' ')}` : ''} — ${reason}`,
    });

    res.json({ closure });
  } catch (err) {
    console.error('[closeAlert]', err);
    res.status(400).json({ error: err.message || 'Failed to close case.' });
  }
});

export default router;
