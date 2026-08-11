import express from 'express';
import { protect } from '../middleware/auth.js';
import { getBufferedAlerts, getAlertStats } from '../services/alertPipeline.js';
import AlertAssignment from '../models/AlertAssignment.js';
import AlertClosure from '../models/AlertClosure.js';
import User from '../models/User.js';

const router = express.Router();

// ─── GET /api/alerts  — CAS-ranked enriched alerts (initial load / fallback for polling clients) ──
router.get('/', protect, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const sortByCas = req.query.sort !== 'time'; // default: rank by CAS like the CAAP dashboard should
    const alerts = getBufferedAlerts({ limit, sortByCas });

    // Alerts live in the in-memory buffer (sourced from the Indexer), not
    // MongoDB — assignment and closure are the durable state we keep per
    // alert, keyed by the Indexer doc id, so join both in here.
    const alertIds = alerts.map((a) => a.id);
    const [assignments, closures] = await Promise.all([
      AlertAssignment.find({ alertId: { $in: alertIds } }),
      AlertClosure.find({ alertId: { $in: alertIds } }),
    ]);
    const assignedByAlertId = new Map(assignments.map((a) => [a.alertId, a.analyst]));
    const closureByAlertId = new Map(closures.map((c) => [c.alertId, c]));
    const withAssignments = alerts.map((a) => ({
      ...a,
      assignedTo: assignedByAlertId.get(a.id) ?? null,
      closure: closureByAlertId.get(a.id) ?? null,
    }));

    res.json({ alerts: withAssignments, count: withAssignments.length, ...getAlertStats() });
  } catch (err) {
    console.error('[getAlerts]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PATCH /api/alerts/:id/assign  — assign/unassign an alert to an analyst ───
router.patch('/:id/assign', protect, async (req, res) => {
  try {
    const { analystId } = req.body;
    const alertId = req.params.id;

    if (!analystId) {
      await AlertAssignment.deleteOne({ alertId });
      return res.json({ assignedTo: null });
    }

    const analyst = await User.findById(analystId);
    if (!analyst) {
      return res.status(404).json({ error: 'Analyst not found.' });
    }
    if (analyst.role !== 'user') {
      return res.status(400).json({ error: 'Alerts can only be assigned to SOC analysts, not admins.' });
    }

    const assignment = await AlertAssignment.findOneAndUpdate(
      { alertId },
      {
        alertId,
        analyst: { id: analyst._id.toString(), name: analyst.name, email: analyst.email },
        assignedBy: { id: req.user.id, name: req.user.name },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.json({ assignedTo: assignment.analyst });
  } catch (err) {
    console.error('[assignAlert]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PATCH /api/alerts/:id/close  — close a case with a reason + evidence ─────
// Restricted to the analyst the alert is currently assigned to, or an admin —
// an analyst can't close another analyst's case, and can't close an
// unassigned one (it isn't theirs to inspect yet).
router.patch('/:id/close', protect, async (req, res) => {
  try {
    const alertId = req.params.id;
    const reason = (req.body.reason || '').trim();
    const evidence = (req.body.evidence || '').trim();

    if (!reason || !evidence) {
      return res.status(400).json({ error: 'Both a reason and supporting evidence are required to close a case.' });
    }

    if (req.user.role !== 'admin') {
      const assignment = await AlertAssignment.findOne({ alertId });
      if (!assignment || assignment.analyst.id !== req.user.id) {
        return res.status(403).json({ error: 'You can only close cases assigned to you.' });
      }
    }

    const closure = await AlertClosure.findOneAndUpdate(
      { alertId },
      {
        alertId,
        reason,
        evidence,
        closedBy: { id: req.user.id, name: req.user.name, email: req.user.email },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true }
    );

    res.json({ closure });
  } catch (err) {
    console.error('[closeAlert]', err);
    res.status(400).json({ error: err.message || 'Failed to close case.' });
  }
});

export default router;
