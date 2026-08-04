import express from 'express';
import { protect } from '../middleware/auth.js';
import { getBufferedAlerts } from '../services/alertPipeline.js';
import AlertAssignment from '../models/AlertAssignment.js';
import User from '../models/User.js';

const router = express.Router();

// ─── GET /api/alerts  — CAS-ranked enriched alerts (initial load / fallback for polling clients) ──
router.get('/', protect, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const sortByCas = req.query.sort !== 'time'; // default: rank by CAS like the CAAP dashboard should
    const alerts = getBufferedAlerts({ limit, sortByCas });

    // Alerts live in the in-memory buffer (sourced from the Indexer), not
    // MongoDB — assignment is the one bit of durable state we keep per
    // alert, keyed by the Indexer doc id, so join it in here.
    const assignments = await AlertAssignment.find({ alertId: { $in: alerts.map((a) => a.id) } });
    const byAlertId = new Map(assignments.map((a) => [a.alertId, a.analyst]));
    const withAssignments = alerts.map((a) => ({ ...a, assignedTo: byAlertId.get(a.id) ?? null }));

    res.json({ alerts: withAssignments, count: withAssignments.length });
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

export default router;
