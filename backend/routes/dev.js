import express from 'express';
import { clearBufferedAlerts, getAlertStats } from '../services/alertPipeline.js';
import { deleteAllAlerts } from '../services/wazuhIndexerService.js';
import AlertLog from '../models/AlertLog.js';
import AlertAssignment from '../models/AlertAssignment.js';
import AlertClosure from '../models/AlertClosure.js';
import AlertSnooze from '../models/AlertSnooze.js';
import AlertNote from '../models/AlertNote.js';
import SoarAction from '../models/SoarAction.js';

const {
  LIFE_CRITICAL_ENGINE_URL = 'http://localhost:8000',
  LIFE_CRITICAL_SHUFFLE_SIM_URL = 'http://localhost:8002',
} = process.env;

const router = express.Router();

// Everything under here is a demo/dev reset utility (see frontend's /devbomb page) —
// unauthenticated by design so it's a one-click reset while iterating on a demo, but
// that's only acceptable because it's hard-disabled outside dev. Never remove this gate.
router.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Dev utilities are disabled in production.' });
  }
  next();
});

// POST /api/dev/wipe-alerts — empties the live alert queue and every durable alert
// record (log, assignments, closures, snoozes, notes) so the dashboard comes back empty.
router.post('/wipe-alerts', async (req, res) => {
  try {
    clearBufferedAlerts();

    const [indexer, log, assignments, closures, snoozes, notes] = await Promise.all([
      deleteAllAlerts(),
      AlertLog.deleteMany({}),
      AlertAssignment.deleteMany({}),
      AlertClosure.deleteMany({}),
      AlertSnooze.deleteMany({}),
      AlertNote.deleteMany({}),
    ]);

    const io = req.app.get('io');
    io?.emit('alerts:wiped');
    io?.emit('alerts:stats', getAlertStats());

    console.warn('[dev/wipe-alerts] Alert backlog wiped.');

    res.json({
      message: 'Alert backlog wiped.',
      deleted: {
        indexerDocs: indexer.deleted,
        alertLog: log.deletedCount,
        assignments: assignments.deletedCount,
        closures: closures.deletedCount,
        snoozes: snoozes.deletedCount,
        notes: notes.deletedCount,
      },
    });
  } catch (err) {
    console.error('[dev/wipe-alerts]', err);
    res.status(500).json({ error: 'Failed to wipe alerts.' });
  }
});

// Best-effort POST to a life-critical-orchestration service's own /dev/reset —
// each service is a separate Python process with its own in-memory state
// (engine/src/main.py's recent-alerts ring, shuffle_sim's action-log ring),
// so Mongo alone can't reset them. Never lets an unreachable/optional
// service (the Shuffle sim is off by default) fail the whole wipe.
async function resetDevService(baseUrl, label) {
  try {
    const res = await fetch(`${baseUrl}/dev/reset`, { method: 'POST' });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      return { ok: false, error: `${label} responded ${res.status}: ${body.slice(0, 200)}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `${label} unreachable: ${err.message}` };
  }
}

// POST /api/dev/wipe-playbooks — clears the durable SOAR mirror plus the
// life-critical-orchestration engine's audit log/recent-alerts cache and the
// Shuffle sim's action log, so the Playbooks panel comes back empty.
router.post('/wipe-playbooks', async (req, res) => {
  try {
    const [soarActions, engine, shuffleSim] = await Promise.all([
      SoarAction.deleteMany({}),
      resetDevService(LIFE_CRITICAL_ENGINE_URL, 'Life-critical engine'),
      resetDevService(LIFE_CRITICAL_SHUFFLE_SIM_URL, 'Shuffle sim'),
    ]);

    console.warn('[dev/wipe-playbooks] Playbooks backlog wiped.', { engine, shuffleSim });

    res.json({
      message: 'Playbooks backlog wiped.',
      deleted: { soarActions: soarActions.deletedCount },
      engine,
      shuffleSim,
    });
  } catch (err) {
    console.error('[dev/wipe-playbooks]', err);
    res.status(500).json({ error: 'Failed to wipe playbooks.' });
  }
});

export default router;
