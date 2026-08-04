// backend/routes/alerts.js
import express from 'express';
import { protect } from '../middleware/auth.js';
import { getBufferedAlerts } from '../services/alertPipeline.js';

const router = express.Router();

// ─── GET /api/alerts  — CAS-ranked enriched alerts (initial load / fallback for polling clients) ──
router.get('/', protect, (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const sortByCas = req.query.sort !== 'time'; // default: rank by CAS like the CAAP dashboard should
    const alerts = getBufferedAlerts({ limit, sortByCas });
    res.json({ alerts, count: alerts.length });
  } catch (err) {
    console.error('[getAlerts]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
