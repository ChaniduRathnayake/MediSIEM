// backend/routes/detectionPerformance.js
import express from 'express';
import { protect } from '../middleware/auth.js';
import { getDetectionPerformance } from '../services/detectionMetrics.js';

const router = express.Router();

// GET /api/detection-performance — live ARA/MTCAI/FPR analogs (see
// detectionMetrics.js) computed against the current alert buffer.
router.get('/', protect, async (req, res) => {
  try {
    res.json(await getDetectionPerformance());
  } catch (err) {
    console.error('[detection-performance]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
