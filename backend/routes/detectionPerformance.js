// backend/routes/detectionPerformance.js
import express from 'express';
import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
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

// ai_server/ is a sibling directory of backend/ at the repo root — this is
// a read-only filesystem peek at whatever ai_server/check_drift.py last
// wrote there, not a service call (check_drift.py is a script someone runs
// manually/on a schedule, not a running process with an API of its own).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DRIFT_REPORTS_DIR = path.join(__dirname, '..', '..', 'ai_server', 'reports');

// GET /api/detection-performance/drift-report — latest saved
// reports/drift_report_<date>.json from ai_server/check_drift.py, if any.
router.get('/drift-report', protect, async (req, res) => {
  try {
    const entries = await fs.readdir(DRIFT_REPORTS_DIR).catch(() => []);
    const files = entries.filter((f) => f.startsWith('drift_report_') && f.endsWith('.json'));
    if (files.length === 0) {
      return res.status(404).json({ error: 'No drift report found yet — run ai_server/check_drift.py to generate one.' });
    }
    // drift_report_YYYY-MM-DD.json sorts chronologically as plain strings.
    files.sort();
    const latest = files[files.length - 1];
    const content = await fs.readFile(path.join(DRIFT_REPORTS_DIR, latest), 'utf-8');
    res.json({ filename: latest, report: JSON.parse(content) });
  } catch (err) {
    console.error('[getDriftReport]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
