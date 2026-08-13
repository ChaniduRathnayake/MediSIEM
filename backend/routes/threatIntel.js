// backend/routes/threatIntel.js
import express from 'express';
import { protect } from '../middleware/auth.js';
import { getKevStatus } from '../services/cveIntelService.js';

const router = express.Router();

// GET /api/threat-intel/kev-status — is the CISA KEV catalog loaded, how
// many entries, when it last refreshed. Lets the UI show honestly whether
// AE (Active Exploitation) scoring is running off real threat intel right
// now or has fallen back to the MITRE-technique heuristic.
router.get('/kev-status', protect, (req, res) => {
  res.json(getKevStatus());
});

export default router;
