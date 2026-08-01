import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import { getAllDeviceMeta, setAgentGroups, setAgentOsCategory } from '../controllers/deviceController.js';

const router = express.Router();

// ─── GET /api/devices/meta  (any authenticated user — read-only insight for SOC analysts) ──
router.get('/meta', protect, getAllDeviceMeta);

// ─── PUT /api/devices/:agentId/groups  (admin only) ────────────────────────────
router.put('/:agentId/groups', protect, adminOnly, setAgentGroups);

// ─── PATCH /api/devices/:agentId/os-category  (admin only) ────────────────────
router.patch('/:agentId/os-category', protect, adminOnly, setAgentOsCategory);

export default router;
