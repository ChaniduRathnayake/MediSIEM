import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import { getAllDeviceMeta, setAgentGroups, setAgentOsCategory } from '../controllers/deviceController.js';

const router = express.Router();

// ─── GET /api/devices/meta  (admin only) ───────────────────────────────────────
router.get('/meta', protect, adminOnly, getAllDeviceMeta);

// ─── PUT /api/devices/:agentId/groups  (admin only) ────────────────────────────
router.put('/:agentId/groups', protect, adminOnly, setAgentGroups);

// ─── PATCH /api/devices/:agentId/os-category  (admin only) ────────────────────
router.patch('/:agentId/os-category', protect, adminOnly, setAgentOsCategory);

export default router;
