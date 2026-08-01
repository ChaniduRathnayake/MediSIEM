import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import {
  getAllDeviceGroups,
  createDeviceGroup,
  updateDeviceGroup,
  deleteDeviceGroup,
} from '../controllers/deviceGroupController.js';

const router = express.Router();

// ─── GET /api/device-groups  (any authenticated user — read-only insight for SOC analysts) ──
router.get('/', protect, getAllDeviceGroups);

// ─── POST /api/device-groups  (admin only) ─────────────────────────────────────
router.post('/', protect, adminOnly, createDeviceGroup);

// ─── PATCH /api/device-groups/:id  (admin only) ────────────────────────────────
router.patch('/:id', protect, adminOnly, updateDeviceGroup);

// ─── DELETE /api/device-groups/:id  (admin only) ───────────────────────────────
router.delete('/:id', protect, adminOnly, deleteDeviceGroup);

export default router;
