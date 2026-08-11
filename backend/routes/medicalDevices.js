import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import {
  getAllMedicalDevices,
  createMedicalDevice,
  updateMedicalDevice,
  deleteMedicalDevice,
  setMedicalDeviceGroups,
} from '../controllers/medicalDeviceController.js';

const router = express.Router();

// ─── GET /api/medical-devices  (any authenticated user — read-only insight for SOC analysts) ──
router.get('/', protect, getAllMedicalDevices);

// ─── POST /api/medical-devices  (admin only — onboard a new device) ───────────
router.post('/', protect, adminOnly, createMedicalDevice);

// ─── PATCH /api/medical-devices/:id  (admin only) ──────────────────────────────
router.patch('/:id', protect, adminOnly, updateMedicalDevice);

// ─── PUT /api/medical-devices/:id/groups  (admin only — tag an onboarded device) ─
router.put('/:id/groups', protect, adminOnly, setMedicalDeviceGroups);

// ─── DELETE /api/medical-devices/:id  (admin only) ─────────────────────────────
router.delete('/:id', protect, adminOnly, deleteMedicalDevice);

export default router;
