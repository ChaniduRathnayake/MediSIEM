import express from 'express';
import { protect, adminOnly, allowRoles } from '../middleware/auth.js';
import {
  getAllMedicalDevices,
  createMedicalDevice,
  updateMedicalDevice,
  deleteMedicalDevice,
  setMedicalDeviceGroups,
} from '../controllers/medicalDeviceController.js';

const router = express.Router();

// Biomedical engineers own the real-world equivalent of this inventory
// (onboarding/retiring physical devices), so they get write access here —
// admin retains it too. Every other write in this file stays admin-only.
const canManageDevices = allowRoles('admin', 'biomed');

// ─── GET /api/medical-devices  (any authenticated user — read-only insight for SOC analysts) ──
router.get('/', protect, getAllMedicalDevices);

// ─── POST /api/medical-devices  (admin or biomed — onboard a new device) ──────
router.post('/', protect, canManageDevices, createMedicalDevice);

// ─── PATCH /api/medical-devices/:id  (admin or biomed) ─────────────────────────
router.patch('/:id', protect, canManageDevices, updateMedicalDevice);

// ─── PUT /api/medical-devices/:id/groups  (admin or biomed — tag an onboarded device) ─
router.put('/:id/groups', protect, canManageDevices, setMedicalDeviceGroups);

// ─── DELETE /api/medical-devices/:id  (admin only — decommissioning stays a stricter action) ─
router.delete('/:id', protect, adminOnly, deleteMedicalDevice);

export default router;
