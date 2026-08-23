import express from 'express';
import { protect, adminOnly, allowRoles } from '../middleware/auth.js';
import { getAllDeviceMeta, setAgentGroups, setAgentOsCategory, setAgentMedicalDevice } from '../controllers/deviceController.js';

const router = express.Router();

// Biomedical engineers manage the medical device inventory itself (see
// medicalDevices.js), so they also get to tag which agent is which device.
const canTagMedicalDevice = allowRoles('admin', 'biomed');

// ─── GET /api/devices/meta  (any authenticated user — read-only insight for SOC analysts) ──
router.get('/meta', protect, getAllDeviceMeta);

// ─── PUT /api/devices/:agentId/groups  (admin only) ────────────────────────────
router.put('/:agentId/groups', protect, adminOnly, setAgentGroups);

// ─── PATCH /api/devices/:agentId/os-category  (admin only) ────────────────────
router.patch('/:agentId/os-category', protect, adminOnly, setAgentOsCategory);

// ─── PUT /api/devices/:agentId/medical-device  (admin or biomed) ──────────────
router.put('/:agentId/medical-device', protect, canTagMedicalDevice, setAgentMedicalDevice);

export default router;
