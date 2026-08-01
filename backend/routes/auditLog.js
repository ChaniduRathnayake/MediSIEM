import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import { getAuditLogs } from '../controllers/auditLogController.js';

const router = express.Router();

// ─── GET /api/audit-log  (admin only) ──────────────────────────────────────────
router.get('/', protect, adminOnly, getAuditLogs);

export default router;
