import express from 'express';
import { protect, allowRoles } from '../middleware/auth.js';
import { getAuditLogs } from '../controllers/auditLogController.js';

const router = express.Router();

// ─── GET /api/audit-log  (admin or auditor — read-only for auditor) ───────────
router.get('/', protect, allowRoles('admin', 'auditor'), getAuditLogs);

export default router;
