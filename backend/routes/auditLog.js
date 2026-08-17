import express from 'express';
import { protect, allowRoles } from '../middleware/auth.js';
import { getAuditLogs, getAuditLogIntegrity } from '../controllers/auditLogController.js';

const router = express.Router();

// ─── GET /api/audit-log  (admin or auditor — read-only for auditor) ───────────
router.get('/', protect, allowRoles('admin', 'auditor'), getAuditLogs);

// ─── GET /api/audit-log/verify  (admin or auditor) ─────────────────────────────
// Registered before any '/:id'-shaped route would be needed — there isn't
// one here, but keeping the specific path first matches the convention used
// elsewhere (see routes/users.js's '/presence').
router.get('/verify', protect, allowRoles('admin', 'auditor'), getAuditLogIntegrity);

export default router;
