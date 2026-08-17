import AuditLog from '../models/AuditLog.js';
import { verifyAuditChain } from '../utils/auditLog.js';

// ─── GET /api/audit-log  (admin only) ──────────────────────────────────────────
export const getAuditLogs = async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(200);
    return res.status(200).json({ logs });
  } catch (err) {
    console.error('[getAuditLogs]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── GET /api/audit-log/verify  (admin or auditor) ─────────────────────────────
// Walks the full hash chain (see utils/auditLog.js) and reports whether any
// entry has been altered or removed outside of the normal append-only path.
export const getAuditLogIntegrity = async (req, res) => {
  try {
    const result = await verifyAuditChain();
    return res.status(200).json(result);
  } catch (err) {
    console.error('[getAuditLogIntegrity]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};
