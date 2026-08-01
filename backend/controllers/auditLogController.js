import AuditLog from '../models/AuditLog.js';

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
