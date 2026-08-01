import AuditLog from '../models/AuditLog.js';

// Best-effort audit trail — never let a logging failure break the actual request.
export const logAudit = async (entry) => {
  try {
    await AuditLog.create(entry);
  } catch (err) {
    console.error('[audit-log]', err);
  }
};
