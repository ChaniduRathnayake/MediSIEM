import crypto from 'crypto';
import AuditLog from '../models/AuditLog.js';

// Exported (rather than kept private, like the rest of this module's
// internals) purely so tests can exercise the chaining logic without a live
// Mongo connection — logAudit/verifyAuditChain themselves aren't unit-tested
// directly, same convention as caapService.enrichAlert() (see
// test/caapService.test.js's comment on why the DB-touching function itself
// isn't imported into tests).
export function computeHash({ action, actor, target, details }, prevHash) {
  const payload = JSON.stringify({
    action,
    actor,
    target: target ?? null,
    details: details ?? '',
    prevHash: prevHash ?? null,
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

// Best-effort audit trail — never let a logging failure break the actual
// request. Each entry chains to the previous one's hash (see
// models/AuditLog.js's prevHash/hash fields), so a DB-level edit or delete
// of a past entry is detectable via verifyAuditChain() below.
export const logAudit = async (entry) => {
  try {
    const last = await AuditLog.findOne().sort({ createdAt: -1, _id: -1 });
    const prevHash = last?.hash ?? null;
    const hash = computeHash(entry, prevHash);
    await AuditLog.create({ ...entry, prevHash, hash });
  } catch (err) {
    console.error('[audit-log]', err);
  }
};

// Walks the chain in creation order and confirms every entry's stored hash
// matches its recomputed value and that prevHash linkage is unbroken.
// Returns { intact: true } or { intact: false, brokenAtIndex } — the index
// (0-based, oldest-first) of the first entry that no longer matches.
export const verifyAuditChain = async () => {
  const entries = await AuditLog.find().sort({ createdAt: 1, _id: 1 });
  let expectedPrevHash = null;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const recomputed = computeHash(e, expectedPrevHash);
    if (e.prevHash !== expectedPrevHash || e.hash !== recomputed) {
      return { intact: false, brokenAtIndex: i, totalEntries: entries.length };
    }
    expectedPrevHash = e.hash;
  }
  return { intact: true, brokenAtIndex: -1, totalEntries: entries.length };
};
