import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { computeHash } from '../utils/auditLog.js';

const entry = {
  action: 'create_user',
  actor: { id: 'u1', name: 'Admin', email: 'admin@medisiem.com' },
  target: { id: 'u2', name: 'New User', email: 'new@medisiem.com' },
  details: 'Created as SOC Analyst',
};

describe('computeHash', () => {
  test('is deterministic for identical input', () => {
    assert.equal(computeHash(entry, null), computeHash(entry, null));
  });

  test('changes when prevHash changes — this is what makes the chain tamper-evident', () => {
    const h1 = computeHash(entry, null);
    const h2 = computeHash(entry, 'some-other-hash');
    assert.notEqual(h1, h2);
  });

  test('changes when any entry field changes (regression: a silent field tweak must not keep the same hash)', () => {
    const base = computeHash(entry, null);
    assert.notEqual(base, computeHash({ ...entry, details: 'Different details' }, null));
    assert.notEqual(base, computeHash({ ...entry, action: 'update_user' }, null));
    assert.notEqual(base, computeHash({ ...entry, target: { ...entry.target, id: 'someone-else' } }, null));
  });

  test('a 3-entry chain verifies only when every link matches — flip one entry and the chain breaks from that point on', () => {
    const e1 = { action: 'create_user', actor: entry.actor, target: entry.target, details: 'first' };
    const e2 = { action: 'update_user', actor: entry.actor, target: entry.target, details: 'second' };
    const e3 = { action: 'delete_user', actor: entry.actor, target: entry.target, details: 'third' };

    const h1 = computeHash(e1, null);
    const h2 = computeHash(e2, h1);
    const h3 = computeHash(e3, h2);

    // Legitimate chain re-verifies cleanly.
    assert.equal(computeHash(e1, null), h1);
    assert.equal(computeHash(e2, h1), h2);
    assert.equal(computeHash(e3, h2), h3);

    // Tamper with e2's details after the fact, as if someone edited it
    // directly in the database — e2's recomputed hash no longer matches h2,
    // and h3 (which was chained from the original h2) is now unreachable
    // from the tampered entry.
    const tamperedE2 = { ...e2, details: 'tampered' };
    assert.notEqual(computeHash(tamperedE2, h1), h2);
  });
});
