import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { adminOnly, allowRoles } from '../middleware/auth.js';

function fakeRes() {
  const res = { statusCode: null, body: null };
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (body) => { res.body = body; return res; };
  return res;
}

describe('adminOnly', () => {
  test('calls next() for an admin', () => {
    const req = { user: { role: 'admin' } };
    const res = fakeRes();
    let nextCalled = false;
    adminOnly(req, res, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.equal(res.statusCode, null);
  });

  test('403s every non-admin role', () => {
    for (const role of ['user', 'biomed', 'auditor']) {
      const req = { user: { role } };
      const res = fakeRes();
      let nextCalled = false;
      adminOnly(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, false, `role "${role}" should not pass adminOnly`);
      assert.equal(res.statusCode, 403);
    }
  });
});

describe('allowRoles', () => {
  test('allows exactly the listed roles', () => {
    const middleware = allowRoles('admin', 'user');
    for (const role of ['admin', 'user']) {
      const req = { user: { role } };
      const res = fakeRes();
      let nextCalled = false;
      middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, true, `role "${role}" should be allowed`);
    }
  });

  test('rejects roles not in the list — regression test for the alert-assignment RBAC gap (biomed/auditor could unassign any analyst\'s case)', () => {
    const middleware = allowRoles('admin', 'user');
    for (const role of ['biomed', 'auditor']) {
      const req = { user: { role } };
      const res = fakeRes();
      let nextCalled = false;
      middleware(req, res, () => { nextCalled = true; });
      assert.equal(nextCalled, false, `role "${role}" should be rejected`);
      assert.equal(res.statusCode, 403);
    }
  });

  test('rejects a missing/undefined user rather than throwing', () => {
    const middleware = allowRoles('admin');
    const req = {};
    const res = fakeRes();
    let nextCalled = false;
    assert.doesNotThrow(() => middleware(req, res, () => { nextCalled = true; }));
    assert.equal(nextCalled, false);
    assert.equal(res.statusCode, 403);
  });
});
