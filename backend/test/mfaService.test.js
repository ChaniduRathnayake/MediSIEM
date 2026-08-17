import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generate as otpGenerate } from 'otplib';
import {
  generateSecret,
  keyUri,
  verifyToken,
  generateBackupCodes,
  hashBackupCode,
} from '../services/mfaService.js';

describe('generateSecret / keyUri', () => {
  test('generates a base32 secret and a well-formed otpauth:// URI', () => {
    const secret = generateSecret();
    assert.ok(secret.length > 0);
    const uri = keyUri('admin@medisiem.com', secret);
    assert.ok(uri.startsWith('otpauth://totp/'));
    assert.ok(uri.includes('MediSIEM'));
  });
});

describe('verifyToken', () => {
  test('accepts a code actually generated from the same secret', async () => {
    const secret = generateSecret();
    const code = await otpGenerate({ secret });
    assert.equal(await verifyToken(code, secret), true);
  });

  test('rejects a code generated from a different secret', async () => {
    const secret = generateSecret();
    const otherSecret = generateSecret();
    const code = await otpGenerate({ secret: otherSecret });
    assert.equal(await verifyToken(code, secret), false);
  });

  test('rejects garbage input without throwing', async () => {
    assert.equal(await verifyToken('not-a-code', generateSecret()), false);
    assert.equal(await verifyToken('', generateSecret()), false);
    assert.equal(await verifyToken('123456', ''), false);
  });
});

describe('backup codes', () => {
  test('generateBackupCodes returns the requested count of unique codes', () => {
    const codes = generateBackupCodes(8);
    assert.equal(codes.length, 8);
    assert.equal(new Set(codes).size, 8);
  });

  test('hashBackupCode is deterministic and case/whitespace-insensitive (so a pasted code with stray spacing still matches)', () => {
    const code = generateBackupCodes(1)[0];
    assert.equal(hashBackupCode(code), hashBackupCode(code));
    assert.equal(hashBackupCode(code), hashBackupCode(`  ${code.toUpperCase()}  `));
  });

  test('different codes hash differently', () => {
    const [a, b] = generateBackupCodes(2);
    assert.notEqual(hashBackupCode(a), hashBackupCode(b));
  });
});
