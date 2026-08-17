// Thin wrapper around otplib (TOTP) + qrcode for two-factor auth. Pure/
// stateless — routes/auth.js owns persistence of the User model's MFA fields.
import { generateSecret as otpGenerateSecret, generateURI, verify as otpVerify } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';

// ±30s (one time-step either side) tolerates minor clock drift between the
// server and the user's authenticator app without meaningfully weakening
// the code — otplib v13 defaults to 0 tolerance (exact match only).
const EPOCH_TOLERANCE_SECONDS = 30;

export function generateSecret() {
  return otpGenerateSecret();
}

export function keyUri(email, secret) {
  return generateURI({ issuer: 'MediSIEM', label: email, secret });
}

export async function generateQrCodeDataUrl(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl);
}

export async function verifyToken(token, secret) {
  if (!token || !secret) return false;
  try {
    const result = await otpVerify({ secret, token, epochTolerance: EPOCH_TOLERANCE_SECONDS });
    return !!result?.valid;
  } catch {
    return false;
  }
}

// One-time backup codes for when the authenticator device is unavailable.
// Returned to the user exactly once (at enrollment); only the hash is stored.
export function generateBackupCodes(count = 8) {
  return Array.from({ length: count }, () => crypto.randomBytes(5).toString('hex'));
}

export function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code.trim().toLowerCase()).digest('hex');
}
