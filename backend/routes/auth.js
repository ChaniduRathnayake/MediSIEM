import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import User from '../models/User.js';
import { protect } from '../middleware/auth.js';
import JWT_SECRET from '../config/jwt.js';
import { getPasswordPolicy, validatePassword } from '../utils/passwordPolicy.js';
import { logAudit } from '../utils/auditLog.js';
import { sendEmail } from '../services/notificationService.js';
import SystemSettings from '../models/SystemSettings.js';
import {
  generateSecret,
  keyUri,
  generateQrCodeDataUrl,
  verifyToken as verifyTotp,
  generateBackupCodes,
  hashBackupCode,
} from '../services/mfaService.js';

const router = express.Router();
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Fallback lockout policy when no SystemSettings doc exists yet (first run,
// before an admin has visited Settings → Integrations) — same defaults as
// the SystemSettings schema itself.
const DEFAULT_MAX_FAILED_ATTEMPTS = 5;
const DEFAULT_LOCK_DURATION_MINUTES = 15;

// ─── Reset-token tuning ─────────────────────────────────────────────────────
const RESET_TOKEN_EXPIRES_MS = 30 * 60 * 1000;

const signSessionToken = (userId) => jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

// Admin-tunable via Settings → Integrations (SystemSettings.lockout) instead
// of a hardcoded constant — read fresh each call so a policy change takes
// effect on the very next login attempt, no restart needed.
async function getLockoutPolicy() {
  const settings = await SystemSettings.findOne();
  return {
    maxAttempts: settings?.lockout?.maxAttempts ?? DEFAULT_MAX_FAILED_ATTEMPTS,
    lockDurationMs: (settings?.lockout?.lockDurationMinutes ?? DEFAULT_LOCK_DURATION_MINUTES) * 60 * 1000,
  };
}

// Admins can be required (org-wide, via the same Settings toggle) to have
// two-factor enabled — computed on every login/`/me` call rather than
// stored on the user, so flipping the toggle applies retroactively to
// admins who haven't enrolled yet without needing to touch their record.
async function isMfaSetupRequired(user) {
  if (user.mfaEnabled) return false;
  if (user.role === 'admin') {
    const settings = await SystemSettings.findOne();
    return !!settings?.mfaRequiredForAdmin;
  }
  return !!user.mfaRequiredByAdmin;
}

const safeUser = async (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  mfaEnabled: user.mfaEnabled,
  mfaSetupRequired: await isMfaSetupRequired(user),
  createdAt: user.createdAt,
});

// Brute-force guard — keyed by IP, independent of whether the attempted
// email exists, so it can't be used to enumerate accounts either.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in a few minutes.' },
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset requests. Please try again in a few minutes.' },
});

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      return res.status(423).json({ error: 'Account temporarily locked due to repeated failed login attempts. Try again later.' });
    }

    const validPassword = await user.comparePassword(password);
    if (!validPassword) {
      const { maxAttempts, lockDurationMs } = await getLockoutPolicy();
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= maxAttempts) {
        user.lockUntil = new Date(Date.now() + lockDurationMs);
        user.failedLoginAttempts = 0;
      }
      await user.save();
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.failedLoginAttempts || user.lockUntil) {
      user.failedLoginAttempts = 0;
      user.lockUntil = null;
      await user.save();
    }

    if (user.mfaEnabled) {
      // Short-lived, single-purpose token — proves "password already
      // verified for this user" without granting a real session until the
      // second factor also checks out.
      const mfaToken = jwt.sign({ id: user._id, purpose: 'mfa' }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ mfaRequired: true, mfaToken });
    }

    const token = signSessionToken(user._id);
    res.json({ message: 'Login successful.', token, user: await safeUser(user) });
  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// ─── POST /api/auth/mfa/verify — second factor to complete a login ───────────
router.post('/mfa/verify', loginLimiter, async (req, res) => {
  try {
    const { mfaToken, code } = req.body;
    if (typeof mfaToken !== 'string' || typeof code !== 'string' || !mfaToken || !code) {
      return res.status(400).json({ error: 'MFA token and code are required.' });
    }

    let decoded;
    try {
      decoded = jwt.verify(mfaToken, JWT_SECRET, { algorithms: ['HS256'] });
    } catch {
      return res.status(401).json({ error: 'MFA session expired. Please log in again.' });
    }
    if (decoded.purpose !== 'mfa') {
      return res.status(401).json({ error: 'Invalid MFA session.' });
    }

    const user = await User.findById(decoded.id).select('+mfaSecret +mfaBackupCodes');
    if (!user || !user.mfaEnabled) {
      return res.status(401).json({ error: 'Invalid MFA session.' });
    }

    let ok = await verifyTotp(code, user.mfaSecret);
    if (!ok) {
      // Fall back to a one-time backup code (used for a lost/unavailable device).
      const hashed = hashBackupCode(code);
      const idx = (user.mfaBackupCodes || []).indexOf(hashed);
      if (idx !== -1) {
        ok = true;
        user.mfaBackupCodes.splice(idx, 1);
        await user.save();
      }
    }
    if (!ok) {
      return res.status(401).json({ error: 'Invalid authentication code.' });
    }

    const token = signSessionToken(user._id);
    res.json({ message: 'Login successful.', token, user: await safeUser(user) });
  } catch (err) {
    console.error('[mfaVerify]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/mfa/setup — begin enrollment for the logged-in user ──────
router.post('/mfa/setup', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.mfaEnabled) return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });

    const secret = generateSecret();
    user.mfaSecret = secret;
    await user.save();

    const otpauth = keyUri(user.email, secret);
    const qrDataUrl = await generateQrCodeDataUrl(otpauth);
    res.json({ secret, qrDataUrl });
  } catch (err) {
    console.error('[mfaSetup]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/mfa/confirm — finish enrollment with a real code ─────────
router.post('/mfa/confirm', protect, async (req, res) => {
  try {
    const { code } = req.body;
    if (typeof code !== 'string' || !code) return res.status(400).json({ error: 'Code is required.' });

    const user = await User.findById(req.user.id).select('+mfaSecret');
    if (!user.mfaSecret) return res.status(400).json({ error: 'Start two-factor setup first.' });
    if (!(await verifyTotp(code, user.mfaSecret))) {
      return res.status(401).json({ error: 'Invalid code — check your authenticator app and try again.' });
    }

    const backupCodes = generateBackupCodes();
    user.mfaBackupCodes = backupCodes.map(hashBackupCode);
    user.mfaEnabled = true;
    await user.save();

    await logAudit({
      action: 'enable_mfa',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: user._id.toString(), name: user.name, email: user.email },
    });

    // Backup codes are only ever visible to the user right now — the server
    // only ever stores their hash from this point on.
    res.json({ message: 'Two-factor authentication enabled.', backupCodes });
  } catch (err) {
    console.error('[mfaConfirm]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/mfa/disable — password-confirmed opt-out ─────────────────
router.post('/mfa/disable', protect, async (req, res) => {
  try {
    const { password } = req.body;
    if (typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'Password is required to disable two-factor authentication.' });
    }

    const user = await User.findById(req.user.id).select('+password');
    if (!(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    user.mfaEnabled = false;
    user.mfaSecret = null;
    user.mfaBackupCodes = [];
    await user.save();

    await logAudit({
      action: 'disable_mfa',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: user._id.toString(), name: user.name, email: user.email },
    });

    res.json({ message: 'Two-factor authentication disabled.' });
  } catch (err) {
    console.error('[mfaDisable]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/forgot-password ───────────────────────────────────────────
// Always returns the same generic message regardless of whether the email
// matches an account, so this endpoint can't be used to enumerate users.
router.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const genericResponse = { message: 'If an account exists for that email, a password reset link has been sent.' };
  try {
    const { email } = req.body;
    if (typeof email !== 'string' || !email) {
      return res.status(400).json({ error: 'Email is required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.json(genericResponse);

    const rawToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.resetPasswordExpires = new Date(Date.now() + RESET_TOKEN_EXPIRES_MS);
    await user.save();

    const resetUrl = `${FRONTEND_URL}/reset-password/${rawToken}`;
    try {
      await sendEmail({
        to: user.email,
        subject: 'MediSIEM password reset',
        text: `Reset your MediSIEM password: ${resetUrl}\n\nThis link expires in 30 minutes. If you didn't request this, you can ignore this email.`,
        html: `<p>Reset your MediSIEM password:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>This link expires in 30 minutes. If you didn't request this, you can ignore this email.</p>`,
      });
    } catch (mailErr) {
      // SMTP not configured yet, or the send failed — don't leak that detail
      // to the client (still returns the generic response), just log it so
      // an admin can diagnose via server logs / Settings → Integrations.
      console.warn('[forgotPassword] Could not send reset email:', mailErr.message);
    }

    res.json(genericResponse);
  } catch (err) {
    console.error('[forgotPassword]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/reset-password/:token ─────────────────────────────────────
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { password } = req.body;
    if (typeof password !== 'string' || !password) {
      return res.status(400).json({ error: 'A new password is required.' });
    }

    const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    }).select('+resetPasswordTokenHash +resetPasswordExpires');

    if (!user) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired.' });
    }

    const policy = await getPasswordPolicy();
    const { valid, errors } = validatePassword(password, policy);
    if (!valid) return res.status(400).json({ error: errors[0], errors });

    user.password = password;
    user.resetPasswordTokenHash = null;
    user.resetPasswordExpires = null;
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    await logAudit({
      action: 'reset_password',
      actor: { id: user._id.toString(), name: user.name, email: user.email },
      target: { id: user._id.toString(), name: user.name, email: user.email },
      details: 'Password reset via emailed link',
    });

    res.json({ message: 'Password updated. You can now log in.' });
  } catch (err) {
    console.error('[resetPassword]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
router.get('/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ user: await safeUser(user) });
  } catch (err) {
    console.error('[getMe]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', protect, (req, res) => {
  // With JWT, logout is handled client-side (delete the token).
  res.json({ message: 'Logged out successfully.' });
});

export default router;
