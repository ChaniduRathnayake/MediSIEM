import express from 'express';
import { protect, adminOnly } from '../middleware/auth.js';
import PasswordPolicy from '../models/PasswordPolicy.js';
import { getPasswordPolicy } from '../utils/passwordPolicy.js';

const router = express.Router();

// ─── GET /api/password-policy  (public) ────────────────────────────────────────
// Needed by every password-entry form — admin create/edit user, self
// password-change, and the pre-auth forgot/reset-password flow — to show
// live requirement feedback. No `protect`: the policy itself (min length,
// which character classes are required) isn't sensitive, and the
// reset-password page has no session token yet by definition.
router.get('/', async (req, res) => {
  try {
    const policy = await getPasswordPolicy();
    res.json({ policy });
  } catch (err) {
    console.error('[getPasswordPolicy]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── PATCH /api/password-policy  (admin only) ──────────────────────────────────
router.patch('/', protect, adminOnly, async (req, res) => {
  try {
    const { minLength, requireUppercase, requireLowercase, requireNumber, requireSpecialChar } = req.body;
    const update = {};

    if (minLength !== undefined) {
      const n = Number(minLength);
      if (!Number.isFinite(n) || n < 8 || n > 128) {
        return res.status(400).json({ error: 'Minimum length must be between 8 and 128.' });
      }
      update.minLength = n;
    }
    if (requireUppercase !== undefined) update.requireUppercase = !!requireUppercase;
    if (requireLowercase !== undefined) update.requireLowercase = !!requireLowercase;
    if (requireNumber !== undefined) update.requireNumber = !!requireNumber;
    if (requireSpecialChar !== undefined) update.requireSpecialChar = !!requireSpecialChar;
    update.updatedBy = { id: req.user.id, name: req.user.name };

    let policy = await PasswordPolicy.findOne();
    if (!policy) policy = new PasswordPolicy();
    Object.assign(policy, update);
    await policy.save();

    res.json({ policy });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    console.error('[updatePasswordPolicy]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
