import express from 'express';
import User from '../models/User.js';
import { protect, adminOnly } from '../middleware/auth.js';
import { createUser, updateUser, deleteUser, getPresenceSummary, setUserMfaRequired, adminResetUserMfa } from '../controllers/userController.js';

const router = express.Router();

// ─── POST /api/users  (admin only) ────────────────────────────────────────────
router.post('/', protect, adminOnly, createUser);

// ─── PATCH /api/users/:id  (admin or own profile) ─────────────────────────────
router.patch('/:id', protect, updateUser);

// ─── DELETE /api/users/:id  (admin only) ──────────────────────────────────────
router.delete('/:id', protect, adminOnly, deleteUser);

// ─── PATCH /api/users/:id/mfa-required  (admin only, non-admin targets) ──────
router.patch('/:id/mfa-required', protect, adminOnly, setUserMfaRequired);

// ─── POST /api/users/:id/mfa-reset  (admin only, non-admin targets) ──────────
router.post('/:id/mfa-reset', protect, adminOnly, adminResetUserMfa);

// ─── GET /api/users  (admin only) ────────────────────────────────────────────
router.get('/', protect, adminOnly, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    res.json({ users });
  } catch (err) {
    console.error('[getAllUsers]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── GET /api/users/presence  (any authenticated user — read-only insight) ───
// Must be registered before GET /:id, otherwise Express would match
// "presence" as an :id param.
router.get('/presence', protect, getPresenceSummary);

// ─── GET /api/users/:id ───────────────────────────────────────────────────────
router.get('/:id', protect, async (req, res) => {
  try {
    // A user can only fetch their own profile; admin can fetch any
    if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ user });
  } catch (err) {
    console.error('[getUserById]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

export default router;
