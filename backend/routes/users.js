import express from 'express';
import User from '../models/User.js';
import { protect, adminOnly } from '../middleware/auth.js';

const router = express.Router();

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
