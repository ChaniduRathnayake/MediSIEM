import User from '../models/User.js';

// ─── GET /api/users  (admin only) ─────────────────────────────────────────────
export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    return res.status(200).json({ users });
  } catch (err) {
    console.error('[getAllUsers]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── GET /api/users/:id  (admin or own profile) ───────────────────────────────
export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    // Non-admins can only fetch their own profile
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    return res.status(200).json({ user });
  } catch (err) {
    console.error('[getUserById]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PATCH /api/users/:id  (admin or own profile) ─────────────────────────────
export const updateUser = async (req, res) => {
  try {
    const { id } = req.params;

    // Non-admins can only edit their own profile, and cannot change role
    if (req.user.role !== 'admin' && req.user.id !== id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const allowedFields = ['name', 'email'];
    if (req.user.role === 'admin') allowedFields.push('role');

    const updates = {};
    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }

    const user = await User.findByIdAndUpdate(id, updates, {
      new: true,          // return updated doc
      runValidators: true,
    });

    if (!user) return res.status(404).json({ error: 'User not found.' });

    return res.status(200).json({ user });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    console.error('[updateUser]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── DELETE /api/users/:id  (admin only) ──────────────────────────────────────
export const deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    return res.status(200).json({ message: 'User deleted successfully.' });
  } catch (err) {
    console.error('[deleteUser]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};