import User from '../models/User.js';
import { logAudit } from '../utils/auditLog.js';
import { getPasswordPolicy, validatePassword } from '../utils/passwordPolicy.js';

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

    if (req.body.role !== undefined && !['admin', 'user'].includes(req.body.role)) {
      return res.status(400).json({ error: 'Role must be "admin" or "user".' });
    }

    const allowedFields = ['name', 'email', 'password'];
    if (req.user.role === 'admin') allowedFields.push('role');

    // Password field is select:false — explicitly include it so comparePassword works below
    const user = await User.findById(id).select('+password');
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Users changing their own password must confirm it with their current password.
    // (Admins resetting someone else's password are exempt — they don't know it.)
    if (req.body.password && req.user.id === id) {
      const { currentPassword } = req.body;
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required.' });
      }
      if (!(await user.comparePassword(currentPassword))) {
        return res.status(401).json({ error: 'Current password is incorrect.' });
      }
    }

    if (req.body.password) {
      const policy = await getPasswordPolicy();
      const { valid, errors } = validatePassword(req.body.password, policy);
      if (!valid) return res.status(400).json({ error: errors[0], errors });
    }

    const before = { name: user.name, email: user.email, role: user.role };

    for (const field of allowedFields) {
      if (req.body[field] !== undefined && req.body[field] !== '') {
        user[field] = field === 'email' ? req.body[field].toLowerCase().trim() : req.body[field];
      }
    }

    // .save() (not findByIdAndUpdate) so the pre-save hook re-hashes a changed password
    await user.save();

    if (req.user.role === 'admin') {
      const changes = [];
      if (user.name !== before.name) changes.push(`name "${before.name}" → "${user.name}"`);
      if (user.email !== before.email) changes.push(`email "${before.email}" → "${user.email}"`);
      if (user.role !== before.role) changes.push(`role "${before.role}" → "${user.role}"`);
      if (req.body.password) changes.push('password changed');

      if (changes.length > 0) {
        await logAudit({
          action: 'update_user',
          actor: { id: req.user.id, name: req.user.name, email: req.user.email },
          target: { id: user._id.toString(), name: user.name, email: user.email },
          details: changes.join(', '),
        });
      }
    }

    return res.status(200).json({ user });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Email already registered.' });
    }
    console.error('[updateUser]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── POST /api/users  (admin only) ────────────────────────────────────────────
export const createUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required.' });
    }

    if (role && !['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Role must be "admin" or "user".' });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    const policy = await getPasswordPolicy();
    const { valid, errors } = validatePassword(password, policy);
    if (!valid) return res.status(400).json({ error: errors[0], errors });

    const newUser = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password,
      role: role || 'user',
    });

    await logAudit({
      action: 'create_user',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: newUser._id.toString(), name: newUser.name, email: newUser.email },
      details: `Created as ${newUser.role === 'admin' ? 'Admin' : 'SOC Analyst'}`,
    });

    return res.status(201).json({ user: newUser });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    console.error('[createUser]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// A user counts as "online" if the auth middleware has stamped lastActiveAt
// within this window — wide enough to tolerate the frontend's 30s poll
// interval plus a missed beat, tight enough to read as "right now".
const ONLINE_THRESHOLD_MS = 2 * 60 * 1000;

// ─── GET /api/users/presence  (any authenticated user — read-only insight) ────
// Everyone gets the counts (that's what the Overview stat cards need). Only
// admins get the actual roster of who's online — SOC analysts see numbers,
// not their colleagues' identities.
export const getPresenceSummary = async (req, res) => {
  try {
    const cutoff = new Date(Date.now() - ONLINE_THRESHOLD_MS);
    const users = await User.find().select('name email role lastActiveAt');

    const summary = {
      admins: { online: 0, total: 0 },
      analysts: { online: 0, total: 0 },
    };
    const roster = { admins: [], analysts: [] };

    for (const u of users) {
      const isAdmin = u.role === 'admin';
      const bucket = isAdmin ? summary.admins : summary.analysts;
      bucket.total += 1;
      const online = !!(u.lastActiveAt && u.lastActiveAt >= cutoff);
      if (online) bucket.online += 1;

      if (req.user.role === 'admin') {
        (isAdmin ? roster.admins : roster.analysts).push({
          id: u._id.toString(),
          name: u.name,
          email: u.email,
          online,
          lastActiveAt: u.lastActiveAt,
        });
      }
    }

    const response = { ...summary, thresholdMs: ONLINE_THRESHOLD_MS };
    if (req.user.role === 'admin') {
      // Online users first, then most-recently-active among the rest.
      const byRecency = (a, b) => {
        if (a.online !== b.online) return a.online ? -1 : 1;
        return new Date(b.lastActiveAt ?? 0).getTime() - new Date(a.lastActiveAt ?? 0).getTime();
      };
      response.roster = {
        admins: roster.admins.sort(byRecency),
        analysts: roster.analysts.sort(byRecency),
      };
    }

    return res.status(200).json(response);
  } catch (err) {
    console.error('[getPresenceSummary]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── DELETE /api/users/:id  (admin only) ──────────────────────────────────────
export const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (req.user.id === id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    await logAudit({
      action: 'delete_user',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: user._id.toString(), name: user.name, email: user.email },
      details: `Deleted ${user.role === 'admin' ? 'Admin' : 'SOC Analyst'} account`,
    });

    return res.status(200).json({ message: 'User deleted successfully.' });
  } catch (err) {
    console.error('[deleteUser]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};