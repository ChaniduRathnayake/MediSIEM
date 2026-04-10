import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// ─── Helper: sign JWT ──────────────────────────────────────────────────────────
const signToken = (userId) =>
  jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });

// ─── Helper: build safe user response ─────────────────────────────────────────
const userResponse = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  createdAt: user.createdAt,
});

// ─── POST /api/auth/register ───────────────────────────────────────────────────
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // Duplicate check
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    // Create user (password hashed in pre-save hook)
    const user = await User.create({ name: name.trim(), email, password });

    const token = signToken(user._id);

    return res.status(201).json({
      token,
      user: userResponse(user),
    });
  } catch (err) {
    // Mongoose validation errors
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    console.error('[register]', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};

// ─── POST /api/auth/login ──────────────────────────────────────────────────────
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Explicitly select password (it's excluded by default via select:false in schema)
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = signToken(user._id);

    return res.status(200).json({
      token,
      user: userResponse(user),
    });
  } catch (err) {
    console.error('[login]', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};

// ─── GET /api/auth/me ──────────────────────────────────────────────────────────
export const getMe = async (req, res) => {
  try {
    // req.user is set by the auth middleware after JWT verification
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    return res.status(200).json({ user: userResponse(user) });
  } catch (err) {
    console.error('[getMe]', err);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};