import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import JWT_SECRET from '../config/jwt.js';
import { isMfaSetupRequired } from '../utils/mfaPolicy.js';

// Presence is derived from lastActiveAt, so it only needs to be written this
// often — not on every single request — to keep the "online" signal fresh
// without hammering the DB on every API call.
const ACTIVITY_THROTTLE_MS = 30 * 1000;

// Requests a user with a pending, policy-required MFA enrollment may still
// make — just enough to complete setup or get out. Everything else is
// blocked below; without this, "require MFA" (SystemSettings.mfaRequiredForAdmin
// / User.mfaRequiredByAdmin) was computed into a `mfaSetupRequired` flag the
// frontend showed as a nag banner, but nothing ever stopped the underlying
// API calls — a targeted user could just dismiss it and keep using a
// password-only session indefinitely.
const MFA_SETUP_EXEMPT_PATHS = new Set(['/api/auth/mfa/setup', '/api/auth/mfa/confirm', '/api/auth/me', '/api/auth/logout']);

// ─── protect: verify JWT and attach user to req ────────────────────────────────
export const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Not authorised. Token missing.' });
    }

    const token = authHeader.split(' ')[1];
    // Pin the accepted algorithm explicitly — without this, jsonwebtoken
    // accepts whatever alg the token header itself claims (including, in
    // some verify configurations, 'none' or an asymmetric alg the server
    // never signed with), which is a classic JWT algorithm-confusion attack.
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists.' });
    }

    req.user = { id: user._id.toString(), role: user.role, email: user.email, name: user.name };

    if (!MFA_SETUP_EXEMPT_PATHS.has(req.originalUrl.split('?')[0]) && (await isMfaSetupRequired(user))) {
      return res.status(403).json({
        error: 'Two-factor authentication setup is required before continuing.',
        mfaSetupRequired: true,
      });
    }

    // Fire-and-forget so this never adds latency to the actual request.
    if (!user.lastActiveAt || Date.now() - user.lastActiveAt.getTime() > ACTIVITY_THROTTLE_MS) {
      User.updateOne({ _id: user._id }, { $set: { lastActiveAt: new Date() } }).catch((err) =>
        console.error('[presence update]', err)
      );
    }

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid token.' });
  }
};

// ─── adminOnly: restrict route to admin role ───────────────────────────────────
export const adminOnly = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admins only.' });
  }
  next();
};

// ─── allowRoles: restrict route to any of the given roles ─────────────────────
// Generalization of adminOnly for the biomed/auditor roles — e.g.
// allowRoles('admin', 'biomed') on the medical device write routes, or
// allowRoles('admin', 'auditor') on the audit log. Always list 'admin'
// explicitly where it should still have access; this never implicitly
// grants it.
export const allowRoles = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) {
    return res.status(403).json({ error: `Access denied. Requires one of: ${roles.join(', ')}.` });
  }
  next();
};