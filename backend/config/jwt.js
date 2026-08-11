// backend/config/jwt.js
// Centralized JWT secret — both signing (routes/auth.js) and verifying
// (middleware/auth.js) import from here so they can never drift, and so a
// missing/weak/placeholder secret fails loudly at startup instead of
// silently falling back to a guessable default (or `undefined`, which
// would 401 every request at runtime with no clue why).
const WEAK_PLACEHOLDERS = new Set([
  'your_super_secret_jwt_key_here_change_in_production',
  'medisiem_secret',
  'secret',
  'changeme',
  'change_me',
  'password',
]);

const secret = process.env.JWT_SECRET;

if (!secret || WEAK_PLACEHOLDERS.has(secret) || secret.length < 32) {
  throw new Error(
    'JWT_SECRET is missing, uses a known placeholder value, or is shorter than 32 characters. ' +
      'Set a long, random JWT_SECRET in backend/.env before starting the server. Generate one with:\n' +
      '  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"'
  );
}

export default secret;
