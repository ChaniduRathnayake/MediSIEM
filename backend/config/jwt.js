// Centralized JWT secret — signing and verifying both import from here so
// they can't drift, and a missing/weak/placeholder secret fails loudly at
// startup instead of silently 401-ing every request later.
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
