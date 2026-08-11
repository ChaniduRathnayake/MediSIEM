import PasswordPolicy from '../models/PasswordPolicy.js';

// Singleton read — creates the default-valued document on first call so the
// app works out of the box with no separate seeding step.
export async function getPasswordPolicy() {
  let policy = await PasswordPolicy.findOne();
  if (!policy) policy = await PasswordPolicy.create({});
  return policy;
}

const SPECIAL_CHAR_RE = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/;

// Same rule set the frontend mirrors in src/utils/passwordPolicy.ts for
// instant client-side feedback — this is the version that's actually
// enforced, called from userController.js before any password is hashed.
export function validatePassword(password, policy) {
  const errors = [];
  const pw = typeof password === 'string' ? password : '';

  if (pw.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters.`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(pw)) {
    errors.push('Password must include an uppercase letter.');
  }
  if (policy.requireLowercase && !/[a-z]/.test(pw)) {
    errors.push('Password must include a lowercase letter.');
  }
  if (policy.requireNumber && !/[0-9]/.test(pw)) {
    errors.push('Password must include a number.');
  }
  if (policy.requireSpecialChar && !SPECIAL_CHAR_RE.test(pw)) {
    errors.push('Password must include a special character.');
  }

  return { valid: errors.length === 0, errors };
}
