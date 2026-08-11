import type { PasswordPolicy } from '../services/passwordPolicyApi';

export interface PolicyCheck {
  label: string;
  met: boolean;
}

const SPECIAL_CHAR_RE = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/;

// Mirrors backend/utils/passwordPolicy.js's validatePassword — this copy is
// for instant UI feedback only; the backend call is still the source of
// truth and re-validates on submit.
export function checkPassword(password: string, policy: PasswordPolicy): PolicyCheck[] {
  const checks: PolicyCheck[] = [
    { label: `At least ${policy.minLength} characters`, met: password.length >= policy.minLength },
  ];
  if (policy.requireUppercase) checks.push({ label: 'An uppercase letter (A-Z)', met: /[A-Z]/.test(password) });
  if (policy.requireLowercase) checks.push({ label: 'A lowercase letter (a-z)', met: /[a-z]/.test(password) });
  if (policy.requireNumber) checks.push({ label: 'A number (0-9)', met: /[0-9]/.test(password) });
  if (policy.requireSpecialChar) checks.push({ label: 'A special character (!@#$…)', met: SPECIAL_CHAR_RE.test(password) });
  return checks;
}

export function passwordMeetsPolicy(password: string, policy: PasswordPolicy): boolean {
  return checkPassword(password, policy).every((c) => c.met);
}
