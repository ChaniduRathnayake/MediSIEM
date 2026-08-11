import React from 'react';
import { Check, X } from 'lucide-react';
import type { PasswordPolicy } from '../services/passwordPolicyApi';
import { checkPassword } from '../utils/passwordPolicy';

// Live requirement feedback shown under any "new password" field — used by
// both the admin's create/edit-user form and the self-service change-
// password form so the two never drift in how they present the policy.
const PasswordChecklist: React.FC<{ password: string; policy: PasswordPolicy | null }> = ({ password, policy }) => {
  if (!policy) return null;
  const checks = checkPassword(password, policy);

  return (
    <ul className="space-y-1 mt-1.5">
      {checks.map((c) => (
        <li key={c.label} className={`flex items-center gap-1.5 text-xs ${c.met ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`}>
          {c.met ? <Check className="w-3 h-3 flex-shrink-0" /> : <X className="w-3 h-3 flex-shrink-0" />}
          {c.label}
        </li>
      ))}
    </ul>
  );
};

export default PasswordChecklist;
