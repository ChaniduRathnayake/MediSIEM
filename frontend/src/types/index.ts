// 'user' = SOC analyst (original/default role, unchanged meaning). 'biomed'
// = biomedical engineer (device inventory access). 'auditor' = compliance/
// audit-log read access. See backend/models/User.js for the same enum.
export type UserRole = 'admin' | 'user' | 'biomed' | 'auditor';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  mfaEnabled?: boolean;
  // True when Settings → Integrations' "Require two-factor authentication
  // for admin accounts" is on and this admin hasn't enrolled yet — the
  // dashboard shows a persistent (non-blocking) prompt until they do.
  mfaSetupRequired?: boolean;
  // Set by an admin from the Users tab (non-admin targets only) — forces
  // mfaSetupRequired true until this user enrolls.
  mfaRequiredByAdmin?: boolean;
  createdAt?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface AuditLogEntry {
  id: string;
  action:
    | 'create_user' | 'update_user' | 'delete_user'
    | 'create_device_group' | 'update_device_group' | 'delete_device_group'
    | 'update_device_groups' | 'update_device_os_category'
    | 'assign_alert' | 'unassign_alert' | 'close_alert'
    | 'onboard_medical_device' | 'update_medical_device'
    | 'update_medical_device_groups' | 'delete_medical_device'
    | 'update_settings' | 'enable_mfa' | 'disable_mfa' | 'reset_password'
    | 'add_alert_note' | 'snooze_alert' | 'unsnooze_alert'
    | 'require_mfa' | 'unrequire_mfa' | 'admin_reset_mfa';
  actor: { id: string; name?: string; email?: string };
  target: { id?: string; name?: string; email?: string };
  details: string;
  createdAt: string;
}

export interface ApiResponse<T = unknown> {
  message?: string;
  error?: string;
  data?: T;
}
