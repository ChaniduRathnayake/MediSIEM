import SystemSettings from '../models/SystemSettings.js';

// Admins can be required (org-wide, via Settings → Integrations) to have
// two-factor enabled — computed on every login/`protect` check rather than
// stored on the user, so flipping the toggle applies retroactively to
// admins who haven't enrolled yet without needing to touch their record.
// Shared between routes/auth.js (login response, /me) and
// middleware/auth.js (protect, to actually enforce it) — a single source of
// truth so the two can't drift apart.
export async function isMfaSetupRequired(user) {
  if (user.mfaEnabled) return false;
  if (user.role === 'admin') {
    const settings = await SystemSettings.findOne();
    return !!settings?.mfaRequiredForAdmin;
  }
  return !!user.mfaRequiredByAdmin;
}
