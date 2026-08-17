import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcryptjs';

// ─── Schema ────────────────────────────────────────────────────────────────────
const UserSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [80, 'Name cannot exceed 80 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please provide a valid email address'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
      select: false, // never returned in queries by default
    },
    // 'user' means SOC analyst (kept as-is for backward compatibility with
    // every existing account/check written against it — see auth.js/
    // alerts.js's assignment restriction). 'biomed' (biomedical engineer)
    // and 'auditor' (compliance/audit reviewer) are read-mostly roles added
    // alongside it: neither can be assigned SOC cases (see alerts.js's
    // `analyst.role !== 'user'` check, left untouched), each just gets a
    // different slice of read (and, for biomed, device-inventory write)
    // access — see middleware/auth.js's allowRoles() and its call sites.
    role: {
      type: String,
      enum: ['admin', 'user', 'biomed', 'auditor'],
      default: 'user',
    },
    // Updated (throttled) on every authenticated request — powers the
    // "logged in now" presence counts on the dashboards' Overview pages.
    lastActiveAt: {
      type: Date,
      default: null,
    },
    // ─── Login lockout (routes/auth.js) ────────────────────────────────────
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    // ─── TOTP two-factor auth (routes/auth.js, services/mfaService.js) ────
    // mfaSecret is set as soon as setup starts but mfaEnabled only flips
    // true once the user confirms a real code, so an abandoned setup never
    // gates login. Backup codes are stored hashed (sha256), single-use.
    mfaSecret: { type: String, select: false, default: null },
    mfaEnabled: { type: Boolean, default: false },
    mfaBackupCodes: { type: [String], select: false, default: [] },
    // Admin-forced requirement for non-admin accounts (Users tab → Configure
    // 2FA) — separate from the org-wide admin toggle in SystemSettings.
    // Checked by routes/auth.js's isMfaSetupRequired(). Never applies to
    // admins: an admin's own 2FA can only ever be self-configured.
    mfaRequiredByAdmin: { type: Boolean, default: false },
    // ─── Password reset (routes/auth.js) ───────────────────────────────────
    resetPasswordTokenHash: { type: String, select: false, default: null },
    resetPasswordExpires: { type: Date, select: false, default: null },
  },
  {
    timestamps: true, // adds createdAt + updatedAt automatically
  }
);

// ─── Pre-save hook: hash password ──────────────────────────────────────────────
UserSchema.pre('save', async function () {
  // Only hash if the password field was actually modified
  if (!this.isModified('password')) return;

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  } catch (error) {
    throw error;
  }
});

// ─── Instance method: compare passwords ───────────────────────────────────────
UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// ─── Sanitise output: strip password from toJSON ──────────────────────────────
UserSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.password;
    // select:false only keeps these out of query projections — it does NOT
    // stop them appearing in toJSON() once a code path explicitly assigns to
    // them (e.g. clearing mfaSecret/mfaBackupCodes on reset) and then
    // serializes the document. Scrub them here too, same as password above,
    // so no response can ever include them regardless of how they got set.
    delete ret.mfaSecret;
    delete ret.mfaBackupCodes;
    delete ret.resetPasswordTokenHash;
    delete ret.resetPasswordExpires;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('User', UserSchema);