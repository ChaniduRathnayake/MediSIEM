import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Singleton — there is only ever one policy document (see
// utils/passwordPolicy.js's getPasswordPolicy, which creates it with these
// defaults on first read). minLength has a hard floor of 8 to match the
// User model's own schema-level minlength — the policy can only ever be
// equal-or-stricter than that baseline, never looser.
const PasswordPolicySchema = new Schema(
  {
    minLength: { type: Number, default: 8, min: 8, max: 128 },
    requireUppercase: { type: Boolean, default: false },
    requireLowercase: { type: Boolean, default: false },
    requireNumber: { type: Boolean, default: false },
    requireSpecialChar: { type: Boolean, default: false },
    updatedBy: {
      id: String,
      name: String,
    },
  },
  {
    timestamps: true,
  }
);

PasswordPolicySchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('PasswordPolicy', PasswordPolicySchema);
