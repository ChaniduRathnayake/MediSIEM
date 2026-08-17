import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
const AuditLogSchema = new Schema(
  {
    action: {
      type: String,
      required: true,
      enum: [
        'create_user', 'update_user', 'delete_user',
        'create_device_group', 'update_device_group', 'delete_device_group',
        'update_device_groups', 'update_device_os_category',
        'assign_alert', 'unassign_alert', 'close_alert',
        'onboard_medical_device', 'update_medical_device',
        'update_medical_device_groups', 'delete_medical_device',
        'update_settings', 'enable_mfa', 'disable_mfa', 'reset_password',
        'export_training_feedback',
        'add_alert_note', 'snooze_alert', 'unsnooze_alert',
        'require_mfa', 'unrequire_mfa', 'admin_reset_mfa',
      ],
    },
    actor: {
      id: { type: String, required: true },
      name: String,
      email: String,
    },
    target: {
      id: String,
      name: String,
      email: String,
    },
    details: {
      type: String,
      default: '',
    },
    // ─── Tamper-evidence chain (utils/auditLog.js) ─────────────────────────
    // Each entry's hash covers its own fields plus the previous entry's
    // hash, so editing or deleting a past entry breaks the chain from that
    // point forward — detectable via utils/auditLog.js's verifyAuditChain().
    // Best-effort, not a cryptographic ledger: concurrent writes can race on
    // reading the "previous" entry (acceptable for a low-frequency admin
    // action log; a strict ordering guarantee would need a DB transaction).
    prevHash: { type: String, default: null },
    hash: { type: String, default: null },
  },
  {
    timestamps: true, // adds createdAt + updatedAt automatically
  }
);

AuditLogSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AuditLog', AuditLogSchema);
