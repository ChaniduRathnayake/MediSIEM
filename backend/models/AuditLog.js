import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
const AuditLogSchema = new Schema(
  {
    action: {
      type: String,
      required: true,
      enum: ['create_user', 'update_user', 'delete_user'],
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
