import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Alerts themselves live in the Wazuh Indexer / caap-alerts (via alertPipeline.js's
// in-memory buffer) — not MongoDB — so this collection is just the durable
// "who's working this" pointer, keyed by the alert's Indexer document id.
const AlertAssignmentSchema = new Schema(
  {
    alertId: {
      type: String,
      required: true,
      unique: true,
    },
    analyst: {
      id: { type: String, required: true },
      name: String,
      email: String,
    },
    assignedBy: {
      id: String,
      name: String,
    },
  },
  {
    timestamps: true,
  }
);

AlertAssignmentSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AlertAssignment', AlertAssignmentSchema);
