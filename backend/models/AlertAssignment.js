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
    // A lean snapshot of the alert's own data at assignment time — not the
    // full EnrichedAlert (skips e.g. the 45-field flow vector), just enough
    // to render a row. Alerts themselves live in alertPipeline.js's
    // in-memory buffer (capped at BUFFER_SIZE), not MongoDB; without this,
    // an assignment record outlives the alert it points to, but the UI has
    // nothing left to join it against once the alert ages out of the
    // buffer — the case just silently vanishes from every list that's
    // supposed to be the durable "who's working what" record. Mixed rather
    // than a strict sub-schema since it needs to track whatever fields
    // alertPipeline.js's toDisplayAlert() happens to produce without a
    // second schema to keep in sync by hand.
    alertSnapshot: { type: Schema.Types.Mixed, default: null },
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
