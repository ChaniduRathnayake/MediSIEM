import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Alerts themselves live in the Wazuh Indexer / caap-alerts (via alertPipeline.js's
// in-memory buffer) — not MongoDB — so, like AlertAssignment, this collection is
// just the durable "how was this resolved" record, keyed by the alert's Indexer
// document id. Kept as its own collection (not a field bolted onto
// AlertAssignment) since an alert can be reassigned after closure without losing
// the closure record, and the two have different authors (assignedBy vs closedBy).
const AlertClosureSchema = new Schema(
  {
    alertId: {
      type: String,
      required: true,
      unique: true,
    },
    reason: {
      type: String,
      required: [true, 'A reason is required to close a case.'],
      trim: true,
      maxlength: 500,
    },
    evidence: {
      type: String,
      required: [true, 'Supporting evidence is required to close a case.'],
      trim: true,
      maxlength: 5000,
    },
    closedBy: {
      id: { type: String, required: true },
      name: String,
      email: String,
    },
    // Analyst's own judgment of whether the underlying detection was
    // correct — the one piece of real ground truth this system ever
    // captures about its own accuracy. Everything else CAS-related
    // (hospital_scenarios.py's offline eval, detectionMetrics.js's live
    // ARA/MTCAI/FPR) either uses synthetic labels or device-criticality as
    // a proxy for "should this have ranked high"; this is an actual human
    // saying "this was/wasn't a real threat" on a real production alert.
    // Optional (not required) so existing closures made before this field
    // existed, and any future closure flow that doesn't ask, don't break.
    verdict: {
      type: String,
      enum: ['true_positive', 'false_positive', 'benign', 'uncertain'],
      default: null,
    },
    // See AlertAssignment.js's alertSnapshot for why this exists — same
    // reasoning, applies equally to closed cases.
    alertSnapshot: { type: Schema.Types.Mixed, default: null },
  },
  {
    timestamps: true,
  }
);

AlertClosureSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AlertClosure', AlertClosureSchema);
