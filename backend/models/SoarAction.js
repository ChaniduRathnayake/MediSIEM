import mongoose, { Schema } from 'mongoose';

// Durable record of the life-critical-orchestration SOAR flow (decision engine
// + Shuffle playbooks). Today the engine's decision and the clinician's
// approve/deny response only round-trip through its own JSONL audit log
// (life-critical-orchestration/engine/data/audit_log.jsonl) — this collection
// mirrors that into Mongo so MediSIEM has a queryable, durable copy that
// survives engine restarts and can be joined against AlertLog/AuditLog.
// Upserted by decisionId: written once by lifeCriticalBridgeService.js when
// the engine first classifies an alert, then updated in place when a
// clinician resolves a Tier 3 pending approval.
const SoarActionSchema = new Schema(
  {
    decisionId: {
      type: String,
      required: true,
      unique: true,
    },
    alertId: { type: String, required: true, index: true },
    assetId: { type: String, default: null, index: true },

    tier: { type: Number, default: null },
    action: { type: String, default: null },
    rationale: { type: String, default: null },
    matchedRule: { type: String, default: null },
    effectiveCriticality: { type: String, default: null },
    effectiveCriticalityScore: { type: Number, default: null },
    extremeThreat: { type: Boolean, default: false },
    failSafeApplied: { type: Boolean, default: false },
    proposedActionIfApproved: { type: String, default: null },
    blockDest: { type: String, default: null },
    blockPorts: { type: [Number], default: [] },

    // 'executed' for tiers the engine acts on immediately; 'pending' for a
    // Tier 3 alert awaiting a clinician; 'approved'/'denied' once resolved.
    status: {
      type: String,
      enum: ['executed', 'pending', 'approved', 'denied'],
      default: 'executed',
    },
    decidedAt: { type: Date, default: null },

    clinicianDecision: {
      approved: { type: Boolean, default: null },
      by: {
        id: { type: String, default: null },
        name: { type: String, default: null },
        email: { type: String, default: null },
      },
      decidedAt: { type: Date, default: null },
      // { mode: 'real' | 'simulated', ... } from the Shuffle sim's enforcement
      // module — null when the sim was unreachable and the engine-only
      // fallback ran instead (no live enforcement in that case).
      enforcement: { type: Schema.Types.Mixed, default: null },
    },

    // Full engine response, kept verbatim so a field this schema doesn't
    // surface yet is never silently dropped.
    raw: { type: Schema.Types.Mixed, default: null },

    // The exact Enriched Alert payload sent to the engine (buildEnrichedAlert's
    // output in lifeCriticalBridgeService.js) — kept verbatim alongside `raw`
    // so /decisions-history can serve a durable {alert, decision} pair without
    // depending on AlertLog, which only gets a full write on a dedup group's
    // FIRST occurrence (see alertPipeline.js) and is otherwise missing CAS for
    // every repeat occurrence this bridge still classifies independently.
    alertSnapshot: { type: Schema.Types.Mixed, default: null },
  },
  {
    timestamps: true,
  }
);

SoarActionSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('SoarAction', SoarActionSchema);
