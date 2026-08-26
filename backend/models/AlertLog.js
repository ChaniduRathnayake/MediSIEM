import mongoose, { Schema } from 'mongoose';

// Durable per-alert log for reports — the in-memory buffer evicts, and
// AlertAssignment/AlertClosure only snapshot alerts someone actually worked.
// Upserted by alertId so a duplicate-folded re-emit doesn't inflate counts.
const AlertLogSchema = new Schema(
  {
    alertId: {
      type: String,
      required: true,
      unique: true,
    },
    timestamp: {
      type: Date,
      required: true,
      index: true,
    },
    CAS: { type: Number, default: null },
    action: { type: String, default: null }, // 'Immediate' | 'Investigate' | 'Monitor'
    severity: { type: String, enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default: null },
    department: { type: String, default: null },
    agent: { type: String, default: null },
    deviceType: { type: String, default: null },
    deviceCriticality: { type: String, default: null },
    label: { type: String, default: null },
    ruleDescription: { type: String, default: null },
    mitreTactic: { type: [String], default: [] },
    matchedRuleNames: { type: [String], default: [] },
    // Populated asynchronously by lifeCriticalBridgeService.js once the
    // decision engine responds — null until then, and permanently null for
    // alerts scored before this integration existed or while the engine is
    // unreachable.
    lifeCriticalTier: { type: Number, default: null },
    lifeCriticalAction: { type: String, default: null },
    lifeCriticalDecisionId: { type: String, default: null },
  },
  {
    timestamps: true,
  }
);

AlertLogSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AlertLog', AlertLogSchema);
