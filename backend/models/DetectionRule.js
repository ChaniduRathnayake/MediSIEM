import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// A rule is a name + an AND-combined list of field/operator/value conditions,
// evaluated against every alert as it flows through alertPipeline.js. Kept
// deliberately simple — no OR logic, no nested groups, no scripting — so
// evaluation stays a fixed whitelist switch, not an injection surface.
const CONDITION_FIELDS = ['ruleDescription', 'ruleLevel', 'agent', 'department', 'CAS', 'label', 'action', 'cluster', 'deviceType', 'deviceCriticality'];
const CONDITION_OPERATORS = ['contains', 'equals', 'gte', 'lte', 'gt', 'lt'];

const ConditionSchema = new Schema(
  {
    field: { type: String, required: true, enum: CONDITION_FIELDS },
    operator: { type: String, required: true, enum: CONDITION_OPERATORS },
    value: { type: Schema.Types.Mixed, required: true },
  },
  { _id: false }
);

const DetectionRuleSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, default: '' },
    enabled: { type: Boolean, default: true },
    conditions: {
      type: [ConditionSchema],
      validate: (v) => Array.isArray(v) && v.length > 0,
    },
    createdBy: {
      id: String,
      name: String,
    },
  },
  {
    timestamps: true,
  }
);

DetectionRuleSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export const RULE_FIELDS = CONDITION_FIELDS;
export const RULE_OPERATORS = CONDITION_OPERATORS;
export default mongoose.model('DetectionRule', DetectionRuleSchema);
