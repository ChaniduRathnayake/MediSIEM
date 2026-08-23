import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// The hospital's onboarded medical device inventory (ventilators, infusion
// pumps, monitors, imaging systems, etc.). This is MediSIEM's own asset
// record, independent of Wazuh agent enrollment — a device can be listed here
// whether or not it happens to also run a Wazuh agent.
//
// `key` is what ties a row here back to a live alert: it's matched against a
// Wazuh alert's agent.name/agent.ip (see config/deviceInventory.js) to derive
// the clinical metadata (device_type/department) the CAAP model scores on.
const MedicalDeviceSchema = new Schema(
  {
    key: {
      type: String,
      required: [true, 'Device key (matching Wazuh agent name or IP) is required'],
      trim: true,
      lowercase: true,
      unique: true,
      index: true,
    },
    deviceName: {
      type: String,
      required: [true, 'Device name is required'],
      trim: true,
      maxlength: 120,
    },
    deviceType: {
      type: String,
      required: [true, 'Device type is required'],
      trim: true,
      maxlength: 80,
    },
    department: {
      type: String,
      required: [true, 'Department is required'],
      trim: true,
      maxlength: 80,
    },
    manufacturer: { type: String, trim: true, maxlength: 100, default: '' },
    model: { type: String, trim: true, maxlength: 100, default: '' },
    serialNumber: { type: String, trim: true, maxlength: 100, default: '' },
    location: { type: String, trim: true, maxlength: 120, default: '' },
    criticality: {
      type: String,
      // 5-tier FDA-device-class hierarchy (21 CFR 860.3) — see
      // shared/cas_config.json's criticality_to_cc for the CC values and
      // MediSIEM_Medical_Device_Criticality_Ranking for the full rationale.
      // 'elevated' = Tier 3, "Clinical Data & Informatics Systems" (PACS,
      // EHR, clinical DB servers, LIS, point-of-care analysers) — sits
      // between 'medium' (Tier 2, IT infrastructure) and 'high' (Tier 4,
      // direct patient monitoring/diagnostic-therapeutic).
      enum: ['low', 'medium', 'elevated', 'high', 'critical'],
      default: 'medium',
    },
    status: {
      type: String,
      enum: ['active', 'maintenance', 'decommissioned'],
      default: 'active',
    },
    groups: {
      type: [String],
      default: [],
    },
    notes: { type: String, trim: true, maxlength: 500, default: '' },
    onboardedBy: {
      id: String,
      name: String,
    },
  },
  {
    timestamps: true,
  }
);

MedicalDeviceSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('MedicalDevice', MedicalDeviceSchema);
