import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Local MediSIEM-side metadata for a Wazuh agent, keyed by the Wazuh agent id.
// Wazuh remains the source of truth for the agent itself (name, IP, OS, status,
// etc. are fetched live and never stored here) — this only holds the overlay
// data MediSIEM owns: manual group membership and an optional OS-category
// override for devices Wazuh misdetects.
const DeviceSchema = new Schema(
  {
    agentId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    agentName: {
      type: String,
      trim: true,
      default: '',
    },
    groups: {
      type: [String],
      default: [],
    },
    osCategoryOverride: {
      type: String,
      enum: ['windows', 'linux', 'macos', 'network', 'iot', 'unknown', null],
      default: null,
    },
    // Manual link to the clinical asset this agent actually is (Devices page
    // "Tag Medical Device") — takes precedence over MedicalDevice.key
    // name/IP matching in config/deviceInventory.js, since an admin explicitly
    // identifying the device is more reliable than a hostname heuristic.
    medicalDeviceId: {
      type: Schema.Types.ObjectId,
      ref: 'MedicalDevice',
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

DeviceSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('Device', DeviceSchema);
