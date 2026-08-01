import mongoose, { Schema } from 'mongoose';

// ─── Schema ────────────────────────────────────────────────────────────────────
// Catalog of MediSIEM-side organizational groups (e.g. "ICU", "Radiology").
// Independent of Wazuh's own native agent groups — purely for local labeling.
const DeviceGroupSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, 'Group name is required'],
      trim: true,
      unique: true,
      minlength: [2, 'Group name must be at least 2 characters'],
      maxlength: [60, 'Group name cannot exceed 60 characters'],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [200, 'Description cannot exceed 200 characters'],
      default: '',
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

DeviceGroupSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('DeviceGroup', DeviceGroupSchema);
