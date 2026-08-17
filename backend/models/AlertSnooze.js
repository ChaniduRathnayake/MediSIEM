import mongoose, { Schema } from 'mongoose';

// Hides an open, still-assigned case from the active queue until snoozedUntil passes.
const AlertSnoozeSchema = new Schema(
  {
    alertId: {
      type: String,
      required: true,
      unique: true,
    },
    snoozedUntil: {
      type: Date,
      required: true,
    },
    reason: {
      type: String,
      trim: true,
      maxlength: 300,
      default: '',
    },
    snoozedBy: {
      id: { type: String, required: true },
      name: String,
      email: String,
    },
  },
  {
    timestamps: true,
  }
);

AlertSnoozeSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AlertSnooze', AlertSnoozeSchema);
