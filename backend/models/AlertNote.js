import mongoose, { Schema } from 'mongoose';

// Own collection (not embedded on AlertAssignment) so notes survive an unassign/reassign.
const AlertNoteSchema = new Schema(
  {
    alertId: {
      type: String,
      required: true,
      index: true,
    },
    author: {
      id: { type: String, required: true },
      name: String,
      email: String,
    },
    text: {
      type: String,
      required: [true, 'Note text is required.'],
      trim: true,
      maxlength: 2000,
    },
    // User ids mentioned via @Name, resolved at write time.
    mentions: [{ type: String }],
  },
  {
    timestamps: true,
  }
);

AlertNoteSchema.set('toJSON', {
  transform(_doc, ret) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    return ret;
  },
});

export default mongoose.model('AlertNote', AlertNoteSchema);
