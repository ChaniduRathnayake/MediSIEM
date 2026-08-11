import DeviceGroup from '../models/DeviceGroup.js';
import Device from '../models/Device.js';
import MedicalDevice from '../models/MedicalDevice.js';
import { logAudit } from '../utils/auditLog.js';

// ─── GET /api/device-groups  (admin only) ──────────────────────────────────────
export const getAllDeviceGroups = async (req, res) => {
  try {
    const groups = await DeviceGroup.find().sort({ name: 1 });

    // Device counts per group, computed in one aggregation rather than N queries.
    // Covers both live Wazuh agents (Device) and the onboarded medical device
    // inventory (MedicalDevice) — a group's count reflects everything tagged
    // with it, regardless of which collection the device lives in.
    const [agentCounts, medicalCounts] = await Promise.all([
      Device.aggregate([
        { $unwind: '$groups' },
        { $group: { _id: '$groups', count: { $sum: 1 } } },
      ]),
      MedicalDevice.aggregate([
        { $unwind: '$groups' },
        { $group: { _id: '$groups', count: { $sum: 1 } } },
      ]),
    ]);
    const countByName = {};
    for (const c of [...agentCounts, ...medicalCounts]) {
      countByName[c._id] = (countByName[c._id] ?? 0) + c.count;
    }

    const withCounts = groups.map((g) => ({ ...g.toJSON(), deviceCount: countByName[g.name] ?? 0 }));
    return res.status(200).json({ groups: withCounts });
  } catch (err) {
    console.error('[getAllDeviceGroups]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── POST /api/device-groups  (admin only) ─────────────────────────────────────
export const createDeviceGroup = async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Group name is required.' });
    }

    const existing = await DeviceGroup.findOne({ name: name.trim() });
    if (existing) {
      return res.status(409).json({ error: 'A group with that name already exists.' });
    }

    const group = await DeviceGroup.create({
      name: name.trim(),
      description: (description || '').trim(),
      createdBy: { id: req.user.id, name: req.user.name },
    });

    await logAudit({
      action: 'create_device_group',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: group._id.toString(), name: group.name },
      details: `Created group "${group.name}"`,
    });

    return res.status(201).json({ group: { ...group.toJSON(), deviceCount: 0 } });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A group with that name already exists.' });
    }
    console.error('[createDeviceGroup]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PATCH /api/device-groups/:id  (admin only) ────────────────────────────────
export const updateDeviceGroup = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description } = req.body;

    const group = await DeviceGroup.findById(id);
    if (!group) return res.status(404).json({ error: 'Group not found.' });

    const beforeName = group.name;
    const beforeDescription = group.description;

    if (name !== undefined && name.trim()) group.name = name.trim();
    if (description !== undefined) group.description = description.trim();

    await group.save();

    // Renaming a group must be reflected everywhere it's already assigned
    if (group.name !== beforeName) {
      await Promise.all([
        Device.updateMany({ groups: beforeName }, { $set: { 'groups.$[el]': group.name } }, { arrayFilters: [{ el: beforeName }] }),
        MedicalDevice.updateMany({ groups: beforeName }, { $set: { 'groups.$[el]': group.name } }, { arrayFilters: [{ el: beforeName }] }),
      ]);
    }

    const changes = [];
    if (group.name !== beforeName) changes.push(`name "${beforeName}" → "${group.name}"`);
    if (group.description !== beforeDescription) changes.push('description changed');
    if (changes.length > 0) {
      await logAudit({
        action: 'update_device_group',
        actor: { id: req.user.id, name: req.user.name, email: req.user.email },
        target: { id: group._id.toString(), name: group.name },
        details: changes.join(', '),
      });
    }

    return res.status(200).json({ group: group.toJSON() });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A group with that name already exists.' });
    }
    console.error('[updateDeviceGroup]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── DELETE /api/device-groups/:id  (admin only) ───────────────────────────────
export const deleteDeviceGroup = async (req, res) => {
  try {
    const { id } = req.params;

    const group = await DeviceGroup.findByIdAndDelete(id);
    if (!group) return res.status(404).json({ error: 'Group not found.' });

    // Don't leave dangling references on devices that had this group assigned
    await Promise.all([
      Device.updateMany({ groups: group.name }, { $pull: { groups: group.name } }),
      MedicalDevice.updateMany({ groups: group.name }, { $pull: { groups: group.name } }),
    ]);

    await logAudit({
      action: 'delete_device_group',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: group._id.toString(), name: group.name },
      details: `Deleted group "${group.name}"`,
    });

    return res.status(200).json({ message: 'Group deleted successfully.' });
  } catch (err) {
    console.error('[deleteDeviceGroup]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};
