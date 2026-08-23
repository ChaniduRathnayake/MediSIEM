import MedicalDevice from '../models/MedicalDevice.js';
import DeviceGroup from '../models/DeviceGroup.js';
import { logAudit } from '../utils/auditLog.js';
import { invalidateDeviceInventoryCache } from '../config/deviceInventory.js';

const CRITICALITY_LEVELS = ['low', 'medium', 'elevated', 'high', 'critical'];
const STATUSES = ['active', 'maintenance', 'decommissioned'];

async function validateGroups(groups) {
  if (!Array.isArray(groups) || !groups.every((g) => typeof g === 'string')) {
    return { error: 'groups must be an array of strings.' };
  }
  const uniqueGroups = [...new Set(groups.map((g) => g.trim()).filter(Boolean))];
  if (uniqueGroups.length > 0) {
    const known = await DeviceGroup.find({ name: { $in: uniqueGroups } }).select('name');
    const knownNames = new Set(known.map((g) => g.name));
    const unknown = uniqueGroups.filter((g) => !knownNames.has(g));
    if (unknown.length > 0) {
      return { error: `Unknown group(s): ${unknown.join(', ')}. Create the group first.` };
    }
  }
  return { groups: uniqueGroups };
}

// ─── GET /api/medical-devices  (any authenticated user) ───────────────────────
export const getAllMedicalDevices = async (req, res) => {
  try {
    const devices = await MedicalDevice.find().sort({ department: 1, deviceName: 1 });
    return res.status(200).json({ devices });
  } catch (err) {
    console.error('[getAllMedicalDevices]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── POST /api/medical-devices  (admin only) ───────────────────────────────────
export const createMedicalDevice = async (req, res) => {
  try {
    const {
      key, deviceName, deviceType, department,
      manufacturer, model, serialNumber, location, criticality, notes, groups,
    } = req.body;

    if (!key || !key.trim()) return res.status(400).json({ error: 'Device key is required.' });
    if (!deviceName || !deviceName.trim()) return res.status(400).json({ error: 'Device name is required.' });
    if (!deviceType || !deviceType.trim()) return res.status(400).json({ error: 'Device type is required.' });
    if (!department || !department.trim()) return res.status(400).json({ error: 'Department is required.' });
    if (criticality !== undefined && !CRITICALITY_LEVELS.includes(criticality)) {
      return res.status(400).json({ error: `criticality must be one of: ${CRITICALITY_LEVELS.join(', ')}.` });
    }

    let groupList = [];
    if (groups !== undefined) {
      const result = await validateGroups(groups);
      if (result.error) return res.status(400).json({ error: result.error });
      groupList = result.groups;
    }

    const device = await MedicalDevice.create({
      key: key.trim().toLowerCase(),
      deviceName: deviceName.trim(),
      deviceType: deviceType.trim(),
      department: department.trim(),
      manufacturer: (manufacturer || '').trim(),
      model: (model || '').trim(),
      serialNumber: (serialNumber || '').trim(),
      location: (location || '').trim(),
      criticality: criticality || 'medium',
      notes: (notes || '').trim(),
      groups: groupList,
      onboardedBy: { id: req.user.id, name: req.user.name },
    });

    invalidateDeviceInventoryCache();

    await logAudit({
      action: 'onboard_medical_device',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: device._id.toString(), name: device.deviceName },
      details: `Onboarded "${device.deviceName}" (${device.deviceType}, ${device.department})`,
    });

    return res.status(201).json({ device });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A device with that key already exists.' });
    }
    console.error('[createMedicalDevice]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PATCH /api/medical-devices/:id  (admin only) ──────────────────────────────
export const updateMedicalDevice = async (req, res) => {
  try {
    const { id } = req.params;
    const device = await MedicalDevice.findById(id);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    const {
      key, deviceName, deviceType, department,
      manufacturer, model, serialNumber, location, criticality, status, notes,
    } = req.body;

    if (criticality !== undefined && !CRITICALITY_LEVELS.includes(criticality)) {
      return res.status(400).json({ error: `criticality must be one of: ${CRITICALITY_LEVELS.join(', ')}.` });
    }
    if (status !== undefined && !STATUSES.includes(status)) {
      return res.status(400).json({ error: `status must be one of: ${STATUSES.join(', ')}.` });
    }

    const changes = [];
    if (key !== undefined && key.trim() && key.trim().toLowerCase() !== device.key) {
      changes.push(`key "${device.key}" → "${key.trim().toLowerCase()}"`);
      device.key = key.trim().toLowerCase();
    }
    if (deviceName !== undefined && deviceName.trim() && deviceName.trim() !== device.deviceName) {
      changes.push(`name "${device.deviceName}" → "${deviceName.trim()}"`);
      device.deviceName = deviceName.trim();
    }
    if (deviceType !== undefined && deviceType.trim() && deviceType.trim() !== device.deviceType) {
      changes.push('device type updated');
      device.deviceType = deviceType.trim();
    }
    if (department !== undefined && department.trim() && department.trim() !== device.department) {
      changes.push('department updated');
      device.department = department.trim();
    }
    if (manufacturer !== undefined) device.manufacturer = manufacturer.trim();
    if (model !== undefined) device.model = model.trim();
    if (serialNumber !== undefined) device.serialNumber = serialNumber.trim();
    if (location !== undefined) device.location = location.trim();
    if (notes !== undefined) device.notes = notes.trim();
    if (criticality !== undefined && criticality !== device.criticality) {
      changes.push(`criticality "${device.criticality}" → "${criticality}"`);
      device.criticality = criticality;
    }
    if (status !== undefined && status !== device.status) {
      changes.push(`status "${device.status}" → "${status}"`);
      device.status = status;
    }

    await device.save();
    invalidateDeviceInventoryCache();

    if (changes.length > 0) {
      await logAudit({
        action: 'update_medical_device',
        actor: { id: req.user.id, name: req.user.name, email: req.user.email },
        target: { id: device._id.toString(), name: device.deviceName },
        details: changes.join(', '),
      });
    }

    return res.status(200).json({ device });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map((e) => e.message);
      return res.status(400).json({ error: messages[0] });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A device with that key already exists.' });
    }
    console.error('[updateMedicalDevice]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PUT /api/medical-devices/:id/groups  (admin only — tag an onboarded device) ─
export const setMedicalDeviceGroups = async (req, res) => {
  try {
    const { id } = req.params;
    const { groups } = req.body;

    const result = await validateGroups(groups);
    if (result.error) return res.status(400).json({ error: result.error });

    const before = await MedicalDevice.findById(id).select('groups deviceName');
    if (!before) return res.status(404).json({ error: 'Device not found.' });
    const beforeGroups = before.groups ?? [];

    const device = await MedicalDevice.findByIdAndUpdate(
      id,
      { $set: { groups: result.groups } },
      { new: true }
    );

    const added = result.groups.filter((g) => !beforeGroups.includes(g));
    const removed = beforeGroups.filter((g) => !result.groups.includes(g));
    if (added.length > 0 || removed.length > 0) {
      const changes = [];
      if (added.length > 0) changes.push(`added to ${added.map((g) => `"${g}"`).join(', ')}`);
      if (removed.length > 0) changes.push(`removed from ${removed.map((g) => `"${g}"`).join(', ')}`);
      await logAudit({
        action: 'update_medical_device_groups',
        actor: { id: req.user.id, name: req.user.name, email: req.user.email },
        target: { id: device._id.toString(), name: device.deviceName },
        details: changes.join('; '),
      });
    }

    return res.status(200).json({ device });
  } catch (err) {
    console.error('[setMedicalDeviceGroups]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── DELETE /api/medical-devices/:id  (admin only) ─────────────────────────────
export const deleteMedicalDevice = async (req, res) => {
  try {
    const { id } = req.params;
    const device = await MedicalDevice.findByIdAndDelete(id);
    if (!device) return res.status(404).json({ error: 'Device not found.' });

    invalidateDeviceInventoryCache();

    await logAudit({
      action: 'delete_medical_device',
      actor: { id: req.user.id, name: req.user.name, email: req.user.email },
      target: { id: device._id.toString(), name: device.deviceName },
      details: `Removed "${device.deviceName}" from the medical device inventory`,
    });

    return res.status(200).json({ message: 'Device removed successfully.' });
  } catch (err) {
    console.error('[deleteMedicalDevice]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};
