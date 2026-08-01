import Device from '../models/Device.js';
import DeviceGroup from '../models/DeviceGroup.js';
import { logAudit } from '../utils/auditLog.js';

const OS_CATEGORIES = ['windows', 'linux', 'macos', 'network', 'iot', 'unknown'];

// ─── GET /api/devices/meta  (admin only) ───────────────────────────────────────
// Returns MediSIEM's local overlay metadata for every known agent. The caller
// merges this with the live Wazuh agent list by agentId — Wazuh remains the
// source of truth for the agent itself.
export const getAllDeviceMeta = async (req, res) => {
  try {
    const devices = await Device.find();
    return res.status(200).json({ devices });
  } catch (err) {
    console.error('[getAllDeviceMeta]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PUT /api/devices/:agentId/groups  (admin only) ────────────────────────────
export const setAgentGroups = async (req, res) => {
  try {
    const { agentId } = req.params;
    const { groups, agentName } = req.body;

    if (!Array.isArray(groups) || !groups.every((g) => typeof g === 'string')) {
      return res.status(400).json({ error: 'groups must be an array of strings.' });
    }

    const uniqueGroups = [...new Set(groups.map((g) => g.trim()).filter(Boolean))];

    if (uniqueGroups.length > 0) {
      const known = await DeviceGroup.find({ name: { $in: uniqueGroups } }).select('name');
      const knownNames = new Set(known.map((g) => g.name));
      const unknown = uniqueGroups.filter((g) => !knownNames.has(g));
      if (unknown.length > 0) {
        return res.status(400).json({ error: `Unknown group(s): ${unknown.join(', ')}. Create the group first.` });
      }
    }

    const before = await Device.findOne({ agentId }).select('groups');
    const beforeGroups = before?.groups ?? [];

    const device = await Device.findOneAndUpdate(
      { agentId },
      { $set: { groups: uniqueGroups, ...(agentName ? { agentName } : {}) } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    const added = uniqueGroups.filter((g) => !beforeGroups.includes(g));
    const removed = beforeGroups.filter((g) => !uniqueGroups.includes(g));
    if (added.length > 0 || removed.length > 0) {
      const changes = [];
      if (added.length > 0) changes.push(`added to ${added.map((g) => `"${g}"`).join(', ')}`);
      if (removed.length > 0) changes.push(`removed from ${removed.map((g) => `"${g}"`).join(', ')}`);
      await logAudit({
        action: 'update_device_groups',
        actor: { id: req.user.id, name: req.user.name, email: req.user.email },
        target: { id: agentId, name: device.agentName || agentName || agentId },
        details: changes.join('; '),
      });
    }

    return res.status(200).json({ device });
  } catch (err) {
    console.error('[setAgentGroups]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};

// ─── PATCH /api/devices/:agentId/os-category  (admin only) ────────────────────
export const setAgentOsCategory = async (req, res) => {
  try {
    const { agentId } = req.params;
    const { osCategory } = req.body;

    if (osCategory !== null && !OS_CATEGORIES.includes(osCategory)) {
      return res.status(400).json({ error: `osCategory must be one of: ${OS_CATEGORIES.join(', ')}, or null.` });
    }

    const before = await Device.findOne({ agentId }).select('osCategoryOverride agentName');
    const beforeCategory = before?.osCategoryOverride ?? null;

    const device = await Device.findOneAndUpdate(
      { agentId },
      { $set: { osCategoryOverride: osCategory } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    if (osCategory !== beforeCategory) {
      await logAudit({
        action: 'update_device_os_category',
        actor: { id: req.user.id, name: req.user.name, email: req.user.email },
        target: { id: agentId, name: device.agentName || agentId },
        details: osCategory ? `OS category set to "${osCategory}"` : 'OS category override cleared',
      });
    }

    return res.status(200).json({ device });
  } catch (err) {
    console.error('[setAgentOsCategory]', err);
    return res.status(500).json({ error: 'Server error.' });
  }
};
