// backend/config/deviceInventory.js
//
// Maps a Wazuh agent (by name or IP) to clinical metadata the CAAP model needs
// for the Clinical Criticality (CC) dimension: device_type + department.
//
// TODO: replace this with your real hospital asset inventory — ideally pulled
// from a CMDB/asset table in Mongo rather than hardcoded here. This file is a
// working stand-in so the pipeline runs end-to-end today.

const DEVICE_INVENTORY = {
  // key: Wazuh agent.name or agent.ip (lowercase), value: clinical metadata
  'icu-vent-04': { device_type: 'ICU Ventilator', department: 'ICU' },
  'inf-pump-12': { device_type: 'Infusion Pump', department: 'ICU' },
  'cardiac-mon-7': { device_type: 'Cardiac Monitor', department: 'Cardiology' },
  'ct-mri-01': { device_type: 'CT/MRI System', department: 'Radiology' },
  'workstation-er': { device_type: 'Workstation', department: 'Emergency' },
  'nurse-station-3': { device_type: 'Workstation', department: 'General Ward' },
};

const DEFAULT_DEVICE = { device_type: 'Unknown Device', department: 'General' };

/**
 * Look up clinical metadata for a Wazuh agent.
 * @param {{name?: string, ip?: string}} agent
 */
export function lookupDevice(agent = {}) {
  const key = (agent.name || agent.ip || '').toLowerCase();
  return DEVICE_INVENTORY[key] || DEFAULT_DEVICE;
}

export default DEVICE_INVENTORY;
