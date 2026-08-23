// The hospital's onboarded medical device inventory (ventilators, infusion
// pumps, monitors, etc.), MongoDB-backed. Unlike the live Wazuh agent table,
// these are admin-onboarded assets that don't need to run a Wazuh agent —
// their device_type/department is what CAAP scores clinical criticality
// against for any alert whose agent name/IP matches a device's `key`.
import React, { useEffect, useMemo, useState } from 'react';
import {
  Stethoscope, Plus, Loader2, AlertCircle, X, Pencil, Trash2, Search, ShieldAlert,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import type { DeviceGroup } from './deviceApi';
import GroupAssignDropdown from './GroupAssignDropdown';
import StatCard from '../../components/StatCard';
import {
  getMedicalDevices, createMedicalDevice, updateMedicalDevice, deleteMedicalDevice, setMedicalDeviceGroups,
} from '../../services/medicalDeviceApi';
import type { MedicalDevice, MedicalDeviceInput, DeviceCriticality, DeviceStatus } from '../../services/medicalDeviceApi';

const CRITICALITY_STYLES: Record<DeviceCriticality, string> = {
  low: 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300',
  medium: 'bg-amber-500/10 border-amber-500/30 text-amber-500 dark:text-amber-400',
  elevated: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-600 dark:text-yellow-400',
  high: 'bg-orange-500/10 border-orange-500/30 text-orange-500 dark:text-orange-400',
  critical: 'bg-red-500/10 border-red-500/30 text-red-500 dark:text-red-400',
};

const STATUS_STYLES: Record<DeviceStatus, string> = {
  active: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500 dark:text-emerald-400',
  maintenance: 'bg-amber-500/10 border-amber-500/30 text-amber-500 dark:text-amber-400',
  decommissioned: 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400',
};

const EMPTY_FORM: MedicalDeviceInput = {
  key: '', deviceName: '', deviceType: '', department: '',
  manufacturer: '', model: '', serialNumber: '', location: '', criticality: 'medium', notes: '',
};

// ─── Onboard / Edit device form modal ───────────────────────────────────────
const MedicalDeviceFormModal: React.FC<{
  initial?: MedicalDevice | null;
  onClose: () => void;
  onSubmit: (payload: MedicalDeviceInput) => Promise<void>;
}> = ({ initial, onClose, onSubmit }) => {
  const [form, setForm] = useState<MedicalDeviceInput>(
    initial
      ? {
          key: initial.key, deviceName: initial.deviceName, deviceType: initial.deviceType, department: initial.department,
          manufacturer: initial.manufacturer, model: initial.model, serialNumber: initial.serialNumber,
          location: initial.location, criticality: initial.criticality, notes: initial.notes,
        }
      : EMPTY_FORM
  );
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const set = (field: keyof MedicalDeviceInput) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.key.trim() || !form.deviceName.trim() || !form.deviceType.trim() || !form.department.trim()) {
      setError('Key, device name, device type, and department are required.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onSubmit(form);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save device.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputClass = 'w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20 transition-all';
  const labelClass = 'block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex-shrink-0">
          <h2 className="text-sm font-bold text-slate-900 dark:text-white">{initial ? 'Edit Device' : 'Onboard Medical Device'}</h2>
          <button onClick={onClose} aria-label="Close" className="text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4 overflow-y-auto">
          {error && (
            <div className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelClass}>Device Name *</label>
              <input value={form.deviceName} onChange={set('deviceName')} placeholder="ICU Ventilator 06" className={inputClass} />
            </div>
            <div>
              <label className={labelClass}>Key (Wazuh agent name/IP) *</label>
              <input value={form.key} onChange={set('key')} placeholder="icu-vent-06" className={inputClass} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelClass}>Device Type *</label>
              <input value={form.deviceType} onChange={set('deviceType')} placeholder="ICU Ventilator" className={inputClass} />
            </div>
            <div>
              <label className={labelClass}>Department *</label>
              <input value={form.department} onChange={set('department')} placeholder="ICU" className={inputClass} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelClass}>Manufacturer</label>
              <input value={form.manufacturer} onChange={set('manufacturer')} placeholder="Draeger" className={inputClass} />
            </div>
            <div>
              <label className={labelClass}>Model</label>
              <input value={form.model} onChange={set('model')} placeholder="Evita V500" className={inputClass} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelClass}>Serial Number</label>
              <input value={form.serialNumber} onChange={set('serialNumber')} className={inputClass} />
            </div>
            <div>
              <label className={labelClass}>Location</label>
              <input value={form.location} onChange={set('location')} placeholder="ICU Bay 6" className={inputClass} />
            </div>
          </div>

          <div>
            <label className={labelClass}>Criticality</label>
            <select value={form.criticality} onChange={set('criticality')} className={inputClass}>
              <option value="low">Low — Administrative / non-clinical</option>
              <option value="medium">Medium — Clinical IT infrastructure</option>
              <option value="elevated">Elevated — Clinical data & informatics</option>
              <option value="high">High — Direct patient monitoring / diagnostic-therapeutic</option>
              <option value="critical">Critical — Life-sustaining / critical care</option>
            </select>
          </div>

          <div>
            <label className={labelClass}>Notes</label>
            <textarea value={form.notes} onChange={set('notes')} rows={2} className={inputClass} />
          </div>

          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 py-2.5 rounded-lg text-sm font-semibold text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-slate-900 dark:text-white bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-60 disabled:cursor-not-allowed transition-all"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : (initial ? 'Save Changes' : 'Onboard Device')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const MedicalDeviceInventoryPanel: React.FC<{
  groups: DeviceGroup[];
  createGroup: (name: string, description?: string) => Promise<DeviceGroup>;
}> = ({ groups, createGroup }) => {
  const { token } = useAuth();
  const [devices, setDevices] = useState<MedicalDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('all');
  const [formTarget, setFormTarget] = useState<MedicalDevice | null | undefined>(undefined); // undefined = closed, null = onboarding, device = editing
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setDevices(await getMedicalDevices(token));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load medical device inventory.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  const departments = useMemo(
    () => [...new Set(devices.map((d) => d.department))].sort((a, b) => a.localeCompare(b)),
    [devices]
  );

  const filtered = devices.filter((d) => {
    if (departmentFilter !== 'all' && d.department !== departmentFilter) return false;
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      return d.deviceName.toLowerCase().includes(q) || d.deviceType.toLowerCase().includes(q) || d.key.toLowerCase().includes(q);
    }
    return true;
  });

  const counts = {
    total: devices.length,
    critical: devices.filter((d) => d.criticality === 'critical').length,
    departments: departments.length,
    decommissioned: devices.filter((d) => d.status === 'decommissioned').length,
  };

  const handleSave = async (payload: MedicalDeviceInput) => {
    if (!token) throw new Error('Not authenticated.');
    if (formTarget) {
      const updated = await updateMedicalDevice(token, formTarget.id, payload);
      setDevices((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));
    } else {
      const created = await createMedicalDevice(token, payload);
      setDevices((prev) => [...prev, created]);
    }
  };

  const handleDelete = async (device: MedicalDevice) => {
    if (!token) return;
    setDeletingId(device.id);
    setActionError(null);
    try {
      await deleteMedicalDevice(token, device.id);
      setDevices((prev) => prev.filter((d) => d.id !== device.id));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to remove device.');
    } finally {
      setDeletingId(null);
    }
  };

  const toggleDeviceGroup = async (device: MedicalDevice, groupName: string) => {
    if (!token) return;
    const next = device.groups.includes(groupName)
      ? device.groups.filter((g) => g !== groupName)
      : [...device.groups, groupName];
    try {
      const updated = await setMedicalDeviceGroups(token, device.id, next);
      setDevices((prev) => prev.map((d) => (d.id === updated.id ? updated : d)));
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to update tags.');
    }
  };

  const createAndAssign = async (device: MedicalDevice, name: string) => {
    const group = await createGroup(name);
    await toggleDeviceGroup(device, group.name);
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
            <Stethoscope className="w-4 h-4 text-cyan-400" /> Medical Device Inventory
          </h3>
          <p className="text-xs text-slate-400 dark:text-slate-500 mt-0.5">
            Onboarded clinical assets — drives CAAP clinical-criticality scoring, independent of Wazuh enrollment
          </p>
        </div>
        <button
          onClick={() => setFormTarget(null)}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-900 dark:text-white text-sm font-semibold transition-all"
        >
          <Plus className="w-3.5 h-3.5" /> Onboard Device
        </button>
      </div>

      {actionError && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {actionError}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={<Stethoscope className="w-5 h-5 text-cyan-400" />} label="Onboarded Devices" value={String(counts.total)} sub="Clinical inventory" color="cyan" />
        <StatCard icon={<ShieldAlert className="w-5 h-5 text-red-400" />} label="Critical" value={String(counts.critical)} sub="Highest impact if compromised" color="red" />
        <StatCard icon={<Stethoscope className="w-5 h-5 text-emerald-400" />} label="Departments" value={String(counts.departments)} sub="Distinct clinical areas" color="emerald" />
        <StatCard icon={<Stethoscope className="w-5 h-5 text-amber-400" />} label="Decommissioned" value={String(counts.decommissioned)} sub="No longer in service" color="amber" />
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name, type, key…"
            className="w-full pl-8 pr-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
          />
        </div>
        <select
          value={departmentFilter}
          onChange={(e) => setDepartmentFilter(e.target.value)}
          className="px-2.5 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500/60"
        >
          <option value="all">All departments</option>
          {departments.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>

      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-slate-400 dark:text-slate-500 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading medical device inventory…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 px-5 py-6 text-red-500 dark:text-red-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" /> {error}
          </div>
        ) : filtered.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500 text-center py-14">
            {devices.length === 0 ? 'No devices onboarded yet — click "Onboard Device" to add the first one.' : 'No devices match the current filters.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-slate-400 dark:text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-5 text-left">Device</th>
                  <th className="py-2.5 px-5 text-left">Type</th>
                  <th className="py-2.5 px-5 text-left">Department</th>
                  <th className="py-2.5 px-5 text-left">Manufacturer / Model</th>
                  <th className="py-2.5 px-5 text-left">Location</th>
                  <th className="py-2.5 px-5 text-left">Criticality</th>
                  <th className="py-2.5 px-5 text-left">Status</th>
                  <th className="py-2.5 px-5 text-left">Tags</th>
                  <th className="py-2.5 px-5 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((d) => (
                  <tr key={d.id} className="border-b border-slate-100 dark:border-slate-800/60 last:border-0 hover:bg-slate-100 dark:hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-5">
                      <p className="text-sm text-slate-900 dark:text-white font-medium">{d.deviceName}</p>
                      <p className="text-xs text-slate-400 dark:text-slate-500 font-mono">{d.key}</p>
                    </td>
                    <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400">{d.deviceType}</td>
                    <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400">{d.department}</td>
                    <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400">
                      {[d.manufacturer, d.model].filter(Boolean).join(' · ') || '—'}
                    </td>
                    <td className="py-3 px-5 text-xs text-slate-500 dark:text-slate-400">{d.location || '—'}</td>
                    <td className="py-3 px-5">
                      <span className={`inline-flex px-2 py-0.5 rounded-full border text-xs capitalize whitespace-nowrap ${CRITICALITY_STYLES[d.criticality]}`}>
                        {d.criticality}
                      </span>
                    </td>
                    <td className="py-3 px-5">
                      <span className={`inline-flex px-2 py-0.5 rounded-full border text-xs capitalize whitespace-nowrap ${STATUS_STYLES[d.status]}`}>
                        {d.status}
                      </span>
                    </td>
                    <td className="py-3 px-5">
                      <GroupAssignDropdown
                        agentGroups={d.groups}
                        allGroups={groups}
                        onToggle={(name) => toggleDeviceGroup(d, name)}
                        onCreateAndAssign={(name) => createAndAssign(d, name)}
                      />
                    </td>
                    <td className="py-3 px-5">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setFormTarget(d)}
                          className="p-1.5 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                          title="Edit device"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(d)}
                          disabled={deletingId === d.id}
                          className="p-1.5 rounded-lg text-slate-500 dark:text-slate-400 hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 transition-colors"
                          title="Remove device"
                        >
                          {deletingId === d.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {formTarget !== undefined && (
        <MedicalDeviceFormModal
          initial={formTarget}
          onClose={() => setFormTarget(undefined)}
          onSubmit={handleSave}
        />
      )}
    </div>
  );
};

export default MedicalDeviceInventoryPanel;
