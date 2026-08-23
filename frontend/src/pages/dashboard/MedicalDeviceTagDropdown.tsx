// Single-select, searchable "which clinical asset is this Wazuh agent"
// dropdown — the manual alternative to MedicalDevice.key matching an agent's
// name/IP, for agents whose hostname doesn't follow that convention (e.g. a
// generic "ICU-PC-04" that's actually a ventilator's control station). The
// tag feeds straight into CAAP's clinical-criticality (CC) scoring — see
// backend/config/deviceInventory.js.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Stethoscope, X, Search, Loader2 } from 'lucide-react';
import type { MedicalDevice } from '../../services/medicalDeviceApi';
import type { TaggedMedicalDevice } from './deviceApi';

const MedicalDeviceTagDropdown: React.FC<{
  devices: MedicalDevice[];
  tagged: TaggedMedicalDevice | null;
  onTag: (medicalDeviceId: string | null) => Promise<void>;
}> = ({ devices, tagged, onTag }) => {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [saving, setSaving] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = q
      ? devices.filter((d) =>
          d.deviceName.toLowerCase().includes(q) ||
          d.deviceType.toLowerCase().includes(q) ||
          d.department.toLowerCase().includes(q) ||
          d.location.toLowerCase().includes(q)
        )
      : devices;
    return [...list].sort((a, b) => a.department.localeCompare(b.department) || a.deviceName.localeCompare(b.deviceName));
  }, [devices, search]);

  const handlePick = async (id: string | null) => {
    setSaving(true);
    try {
      await onTag(id);
      setOpen(false);
      setSearch('');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="relative" ref={ref}>
      {tagged ? (
        <button
          onClick={() => setOpen((o) => !o)}
          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs whitespace-nowrap hover:bg-cyan-500/20 transition-colors max-w-[220px]"
          title={`${tagged.deviceName} · ${tagged.deviceType} · ${tagged.department}`}
        >
          <Stethoscope className="w-2.5 h-2.5 flex-shrink-0" />
          <span className="truncate">{tagged.deviceName}</span>
        </button>
      ) : (
        <button
          onClick={() => setOpen((o) => !o)}
          className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-400 dark:text-slate-500 text-xs whitespace-nowrap hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
        >
          <Stethoscope className="w-2.5 h-2.5" /> Tag device
        </button>
      )}

      {open && (
        <div className="absolute z-40 top-full left-0 mt-1.5 w-72 rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 shadow-2xl p-2">
          <div className="relative mb-2">
            <Search className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
            <input
              autoFocus
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search name, type, department…"
              className="w-full pl-7 pr-2 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
          </div>

          {tagged && (
            <button
              onClick={() => handlePick(null)}
              disabled={saving}
              className="flex items-center gap-1.5 w-full px-2 py-1.5 rounded-lg text-xs text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors mb-1"
            >
              <X className="w-3 h-3" /> Clear tag
            </button>
          )}

          <div className="max-h-56 overflow-y-auto space-y-0.5">
            {filtered.length === 0 ? (
              <p className="text-xs text-slate-400 dark:text-slate-500 px-2 py-1.5">No devices match.</p>
            ) : (
              filtered.map((d) => {
                const active = tagged?.id === d.id;
                return (
                  <button
                    key={d.id}
                    onClick={() => handlePick(d.id)}
                    disabled={saving}
                    className={`flex items-center justify-between gap-2 w-full px-2 py-1.5 rounded-lg text-left transition-colors disabled:opacity-50 ${
                      active ? 'bg-cyan-500/10 text-cyan-400' : 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    <span className="min-w-0">
                      <span className="block text-xs font-medium truncate">{d.deviceName}</span>
                      <span className="block text-xs text-slate-400 dark:text-slate-500 truncate">{d.deviceType} · {d.department}</span>
                    </span>
                    {saving && active ? <Loader2 className="w-3 h-3 animate-spin flex-shrink-0" /> : null}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default MedicalDeviceTagDropdown;
