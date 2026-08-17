// Reusable tag-assignment dropdown: current groups as pills, "+" opens a
// checklist with inline create-and-assign. Used by both device tables.
import React, { useEffect, useRef, useState } from 'react';
import { Tag, Plus, Loader2 } from 'lucide-react';
import type { DeviceGroup } from './deviceApi';

const GroupAssignDropdown: React.FC<{
  agentGroups: string[];
  allGroups: DeviceGroup[];
  onToggle: (groupName: string) => void;
  onCreateAndAssign: (name: string) => Promise<void>;
}> = ({ agentGroups, allGroups, onToggle, onCreateAndAssign }) => {
  const [open, setOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const handleCreate = async () => {
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      await onCreateAndAssign(name);
      setNewName('');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center gap-1 flex-wrap">
        {agentGroups.map((g) => (
          <span
            key={g}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs whitespace-nowrap"
          >
            <Tag className="w-2.5 h-2.5" /> {g}
          </span>
        ))}
        <button
          onClick={() => setOpen((o) => !o)}
          className="w-5 h-5 flex items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors flex-shrink-0"
          title="Assign groups"
        >
          <Plus className="w-3 h-3" />
        </button>
      </div>

      {open && (
        <div className="absolute z-40 top-full left-0 mt-1.5 w-56 rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 shadow-2xl p-2">
          {allGroups.length === 0 ? (
            <p className="text-xs text-slate-400 dark:text-slate-500 px-2 py-1.5">No groups yet — create one below.</p>
          ) : (
            <div className="max-h-40 overflow-y-auto space-y-0.5">
              {allGroups.map((g) => {
                const checked = agentGroups.includes(g.name);
                return (
                  <label key={g.id} className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer">
                    <input type="checkbox" checked={checked} onChange={() => onToggle(g.name)} className="accent-cyan-500" />
                    <span className="text-xs text-slate-200 truncate">{g.name}</span>
                  </label>
                );
              })}
            </div>
          )}
          <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-slate-200 dark:border-slate-800">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleCreate(); } }}
              placeholder="New group…"
              className="flex-1 min-w-0 px-2 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
            <button
              onClick={handleCreate}
              disabled={creating || !newName.trim()}
              className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 disabled:opacity-40 transition-colors flex-shrink-0"
            >
              {creating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default GroupAssignDropdown;
