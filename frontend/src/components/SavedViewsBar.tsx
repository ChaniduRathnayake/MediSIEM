// Generic "save current filters as a named view" dropdown — used by both
// AlertsBrowser and AlertsPanel, which have different filter shapes.
import { useEffect, useRef, useState } from 'react';
import { Bookmark, Save, Trash2, ChevronDown } from 'lucide-react';
import { useSavedViews } from '../hooks/useSavedViews';

function SavedViewsBar<T>({
  storageKey,
  currentFilters,
  onApply,
}: {
  storageKey: string;
  currentFilters: T;
  onApply: (filters: T) => void;
}) {
  const { views, saveView, deleteView } = useSavedViews<T>(storageKey);
  const [open, setOpen] = useState(false);
  const [nameInput, setNameInput] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, [open]);

  const handleSave = () => {
    if (!nameInput.trim()) return;
    saveView(nameInput.trim(), currentFilters);
    setNameInput('');
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
      >
        <Bookmark className="w-3.5 h-3.5" /> Saved views{views.length > 0 && ` (${views.length})`}
        <ChevronDown className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1.5 w-64 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-xl shadow-2xl z-30 overflow-hidden">
          <div className="p-2 border-b border-slate-200 dark:border-slate-800 flex items-center gap-1.5">
            <input
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSave()}
              placeholder="Save current filters as…"
              className="flex-1 min-w-0 px-2 py-1.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500/60"
            />
            <button
              onClick={handleSave}
              disabled={!nameInput.trim()}
              className="flex-shrink-0 p-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 transition-colors"
              title="Save current filters"
            >
              <Save className="w-3.5 h-3.5" />
            </button>
          </div>
          {views.length === 0 ? (
            <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-4">No saved views yet.</p>
          ) : (
            <div className="max-h-56 overflow-y-auto">
              {views.map((v) => (
                <div key={v.name} className="flex items-center justify-between gap-2 px-3 py-2 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors">
                  <button onClick={() => { onApply(v.filters); setOpen(false); }} className="flex-1 min-w-0 text-left text-xs text-slate-700 dark:text-slate-300 truncate">
                    {v.name}
                  </button>
                  <button onClick={() => deleteView(v.name)} className="flex-shrink-0 text-slate-400 dark:text-slate-500 hover:text-red-500 transition-colors" title={`Delete "${v.name}"`}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default SavedViewsBar;
