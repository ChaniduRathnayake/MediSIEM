// Ctrl/Cmd+K quick-jump — tab navigation plus a handful of global actions.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Search, CornerDownLeft, ArrowUp, ArrowDown } from 'lucide-react';

export interface CommandPaletteItem {
  id: string;
  label: string;
  hint?: string;
  icon?: React.ReactNode;
  run: () => void;
}

const CommandPalette: React.FC<{ open: boolean; onClose: () => void; items: CommandPaletteItem[] }> = ({ open, onClose, items }) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => it.label.toLowerCase().includes(q) || it.hint?.toLowerCase().includes(q));
  }, [items, query]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    if (activeIndex >= filtered.length) setActiveIndex(filtered.length > 0 ? filtered.length - 1 : 0);
  }, [filtered.length, activeIndex]);

  if (!open) return null;

  const runActive = () => {
    const item = filtered[activeIndex];
    if (item) { item.run(); onClose(); }
  };

  return (
    <div className="fixed inset-0 z-[200] flex items-start justify-center pt-[15vh] px-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-lg rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          <Search className="w-4 h-4 text-slate-400 dark:text-slate-500 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIndex((i) => Math.min(filtered.length - 1, i + 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIndex((i) => Math.max(0, i - 1)); }
              else if (e.key === 'Enter') { e.preventDefault(); runActive(); }
              else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
            }}
            placeholder="Jump to a tab or run a command…"
            className="flex-1 bg-transparent text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none"
          />
          <kbd className="flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded border border-slate-300 dark:border-slate-700 text-slate-400 dark:text-slate-500">Esc</kbd>
        </div>
        <div className="max-h-80 overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-6">No matches.</p>
          ) : (
            filtered.map((it, i) => (
              <button
                key={it.id}
                onMouseEnter={() => setActiveIndex(i)}
                onClick={() => { it.run(); onClose(); }}
                className={`w-full flex items-center gap-2.5 px-4 py-2 text-left text-sm transition-colors ${
                  i === activeIndex ? 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300' : 'text-slate-700 dark:text-slate-300'
                }`}
              >
                {it.icon}
                <span className="flex-1 truncate">{it.label}</span>
                {it.hint && <span className="text-[11px] text-slate-400 dark:text-slate-500 flex-shrink-0">{it.hint}</span>}
              </button>
            ))
          )}
        </div>
        <div className="flex items-center gap-3 px-4 py-2 border-t border-slate-200 dark:border-slate-800 text-[11px] text-slate-400 dark:text-slate-500">
          <span className="flex items-center gap-1"><ArrowUp className="w-3 h-3" /><ArrowDown className="w-3 h-3" /> navigate</span>
          <span className="flex items-center gap-1"><CornerDownLeft className="w-3 h-3" /> select</span>
        </div>
      </div>
    </div>
  );
};

export default CommandPalette;
