// Named, localStorage-persisted filter presets, scoped per panel via a
// distinct storageKey. Generic over T so each caller keeps its own
// type-safe preset payload.
import { useCallback, useEffect, useState } from 'react';

export interface SavedView<T> {
  name: string;
  filters: T;
}

export function useSavedViews<T>(storageKey: string) {
  const [views, setViews] = useState<SavedView<T>[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) setViews(JSON.parse(raw));
    } catch {
      // Corrupt/foreign localStorage value — start empty rather than throwing.
    }
  }, [storageKey]);

  const persist = useCallback(
    (next: SavedView<T>[]) => {
      setViews(next);
      try {
        localStorage.setItem(storageKey, JSON.stringify(next));
      } catch {
        // Storage full or unavailable (private browsing) — the view still
        // works for this session, it just won't survive a reload.
      }
    },
    [storageKey]
  );

  const saveView = useCallback(
    (name: string, filters: T) => {
      const trimmed = name.trim();
      if (!trimmed) return;
      persist([...views.filter((v) => v.name !== trimmed), { name: trimmed, filters }]);
    },
    [views, persist]
  );

  const deleteView = useCallback(
    (name: string) => {
      persist(views.filter((v) => v.name !== name));
    },
    [views, persist]
  );

  return { views, saveView, deleteView };
}
