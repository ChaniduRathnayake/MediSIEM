// Lightweight global keydown shortcuts, built directly on
// document.addEventListener (no hotkey library in this project). Attaches
// the listener once (the map is read from a ref) and ignores keystrokes
// while typing in a form field, except Escape.
import { useEffect, useRef } from 'react';

export type ShortcutMap = Record<string, (e: KeyboardEvent) => void>;

export function useKeyboardShortcuts(map: ShortcutMap, enabled = true) {
  const mapRef = useRef(map);
  mapRef.current = map;

  useEffect(() => {
    if (!enabled) return undefined;

    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isTyping =
        !!target &&
        (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable);
      if (isTyping && e.key !== 'Escape') return;

      const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      const fn = mapRef.current[key];
      if (fn) {
        e.preventDefault();
        fn(e);
      }
    };

    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [enabled]);
}
