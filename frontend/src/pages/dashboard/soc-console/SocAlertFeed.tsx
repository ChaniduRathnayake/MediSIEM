// Ported from life-critical-orchestration/frontend/src/components/AlertFeed.jsx —
// left-column list of stub + live alerts. Clicking one fires onSelect.
import React, { useMemo, useState } from 'react';
import type { StubAlert } from './socTypes';

const tierColor: Record<number, string> = {
  1: 'border-l-tier-1',
  2: 'border-l-tier-2',
  3: 'border-l-tier-3',
};

const SocAlertFeed: React.FC<{
  alerts: StubAlert[];
  selectedId?: string;
  onSelect: (alert: StubAlert) => void;
  busy: boolean;
}> = ({ alerts, selectedId, onSelect, busy }) => {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter((a) => {
      const haystack = [
        a.alert_id,
        a.asset?.asset_id,
        a.asset?.hostname,
        a.asset?.department,
        a.asset?.device_category,
        a.source?.rule_description,
        a.threat?.category,
        a._liveDecision?.decision_id,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [alerts, query]);

  return (
    <>
      <div className="px-4 py-2 border-b border-soc-border bg-soc-bg">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search asset, alert, rule…"
          className="w-full bg-soc-panel border border-soc-border rounded px-2 py-1 text-xs text-soc-text placeholder:text-soc-muted focus:outline-none focus:border-soc-accent"
        />
        {query && (
          <div className="text-[10px] text-soc-muted mt-1">
            {filtered.length} of {alerts.length} shown
          </div>
        )}
      </div>

      <ul className="divide-y divide-soc-border">
        {filtered.length === 0 && (
          <li className="px-4 py-3 text-soc-muted text-xs">No alerts match.</li>
        )}
        {filtered.map((alert) => {
          const isSelected = alert.alert_id === selectedId;
          const accent = tierColor[alert._expectedTier ?? 0] || 'border-l-soc-muted';

          return (
            <li key={alert.alert_id}>
              <button
                type="button"
                disabled={busy}
                onClick={() => onSelect(alert)}
                className={[
                  'w-full text-left px-4 py-3 border-l-4 transition-colors',
                  accent,
                  isSelected ? 'bg-soc-panel' : 'hover:bg-soc-panel/50',
                  busy ? 'opacity-50 cursor-wait' : 'cursor-pointer',
                ].join(' ')}
              >
                <div className="flex items-baseline justify-between gap-2 mb-1">
                  <span className="text-soc-text text-sm font-bold truncate">{alert.asset.asset_id}</span>
                  <span className="flex items-center gap-1 shrink-0">
                    <span className="text-soc-muted text-[10px] uppercase tracking-wider">
                      T{alert._expectedTier ?? '?'}
                    </span>
                  </span>
                </div>
                <div className="text-soc-muted text-xs truncate">
                  {alert.source.rule_description || alert.threat.category || '—'}
                </div>
                <div className="flex gap-3 text-[10px] text-soc-muted mt-1">
                  <span>cc={alert.clinical_context.criticality_score ?? '?'}</span>
                  <span>cas={alert.threat.cas_score ?? '?'}</span>
                  <span className="truncate">{alert.asset.department || ''}</span>
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </>
  );
};

export default SocAlertFeed;
