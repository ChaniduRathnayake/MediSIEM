// Ported from life-critical-orchestration/frontend/src/components/ShuffleActionsPanel.jsx —
// shows the playbook steps Shuffle actually ran for this decision. Polls a few times
// after a decision changes to give the engine's background push + sim's workflow
// time to land, same as the original.
import React, { useEffect, useState } from 'react';
import { apiGetShuffleActions } from '../../../services/lifeCriticalApi';
import type { ShuffleAction } from '../../../services/lifeCriticalApi';

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 4;

const stepStyle: Record<string, { color: string; label: string }> = {
  deep_telemetry: { color: 'text-tier-1', label: 'deep telemetry' },
  shadow_auditing: { color: 'text-tier-1', label: 'shadow auditing' },
  zero_interference: { color: 'text-tier-1', label: 'zero interference' },
  clinician_dispatch: { color: 'text-tier-2', label: 'clinician dispatch' },
  clinician_push: { color: 'text-tier-2', label: 'clinician push' },
  clinician_response: { color: 'text-soc-accent', label: 'clinician response' },
  log_only: { color: 'text-soc-muted', label: 'log only' },
  block_port: { color: 'text-tier-2', label: 'block port' },
  isolate_host: { color: 'text-tier-3', label: 'isolate host' },
  throttle: { color: 'text-tier-2', label: 'throttle' },
  selective_block: { color: 'text-tier-2', label: 'selective block' },
  quarantine: { color: 'text-tier-3', label: 'quarantine' },
  engine_callback: { color: 'text-tier-3', label: 'engine callback' },
  network_isolation: { color: 'text-tier-3', label: 'network isolation' },
  network_restore: { color: 'text-tier-1', label: 'network restore' },
};

function formatTime(iso?: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleTimeString([], { hour12: false });
  } catch {
    return iso;
  }
}

const SocShuffleActionsPanel: React.FC<{ token: string; decisionId: string; assetId: string; refreshKey?: number }> = ({
  token,
  decisionId,
  assetId,
  refreshKey = 0,
}) => {
  const [actions, setActions] = useState<ShuffleAction[]>([]);
  const [loading, setLoading] = useState(false);
  const [simReachable, setSimReachable] = useState(true);

  useEffect(() => {
    if (!assetId) {
      setActions([]);
      return undefined;
    }

    let cancelled = false;
    let attempts = 0;
    setLoading(true);

    async function poll() {
      attempts += 1;
      const res = await apiGetShuffleActions(token, assetId).catch(() => ({ reachable: false, actions: [] as ShuffleAction[] }));
      if (cancelled) return;

      if (!res.reachable) {
        setActions([]);
        setSimReachable(false);
        setLoading(false);
        return;
      }

      const all = res.actions;
      let result: ShuffleAction[] = [];
      if (all.length > 0) {
        const sortedByTime = [...all].sort((a, b) => (b.logged_at || '').localeCompare(a.logged_at || ''));
        const latestDecisionId = sortedByTime[0].decision_id;
        const latestGroup = all.filter((e) => e.decision_id === latestDecisionId);
        const allResponses = all.filter((e) => e.step === 'clinician_response').sort((a, b) => (b.logged_at || '').localeCompare(a.logged_at || ''));
        const latestResponse = allResponses[0];
        const groupHasResponse = latestGroup.some((e) => e.step === 'clinician_response');
        const merged = latestResponse && !groupHasResponse ? [...latestGroup, latestResponse] : latestGroup;
        result = merged.sort((a, b) => (a.logged_at || '').localeCompare(b.logged_at || ''));
      }

      setActions(result);

      if (result.length > 0 || attempts >= MAX_POLL_ATTEMPTS) {
        setLoading(false);
        setSimReachable(!(result.length === 0 && attempts >= MAX_POLL_ATTEMPTS) || true);
        return;
      }
      setTimeout(poll, POLL_INTERVAL_MS);
    }

    poll();
    return () => {
      cancelled = true;
    };
  }, [token, assetId, decisionId, refreshKey]);

  if (!decisionId) return null;

  if (loading && actions.length === 0) {
    return <p className="text-soc-muted text-xs">Waiting for Shuffle actions…</p>;
  }

  if (actions.length === 0) {
    return (
      <p className="text-soc-muted text-xs">
        {simReachable ? 'No Shuffle actions recorded for this decision yet.' : 'Shuffle sim not reachable on :8002. Start it to see playbook activity.'}
      </p>
    );
  }

  return (
    <ol className="space-y-2">
      {actions.map((entry, idx) => {
        const style = stepStyle[entry.step] || { color: 'text-soc-text', label: entry.step };
        return (
          <li key={`${entry.logged_at}-${idx}`} className="flex items-start gap-3 text-xs">
            <span className="text-soc-muted font-mono shrink-0 w-16">{formatTime(entry.logged_at)}</span>
            <span className={`${style.color} font-bold uppercase tracking-wider shrink-0 w-32`}>{style.label}</span>
            <span className="text-soc-muted shrink-0 w-20 italic">{entry.status}</span>
            <span className="text-soc-text">{entry.detail}</span>
          </li>
        );
      })}
    </ol>
  );
};

export default SocShuffleActionsPanel;
