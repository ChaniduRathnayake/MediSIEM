// Ported from life-critical-orchestration/frontend/src/App.jsx — the standalone
// "Life-Critical SOC Console" UI, rehomed as MediSIEM's Playbooks tab content.
// Data comes through MediSIEM's authenticated proxy (backend/routes/lifeCriticalOrchestration.js)
// instead of hitting the engine/:8000 and sim/:8002 directly — same engine, same
// contract, just routed through MediSIEM's own auth like every other tab.
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Radio, WifiOff } from 'lucide-react';
import {
  apiGetLifeCriticalStatus, apiGetDecisionsHistory,
} from '../../../services/lifeCriticalApi';
import type { LifeCriticalDecision, LifeCriticalDecisionItem } from '../../../services/lifeCriticalApi';
import type { StubAlert } from './socTypes';
import SocAlertFeed from './SocAlertFeed';
import SocDecisionDetail from './SocDecisionDetail';
import SocPendingApprovalTray from './SocPendingApprovalTray';
import SocAuditTimeline from './SocAuditTimeline';

// The original standalone app used 3000ms — fine for a lone app with only
// these two endpoints on its own server. Embedded in MediSIEM, this shares
// a single global rate limit (300 req/15min across ALL of /api/*, see
// backend/server.js) with every other panel/poll in the whole dashboard.
// Two separate 3s intervals alone would be ~600 req/15min — well over
// budget by itself. 10s, combined into one tick below, keeps this console's
// footprint modest.
const LIVE_POLL_INTERVAL_MS = 10000;

function liveItemToStubAlert(item: LifeCriticalDecisionItem): StubAlert {
  const a = item.alert;
  return {
    alert_id: a.alert_id,
    timestamp: a.timestamp,
    source: { siem: 'wazuh', ...a.source },
    threat: a.threat || {},
    asset: { asset_id: a.asset?.asset_id || item.decision.asset_id, ...a.asset },
    clinical_context: a.clinical_context || {},
    _live: true,
    _liveDecision: item.decision,
    _expectedTier: item.decision.tier,
    _sortTimestamp: item.decision.decided_at || a.timestamp || '',
  };
}

function fingerprint(a: StubAlert): string {
  return [
    a.asset?.asset_id || '',
    a.source?.rule_description || '',
    a.threat?.cas_score ?? '',
    a.clinical_context?.criticality_score ?? '',
    a.threat?.category || '',
    a._expectedTier ?? '',
  ].join('|');
}

type EngineStatus = 'checking' | 'online' | 'offline' | 'unknown';

const STATUS_LABEL: Record<EngineStatus, string> = {
  checking: 'checking',
  online: 'online',
  // Distinguished from 'offline' deliberately — this is "the engine itself
  // reported unreachable" (the backend's own /status check succeeded and
  // said engineReachable:false), not the same as failing to even ask.
  offline: 'offline',
  // The status *request itself* failed — auth expired, rate-limited, a
  // network blip — never conflate this with "the engine is down": the
  // engine could be perfectly healthy while this session just can't
  // currently reach MediSIEM's own backend to ask it.
  unknown: 'unknown',
};

const SocHeaderBar: React.FC<{ engineStatus: EngineStatus; statusDetail?: string | null }> = ({ engineStatus, statusDetail }) => {
  const statusColor = engineStatus === 'online' ? 'text-tier-1' : engineStatus === 'offline' ? 'text-tier-3' : 'text-soc-muted';
  return (
    <header className="border-b border-soc-border bg-soc-panel px-6 py-3 flex items-center justify-between">
      <div className="flex items-baseline gap-3">
        <h1 className="text-soc-accent text-lg font-bold">Life-Critical SOC Console</h1>
        <span className="text-soc-muted text-xs">R26-CS-008 • PP1</span>
      </div>
      <div className="flex items-center gap-2 text-xs" title={statusDetail || undefined}>
        {engineStatus === 'online' ? <Radio className="w-3.5 h-3.5 text-tier-1" /> : <WifiOff className="w-3.5 h-3.5 text-tier-3" />}
        <span className="text-soc-muted">engine:</span>
        <span className={`${statusColor} font-bold uppercase`}>{STATUS_LABEL[engineStatus]}</span>
      </div>
    </header>
  );
};

const SocConsole: React.FC<{ token: string }> = ({ token }) => {
  const [engineStatus, setEngineStatus] = useState<EngineStatus>('checking');
  const [statusDetail, setStatusDetail] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<StubAlert | null>(null);
  const [decision, setDecision] = useState<LifeCriticalDecision | null>(null);
  const [decideError, setDecideError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [liveItems, setLiveItems] = useState<LifeCriticalDecisionItem[]>([]);
  const [trayRefreshKey, setTrayRefreshKey] = useState(0);

  // Combined into a single tick (was two separate 3s intervals) — halves the
  // request volume for the same information, see the interval comment above.
  const refresh = useCallback(async () => {
    try {
      const s = await apiGetLifeCriticalStatus(token);
      setEngineStatus(s.engineReachable ? 'online' : 'offline');
      setStatusDetail(s.engineReachable ? null : s.error || 'Engine reported unreachable.');
    } catch (err) {
      // The status *request* failed (auth expired, rate-limited, network
      // blip) — this says nothing about whether the engine itself is up.
      // Conflating this with 'offline' is exactly the bug that made a
      // healthy engine look down during a transient MediSIEM-side hiccup.
      setEngineStatus('unknown');
      setStatusDetail(err instanceof Error ? err.message : 'Could not reach MediSIEM\'s backend to check.');
    }
    try {
      // Durable history (backend's SoarAction mirror), not the engine's own
      // ephemeral ring buffer — see apiGetDecisionsHistory's doc comment for
      // why: the ring buffer resets on an engine restart and never included
      // decisions for dedup-folded repeat alerts in the first place.
      const { items } = await apiGetDecisionsHistory(token, 200);
      setLiveItems(items);
    } catch {
      // Engine offline / proxy unreachable / rate-limited — status badge above already covers this.
    }
  }, [token]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, LIVE_POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  // Every durable decision from apiGetDecisionsHistory, full stop — this used
  // to also filter out any item without a numeric cas_score (a leftover from
  // when this list could include life-critical-orchestration's bundled demo
  // stubs, which never carried one). Those stubs never reach this endpoint —
  // it's exclusively SoarAction's own history — so that filter was instead
  // silently hiding real decisions whose alert payload predates the
  // alertSnapshot field or has no matching AlertLog row for a CAS score.
  // Sorted tier desc / cc desc / cas desc / newest first. Adapted from
  // App.jsx's feedAlerts useMemo.
  const feedAlerts = useMemo<StubAlert[]>(() => {
    const taggedLive = liveItems.map(liveItemToStubAlert);

    const seen = new Map<string, StubAlert>();
    for (const item of taggedLive) {
      const key = fingerprint(item);
      if (!seen.has(key)) seen.set(key, item);
    }
    const deduped = Array.from(seen.values());

    const effectiveCC = (a: StubAlert) => a._liveDecision?.effective_criticality_score ?? a.clinical_context?.criticality_score ?? -1;

    deduped.sort((a, b) => {
      const tierA = a._expectedTier ?? 0;
      const tierB = b._expectedTier ?? 0;
      if (tierB !== tierA) return tierB - tierA;
      const ccA = effectiveCC(a);
      const ccB = effectiveCC(b);
      if (ccB !== ccA) return ccB - ccA;
      const casA = a.threat?.cas_score ?? -1;
      const casB = b.threat?.cas_score ?? -1;
      if (casB !== casA) return casB - casA;
      return (b._sortTimestamp || '').localeCompare(a._sortTimestamp || '');
    });

    return deduped;
  }, [liveItems]);

  // feedAlerts is built entirely from liveItemToStubAlert, so every entry has
  // _liveDecision by construction (cas_score may still be missing for older
  // history — see the feedAlerts comment above) — this always has a decision
  // on hand already; no on-demand /decide classification needed anymore.
  function handleSelectAlert(alert: StubAlert) {
    setSelectedAlert(alert);
    setDecideError(null);
    setDecision(alert._liveDecision ?? null);
    setBusy(false);
  }

  function handleSelectPendingItem(item: LifeCriticalDecisionItem) {
    setSelectedAlert(liveItemToStubAlert(item));
    setDecision(item.decision);
    setDecideError(null);
    setBusy(false);
  }

  return (
    <div className="h-[calc(100vh-4rem)] min-h-[600px] flex flex-col font-mono bg-soc-bg text-soc-text rounded-xl overflow-hidden border border-soc-border">
      <SocHeaderBar engineStatus={engineStatus} statusDetail={statusDetail} />
      <SocPendingApprovalTray token={token} refreshKey={decision?.decision_id} onSelectItem={handleSelectPendingItem} />

      <main className="flex-1 grid grid-cols-3 gap-px bg-soc-border overflow-hidden">
        <section className="bg-soc-bg overflow-y-auto">
          <div className="px-4 py-3 border-b border-soc-border sticky top-0 bg-soc-bg z-10">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">
              Alert Feed
              <span className="ml-2 text-soc-muted normal-case">
                ({feedAlerts.length} decisions)
              </span>
            </h2>
          </div>
          <SocAlertFeed alerts={feedAlerts} selectedId={selectedAlert?.alert_id} onSelect={handleSelectAlert} busy={busy} />
        </section>

        <section className="col-span-2 bg-soc-bg overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-soc-border">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">Decision Detail</h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            <SocDecisionDetail
              token={token}
              alert={selectedAlert}
              decision={decision}
              busy={busy}
              error={decideError}
              onResolved={() => setTrayRefreshKey((k) => k + 1)}
            />
          </div>

          <div className="px-4 py-3 border-t border-b border-soc-border">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">Audit Timeline</h2>
          </div>
          <div className="p-4 max-h-80 overflow-y-auto">
            <SocAuditTimeline token={token} refreshKey={`${decision?.decision_id}-${trayRefreshKey}`} />
          </div>
        </section>
      </main>
    </div>
  );
};

export default SocConsole;
