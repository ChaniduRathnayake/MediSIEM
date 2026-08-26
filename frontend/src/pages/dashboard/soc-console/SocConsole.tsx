// Ported from life-critical-orchestration/frontend/src/App.jsx — the standalone
// "Life-Critical SOC Console" UI, rehomed as MediSIEM's Playbooks tab content.
// Data comes through MediSIEM's authenticated proxy (backend/routes/lifeCriticalOrchestration.js)
// instead of hitting the engine/:8000 and sim/:8002 directly — same engine, same
// contract, just routed through MediSIEM's own auth like every other tab.
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Radio, WifiOff } from 'lucide-react';
import {
  apiGetLifeCriticalStatus, apiGetRecentDecisions, apiDecideAlert,
} from '../../../services/lifeCriticalApi';
import type { LifeCriticalDecision, LifeCriticalDecisionItem } from '../../../services/lifeCriticalApi';
import type { StubAlert } from './socTypes';
import { socSampleAlerts } from './socSampleAlerts';
import SocAlertFeed from './SocAlertFeed';
import SocDecisionDetail from './SocDecisionDetail';
import SocPendingApprovalTray from './SocPendingApprovalTray';
import SocAuditTimeline from './SocAuditTimeline';

const LIVE_POLL_INTERVAL_MS = 3000;

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
    a.threat?.cvss_score ?? '',
    a.clinical_context?.criticality_score ?? '',
    a.threat?.category || '',
    a._expectedTier ?? '',
  ].join('|');
}

const SocHeaderBar: React.FC<{ engineStatus: 'checking' | 'online' | 'offline' }> = ({ engineStatus }) => {
  const statusColor = engineStatus === 'online' ? 'text-tier-1' : engineStatus === 'offline' ? 'text-tier-3' : 'text-soc-muted';
  return (
    <header className="border-b border-soc-border bg-soc-panel px-6 py-3 flex items-center justify-between">
      <div className="flex items-baseline gap-3">
        <h1 className="text-soc-accent text-lg font-bold">Life-Critical SOC Console</h1>
        <span className="text-soc-muted text-xs">R26-CS-008 • PP1</span>
      </div>
      <div className="flex items-center gap-2 text-xs">
        {engineStatus === 'online' ? <Radio className="w-3.5 h-3.5 text-tier-1" /> : <WifiOff className="w-3.5 h-3.5 text-tier-3" />}
        <span className="text-soc-muted">engine:</span>
        <span className={`${statusColor} font-bold uppercase`}>{engineStatus}</span>
      </div>
    </header>
  );
};

const SocConsole: React.FC<{ token: string }> = ({ token }) => {
  const [engineStatus, setEngineStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [selectedAlert, setSelectedAlert] = useState<StubAlert | null>(null);
  const [decision, setDecision] = useState<LifeCriticalDecision | null>(null);
  const [decideError, setDecideError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [liveItems, setLiveItems] = useState<LifeCriticalDecisionItem[]>([]);
  const [trayRefreshKey, setTrayRefreshKey] = useState(0);

  const checkStatus = useCallback(async () => {
    try {
      const s = await apiGetLifeCriticalStatus(token);
      setEngineStatus(s.engineReachable ? 'online' : 'offline');
    } catch {
      setEngineStatus('offline');
    }
  }, [token]);

  const pollLive = useCallback(async () => {
    try {
      const { items } = await apiGetRecentDecisions(token, 50);
      setLiveItems(items);
    } catch {
      // Engine offline / proxy unreachable — status banner already covers this.
    }
  }, [token]);

  useEffect(() => {
    checkStatus();
    pollLive();
    const statusId = setInterval(checkStatus, LIVE_POLL_INTERVAL_MS);
    const liveId = setInterval(pollLive, LIVE_POLL_INTERVAL_MS);
    return () => {
      clearInterval(statusId);
      clearInterval(liveId);
    };
  }, [checkStatus, pollLive]);

  // Merge live decisions with the bundled stubs — live wins on a fingerprint
  // collision, sorted tier desc / cc desc / cvss desc / newest first. Ported
  // from App.jsx's feedAlerts useMemo.
  const feedAlerts = useMemo<StubAlert[]>(() => {
    const taggedLive = liveItems.map(liveItemToStubAlert);
    const taggedStubs: StubAlert[] = socSampleAlerts.map((a) => ({ ...a, _sortTimestamp: a.timestamp || '' }));

    const merged = [...taggedLive, ...taggedStubs];
    const seen = new Map<string, StubAlert>();
    for (const item of merged) {
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
      const cvssA = a.threat?.cvss_score ?? -1;
      const cvssB = b.threat?.cvss_score ?? -1;
      if (cvssB !== cvssA) return cvssB - cvssA;
      return (b._sortTimestamp || '').localeCompare(a._sortTimestamp || '');
    });

    return deduped;
  }, [liveItems]);

  async function handleSelectAlert(alert: StubAlert) {
    setSelectedAlert(alert);
    setDecideError(null);

    if (alert._live && alert._liveDecision) {
      setDecision(alert._liveDecision);
      setBusy(false);
      return;
    }

    const prior = liveItems.find((x) => x.alert.alert_id === alert.alert_id);
    if (prior) {
      setDecision(prior.decision);
      setBusy(false);
      return;
    }

    setDecision(null);
    setBusy(true);
    try {
      const result = await apiDecideAlert(token, alert as unknown as Record<string, unknown>);
      setDecision(result);
    } catch (err) {
      setDecideError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  function handleSelectPendingItem(item: LifeCriticalDecisionItem) {
    setSelectedAlert(liveItemToStubAlert(item));
    setDecision(item.decision);
    setDecideError(null);
    setBusy(false);
  }

  return (
    <div className="h-[calc(100vh-4rem)] min-h-[600px] flex flex-col font-mono bg-soc-bg text-soc-text rounded-xl overflow-hidden border border-soc-border">
      <SocHeaderBar engineStatus={engineStatus} />
      <SocPendingApprovalTray token={token} refreshKey={decision?.decision_id} onSelectItem={handleSelectPendingItem} />

      <main className="flex-1 grid grid-cols-3 gap-px bg-soc-border overflow-hidden">
        <section className="bg-soc-bg overflow-y-auto">
          <div className="px-4 py-3 border-b border-soc-border sticky top-0 bg-soc-bg z-10">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">
              Alert Feed
              <span className="ml-2 text-soc-muted normal-case">
                ({feedAlerts.length}{liveItems.length > 0 ? ` • ${liveItems.length} live` : ' samples'})
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
