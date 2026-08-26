import { useEffect, useState, useMemo } from "react";
import { checkHealth, decide, getRecentAlerts } from "./api/engine";
import { sampleAlerts } from "./data/sampleAlerts";
import AlertFeed from "./components/AlertFeed";
import DecisionDetail from "./components/DecisionDetail";
import AuditTimeline from "./components/AuditTimeline";
import PendingApprovalTray from "./components/PendingApprovalTray";

const LIVE_POLL_INTERVAL_MS = 3000;

function HeaderBar({ engineStatus, liveMode, onToggleLive, liveCount }) {
  const statusColor =
    engineStatus === "online" ? "text-tier-1"
    : engineStatus === "offline" ? "text-tier-3"
    : "text-soc-muted";

  return (
    <header className="border-b border-soc-border bg-soc-panel px-6 py-3 flex items-center justify-between">
      <div className="flex items-baseline gap-3">
        <h1 className="text-soc-accent text-lg font-bold">
          Life-Critical SOC Console
        </h1>
        <span className="text-soc-muted text-xs">R26-CS-008 • PP1</span>
      </div>
      <div className="flex items-center gap-4 text-xs">
        <button
          type="button"
          onClick={onToggleLive}
          disabled={engineStatus !== "online"}
          className={[
            "px-2 py-1 rounded border text-[10px] uppercase tracking-wider font-bold transition-colors",
            liveMode
              ? "border-soc-accent text-soc-accent bg-soc-accent/10"
              : "border-soc-border text-soc-muted hover:text-soc-text",
            engineStatus !== "online" ? "opacity-40 cursor-not-allowed" : "cursor-pointer",
          ].join(" ")}
          title="Poll /alerts/recent for shim-injected alerts"
        >
          {liveMode ? `● Live${liveCount ? ` (${liveCount})` : ""}` : "○ Live"}
        </button>
        <span className="text-soc-muted">engine:</span>
        <span className={`${statusColor} font-bold uppercase`}>
          {engineStatus}
        </span>
      </div>
    </header>
  );
}

// Strip frontend-only fields before sending an alert to the engine.
function toEngineAlert(alert) {
  const { _expectedTier, _live, _liveDecision, ...rest } = alert;
  return rest;
}

// Infer a tier from a live alert's already-classified decision so the
// feed can colour-code it the same way as the stubs.
function inferTier(decision) {
  return decision?.tier ?? null;
}

function App() {
  const [engineStatus, setEngineStatus] = useState("checking");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [decision, setDecision] = useState(null);
  const [decideError, setDecideError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const [liveAlerts, setLiveAlerts] = useState([]); // [{alert, decision}, ...]

  useEffect(() => {
    checkHealth()
      .then(() => setEngineStatus("online"))
      .catch(() => setEngineStatus("offline"));

    // One-shot rehydration on mount: pull whatever's in the engine's
    // recent-alerts buffer so the feed matches the tray's view without
    // requiring the user to toggle live mode after a page reload.
    // Live polling (if enabled) takes over from here.
    getRecentAlerts(50)
      .then(setLiveAlerts)
      .catch(() => {
        // Engine offline / endpoint missing — silent. The health check
        // above already surfaces engine status; no need to double-flag it.
      });
  }, []);

  // Live polling — pulls /alerts/recent every few seconds while liveMode is on.
  useEffect(() => {
    if (!liveMode) return undefined;
    let cancelled = false;

    async function poll() {
      try {
        const items = await getRecentAlerts(50);
        if (!cancelled) setLiveAlerts(items);
      } catch {
        // Silent — engine may have just restarted; next tick will retry.
      }
    }

    poll(); // immediate fetch on enable
    const id = setInterval(poll, LIVE_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [liveMode]);

  // Merge live alerts with stub alerts for the feed.
  //
  // Dedupe rule: collapse entries that represent the **same scenario** —
  // i.e. same asset + same rule + same cc/cvss + same tier. Re-running the
  // demo produces fresh alert_ids for identical content, so dedupe-by-alert_id
  // (the previous behaviour) leaves visible duplicates. Content-fingerprint
  // dedupe collapses true repeats while preserving distinct scenarios on the
  // same asset (e.g. OR-ANAES-002 ransomware vs OR-ANAES-002 lateral movement).
  //
  // Live wins over stub on collision: a live alert carries a real decision,
  // so when a stub fingerprint matches a live one we drop the stub.
  //
  // Sort order: tier descending (T3 → T2 → T1 → unknown), then clinical
  // criticality descending, then cvss descending, then newest-first. This
  // surfaces the most patient-impactful alerts at the top of the feed,
  // matching the project's safety-first thesis.
  //
  // Live alerts persist in the feed even when liveMode is off — the toggle
  // controls polling intake, not display. Once an alert has arrived in this
  // session, it stays visible until the page reloads.
  const feedAlerts = useMemo(() => {
    // Tag live alerts with their decision for downstream rendering + click
    // handling, then merge with stubs.
    const taggedLive = liveAlerts.map(({ alert, decision }) => ({
      ...alert,
      _live: true,
      _liveDecision: decision,
      _expectedTier: inferTier(decision),
      // Carry through the engine's decided_at if available, so newest-first
      // tiebreakers within a tier reflect actual classification time.
      _sortTimestamp: decision?.decided_at || alert.timestamp || "",
    }));
    const taggedStubs = sampleAlerts.map((a) => ({
      ...a,
      _sortTimestamp: a.timestamp || "",
    }));

    // Content fingerprint: same scenario = same asset, rule, severity, tier.
    // Order matters — taggedLive comes first so live wins on fingerprint
    // collision when we walk in order.
    const merged = [...taggedLive, ...taggedStubs];
    const fingerprint = (a) => [
      a.asset?.asset_id || "",
      a.source?.rule_description || "",
      a.threat?.cvss_score ?? "",
      a.clinical_context?.criticality_score ?? "",
      a.threat?.category || "",
      a._expectedTier ?? "",
    ].join("|");

    const seen = new Map();
    for (const item of merged) {
      const key = fingerprint(item);
      if (!seen.has(key)) {
        seen.set(key, item);
      }
    }
    const deduped = Array.from(seen.values());

    // Sort: tier desc, cc desc, cvss desc, timestamp desc.
    //
    // For "cc desc" we prefer the decision's effective_criticality_score
    // (which the engine substitutes to 10 for fail-safe cases on unknown
    // assets) over the raw alert.clinical_context.criticality_score. That
    // way the safety-first principle is reflected in the feed order: an
    // unknown-asset alert that the engine treated as life-critical sorts
    // alongside known life-critical assets, not at the bottom.
    const effectiveCC = (a) =>
      a._liveDecision?.effective_criticality_score
      ?? a.clinical_context?.criticality_score
      ?? -1;

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

      // Newest first within the same tier/severity bucket.
      return (b._sortTimestamp || "").localeCompare(a._sortTimestamp || "");
    });

    return deduped;
  }, [liveAlerts]);

  async function handleSelectAlert(alert) {
    setSelectedAlert(alert);
    setDecideError(null);

    // Live alert path: decision already exists, just show it.
    if (alert._live && alert._liveDecision) {
      setDecision(alert._liveDecision);
      setBusy(false);
      return;
    }

    // Stub path: if this alert_id has already been classified in the
    // current session (it's in liveAlerts), just show that decision
    // instead of re-classifying. Re-classifying mints a fresh decision_id
    // each time, which orphans the prior playbook actions and clinician
    // responses on the dashboard.
    const prior = liveAlerts.find((x) => x.alert.alert_id === alert.alert_id);
    if (prior) {
      setDecision(prior.decision);
      setBusy(false);
      return;
    }

    // First-time classification.
    setDecision(null);
    setBusy(true);
    try {
      const result = await decide(toEngineAlert(alert));
      setDecision(result);
    } catch (err) {
      setDecideError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function handleSelectPending(historicalDecision) {
    // Look in live alerts first (more up-to-date), then stubs.
    const fromLive = liveAlerts.find(
      (x) => x.alert.alert_id === historicalDecision.alert_id
    );
    const matchingAlert =
      fromLive?.alert ||
      sampleAlerts.find((a) => a.alert_id === historicalDecision.alert_id) ||
      null;
    setSelectedAlert(matchingAlert);
    setDecision(historicalDecision);
    setDecideError(null);
    setBusy(false);
  }

  return (
    <div className="h-screen flex flex-col font-mono">
      <HeaderBar
        engineStatus={engineStatus}
        liveMode={liveMode}
        onToggleLive={() => setLiveMode((v) => !v)}
        liveCount={liveAlerts.length}
      />
      <PendingApprovalTray
        refreshKey={decision?.decision_id}
        onSelectDecision={handleSelectPending}
      />

      <main className="flex-1 grid grid-cols-3 gap-px bg-soc-border overflow-hidden">
        {/* Left: alert feed */}
        <section className="bg-soc-bg overflow-y-auto">
          <div className="px-4 py-3 border-b border-soc-border sticky top-0 bg-soc-bg">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">
              Alert Feed
              <span className="ml-2 text-soc-muted normal-case">
                ({feedAlerts.length}{liveAlerts.length > 0 ? ` • ${liveAlerts.length} live` : " samples"})
              </span>
            </h2>
          </div>
          <AlertFeed
            alerts={feedAlerts}
            selectedId={selectedAlert?.alert_id}
            onSelect={handleSelectAlert}
            busy={busy}
          />
        </section>

        {/* Right: decision detail (top) + audit timeline (bottom) */}
        <section className="col-span-2 bg-soc-bg overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-soc-border">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">
              Decision Detail
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4">
            <DecisionDetail
              alert={selectedAlert}
              decision={decision}
              busy={busy}
              error={decideError}
            />
          </div>

          <div className="px-4 py-3 border-t border-b border-soc-border">
            <h2 className="text-xs uppercase tracking-wider text-soc-muted">
              Audit Timeline
            </h2>
          </div>
          <div className="p-4 max-h-80 overflow-y-auto">
            <AuditTimeline refreshKey={decision?.decision_id} />
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;