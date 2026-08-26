// ClinicianDecisionPanel — SOC-side approve/deny override for Tier 3.
//
// As of PP2 Workstream C, the *real* clinician-facing interface is the
// standalone /clinician view (frontend/src/pages/ClinicianView.jsx) —
// a mobile-friendly page a clinician would actually use, decoupled from
// this SOC console. This panel remains here as a SOC-operator override /
// demo convenience (e.g. to drive the flow from one screen while
// screen-recording, or to unblock an asset if a clinician is unreachable)
// and posts to the exact same endpoint /clinician-decision does, so both
// paths trigger the same real enforcement action.
//
// Posts to the Shuffle sim's /clinician-decision endpoint, which records
// the playbook-side action AND calls back into the engine's audit log.
// Falls back to direct engine post if the sim is unreachable.

import { useState, useEffect } from "react";
import { submitClinicianDecision, getClinicianDecisions } from "../api/engine";

export default function ClinicianDecisionPanel({ decision, onResolved }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [existing, setExisting] = useState(null); // prior follow-up if any

  // On mount / when decision changes, check if a clinician already responded.
  useEffect(() => {
    if (!decision?.asset_id) return;
    let cancelled = false;
    getClinicianDecisions()
      .then((all) => {
        if (cancelled) return;
        // Look up the most recent follow-up for THIS ASSET, not this decision_id.
        // Each /decide call mints a fresh decision_id, but a clinician's
        // response semantically applies to the asset's current state.
        const forAsset = Object.values(all).filter(
          (f) => f.asset_id === decision.asset_id
        );
        // Sort by responded_at descending — pick the latest.
        forAsset.sort((a, b) =>
          (b.responded_at || "").localeCompare(a.responded_at || "")
        );
        setExisting(forAsset[0] || null);
      })
      .catch(() => {
        if (cancelled) return;
        setExisting(null);
      });
    return () => {
      cancelled = true;
    };
  }, [decision?.asset_id, decision?.decision_id]);

  if (!decision || decision.tier !== 3) return null;

  async function handleClick(approved) {
    setBusy(true);
    setError(null);
    try {
      const result = await submitClinicianDecision({
        decisionId: decision.decision_id,
        assetId: decision.asset_id,
        approved,
      });
      // Refresh existing-state from engine (canonical source).
      const all = await getClinicianDecisions();
      setExisting(all[decision.decision_id] || null);
      if (onResolved) onResolved(result);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  // Already resolved — show the outcome instead of the buttons.
  if (existing) {
    const approved = existing.approved;
    const labelClass = approved
      ? "text-tier-3 border-tier-3 bg-tier-3/10"
      : "text-tier-1 border-tier-1 bg-tier-1/10";
    return (
      <div className="mt-3 pt-3 border-t border-soc-border">
        <div className="text-[10px] uppercase tracking-wider text-soc-muted mb-2">
          Clinician response (recorded)
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span
            className={`${labelClass} px-2 py-0.5 rounded border font-bold uppercase tracking-wider`}
          >
            {approved ? "Approved" : "Denied"}
          </span>
          <span className="text-soc-muted">by</span>
          <span className="font-mono text-soc-text">
            {existing.clinician_id}
          </span>
          <span className="text-soc-muted">→ final action:</span>
          <span className="font-mono text-soc-accent">
            {existing.final_action}
          </span>
        </div>
      </div>
    );
  }

  // Unresolved — show the buttons.
  return (
    <div className="mt-3 pt-3 border-t border-soc-border">
      <div className="text-[10px] uppercase tracking-wider text-soc-muted mb-2">
        Clinician decision (SOC override / demo)
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => handleClick(true)}
          className="px-3 py-1.5 text-xs uppercase tracking-wider font-bold rounded border border-tier-3 text-tier-3 bg-tier-3/5 hover:bg-tier-3/15 disabled:opacity-40 disabled:cursor-not-allowed"
          title={`Escalate to ${decision.proposed_action_if_approved}`}
        >
          Approve → {decision.proposed_action_if_approved}
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => handleClick(false)}
          className="px-3 py-1.5 text-xs uppercase tracking-wider font-bold rounded border border-tier-1 text-tier-1 bg-tier-1/5 hover:bg-tier-1/15 disabled:opacity-40 disabled:cursor-not-allowed"
          title="Deny — asset stays in Monitored Mode (FR-06)"
        >
          Deny → stay in monitored_mode
        </button>
        {busy && <span className="text-soc-muted text-xs">recording…</span>}
      </div>
      {error && (
        <p className="mt-2 text-tier-3 text-xs">Error: {error}</p>
      )}
      <p className="mt-2 text-soc-muted text-[10px]">
        SOC override. The real clinician approval screen is /clinician —
        this control exists for demo convenience and as a fallback.
      </p>
    </div>
  );
}
