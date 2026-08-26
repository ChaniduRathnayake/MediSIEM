// Horizontal strip showing assets currently pending clinician approval.
// Deduplicated by asset_id — only the most recent pending decision per
// asset is shown. The audit log retains the full history; this tray is
// the operational "who needs attention right now" view.
//
// PP1 scope: clicking a card surfaces the underlying alert + decision
// in the main detail pane. Full clinician approval interaction is
// PP2 scope.

import { useEffect, useState, useCallback } from "react";
import { getAuditLog, getClinicianDecisions } from "../api/engine";

export default function PendingApprovalTray({ refreshKey, onSelectDecision }) {
  const [pending, setPending] = useState([]);

  const reload = useCallback(async () => {
    try {
      const [log, resolutions] = await Promise.all([
        getAuditLog(),
        getClinicianDecisions().catch(() => ({})),
      ]);

      // Build a set of asset_ids that have a clinician response on file.
      // Once an asset has been responded to, it shouldn't appear in the
      // "pending" tray anymore — the response semantically applies to the
      // asset, not just to the specific decision_id (re-classification
      // mints fresh decision_ids but a clinician's call still stands).
      const resolvedAssets = new Set(
        Object.values(resolutions || {})
          .map((r) => r.asset_id)
          .filter(Boolean)
      );

      const awaiting = log
        .map((entry) => entry.decision || entry)
        .filter((d) => d.action === "await_clinician_approval")
        .filter((d) => !resolvedAssets.has(d.asset_id));

      // Dedupe by asset_id, keeping the most recent decision per asset.
      // The audit log is appended in chronological order, so the *last*
      // occurrence we encounter is the most recent.
      const byAsset = new Map();
      for (const d of awaiting) {
        byAsset.set(d.asset_id, d);
      }

      // Render newest-first so a fresh Tier 3 jumps to the front.
      const deduped = Array.from(byAsset.values()).sort(
        (a, b) => new Date(b.decided_at) - new Date(a.decided_at)
      );

      setPending(deduped);
    } catch {
      // Tray failure is non-critical — the header status indicator
      // already tells the analyst if the engine is unreachable.
      setPending([]);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload, refreshKey]);

  if (pending.length === 0) return null;

  return (
    <div className="border-b border-tier-3 bg-tier-3/10 px-6 py-2">
      <div className="flex items-center gap-3">
        <span className="text-tier-3 text-[10px] uppercase tracking-wider font-bold shrink-0">
          Pending Clinician Approval
        </span>
        <span className="text-soc-muted text-xs shrink-0">
          {pending.length} {pending.length === 1 ? "asset" : "assets"}
        </span>

        <div className="flex gap-2 overflow-x-auto">
          {pending.map((d) => (
            <button
              key={d.decision_id}
              type="button"
              onClick={() => onSelectDecision?.(d)}
              className="border border-tier-3 bg-soc-panel hover:bg-soc-panel/70 rounded px-3 py-1.5 shrink-0 text-left transition-colors cursor-pointer"
            >
              <div className="flex items-baseline gap-2">
                <span className="font-mono font-bold text-soc-text text-xs">
                  {d.asset_id}
                </span>
                <span className="text-soc-muted text-[10px]">
                  → {d.proposed_action_if_approved || "isolate_host"}
                </span>
              </div>
              <div className="text-soc-muted text-[10px] font-mono">
                in monitored_mode • PP2: clinician UI here
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}