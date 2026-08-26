// ShuffleActionsPanel — shows the playbook steps that fired for a decision.
//
// This component is the visible answer to "what did Shuffle actually do?"
// — pulls /actions/by-decision from the sim and renders each step as a
// timeline row. When the sim is offline it shows a quiet placeholder so
// the rest of the decision detail keeps working.

import { useEffect, useState } from "react";
import { getShuffleActionsByAsset, releaseEnforcement } from "../api/engine";

const POLL_INTERVAL_MS = 2000;
const MAX_POLL_ATTEMPTS = 4; // ~8 seconds total — enough for the engine
                             // background task to fire + sim to record.

const stepStyle = {
  // Monitored Mode steps — green-ish (asset is being protected non-disruptively)
  deep_telemetry: { color: "text-tier-1", label: "deep telemetry" },
  shadow_auditing: { color: "text-tier-1", label: "shadow auditing" },
  zero_interference: { color: "text-tier-1", label: "zero interference" },
  // Tier 3 dispatch — amber (waiting on human)
  clinician_dispatch: { color: "text-tier-2", label: "clinician dispatch" },
  // Phase B — colour by status
  clinician_response: { color: "text-soc-accent", label: "clinician response" },
  // Tier 1 enforcement marker
  log_only: { color: "text-soc-muted", label: "log only" },
  block_port: { color: "text-tier-2", label: "block port" },
  isolate_host: { color: "text-tier-3", label: "isolate host" },
  // Engine callback failure
  engine_callback: { color: "text-tier-3", label: "engine callback" },
  // Workstream C real enforcement (network-boundary isolation)
  network_isolation: { color: "text-tier-3", label: "network isolation" },
  network_restore: { color: "text-tier-1", label: "network restore" },
};

function formatTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour12: false });
  } catch {
    return iso;
  }
}

export default function ShuffleActionsPanel({ decisionId, assetId, refreshKey = 0 }) {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [simReachable, setSimReachable] = useState(true);
  const [releasing, setReleasing] = useState(false);
  const [releaseError, setReleaseError] = useState(null);

  // When decisionId changes, poll a few times to give the engine's
  // background push + the sim's workflow time to land. Stop polling once
  // we see at least one action OR after MAX_POLL_ATTEMPTS.
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
      const all = await getShuffleActionsByAsset(assetId);
      if (cancelled) return;

      // Filter to the most recent decision_id for this asset.
      // (Showing all-time history was too noisy — the audit timeline
      // below already shows the full chain. This panel answers
      // "what did the playbook do for THIS alert?")
      // Special case: clinician_response entries belong to whichever
      // decision_id they reference, so they ride along with that group.
      let result = [];
      if (all.length > 0) {
        // Find the most recent decision_id for this asset.
        const sortedByTime = [...all].sort((a, b) =>
          (b.logged_at || "").localeCompare(a.logged_at || "")
        );
        const latestDecisionId = sortedByTime[0].decision_id;

        // Show: (a) all actions for the latest decision_id, PLUS
        //       (b) the most recent clinician_response on this asset,
        //           even if it was recorded against a prior decision_id.
        // Re-classifying an alert mints a fresh decision_id, but a
        // clinician's response semantically applies to the asset.
        const latestGroup = all.filter(
          (e) => e.decision_id === latestDecisionId
        );

        const allResponses = all
          .filter((e) => e.step === "clinician_response")
          .sort((a, b) =>
            (b.logged_at || "").localeCompare(a.logged_at || "")
          );
        const latestResponse = allResponses[0];

        // Avoid double-adding if the response is already in latestGroup.
        const groupHasResponse = latestGroup.some(
          (e) => e.step === "clinician_response"
        );
        const merged =
          latestResponse && !groupHasResponse
            ? [...latestGroup, latestResponse]
            : latestGroup;

        result = merged.sort((a, b) =>
          (a.logged_at || "").localeCompare(b.logged_at || "")
        );
      }

      setActions(result);

      if (result.length > 0 || attempts >= MAX_POLL_ATTEMPTS) {
        setLoading(false);
        if (result.length === 0 && attempts >= MAX_POLL_ATTEMPTS) {
          // Final attempt produced nothing — assume the sim isn't running.
          setSimReachable(false);
        } else {
          setSimReachable(true);
        }
        return;
      }
      setTimeout(poll, POLL_INTERVAL_MS);
    }

    poll();
    return () => {
      cancelled = true;
    };
  }, [assetId, decisionId, refreshKey]);

  // Derive current isolation state from the enforcement steps recorded so
  // far: the most recent of network_isolation / network_restore wins. This
  // lets the SOC operator see — and undo — a real docker network cut
  // without needing a separate polling endpoint.
  const enforcementSteps = actions.filter(
    (e) => e.step === "network_isolation" || e.step === "network_restore"
  );
  const lastEnforcement = enforcementSteps[enforcementSteps.length - 1];
  const isIsolated =
    lastEnforcement?.step === "network_isolation" &&
    ["enforced", "already_isolated"].includes(lastEnforcement.status);
  const enforcementMode = lastEnforcement?.extra?.mode; // "real" | "simulated"

  async function handleRelease() {
    if (!assetId) return;
    setReleasing(true);
    setReleaseError(null);
    try {
      const result = await releaseEnforcement(assetId);
      if (result?.entry) {
        setActions((prev) => [...prev, result.entry]);
      }
    } catch (err) {
      setReleaseError(err.message || String(err));
    } finally {
      setReleasing(false);
    }
  }

  if (!decisionId) return null;

  if (loading && actions.length === 0) {
    return (
      <p className="text-soc-muted text-xs">Waiting for Shuffle actions…</p>
    );
  }

  if (actions.length === 0) {
    return (
      <p className="text-soc-muted text-xs">
        {simReachable
          ? "No Shuffle actions recorded for this decision yet."
          : "Shuffle sim not reachable on :8002. Start it to see playbook activity."}
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {isIsolated && (
        <div className="flex flex-wrap items-center gap-3 rounded border border-tier-3 bg-tier-3/10 px-3 py-2">
          <span className="text-tier-3 text-[10px] uppercase tracking-wider font-bold">
            Device isolated{enforcementMode === "real" ? " (real network cut)" : " (simulated)"}
          </span>
          <button
            type="button"
            disabled={releasing}
            onClick={handleRelease}
            className="ml-auto px-3 py-1 text-[10px] uppercase tracking-wider font-bold rounded border border-tier-1 text-tier-1 bg-tier-1/5 hover:bg-tier-1/15 disabled:opacity-40 disabled:cursor-not-allowed"
            title="Reconnect the device (docker network connect) and reset for the next demo run"
          >
            {releasing ? "Releasing…" : "Release / Reset Device"}
          </button>
        </div>
      )}
      {releaseError && (
        <p className="text-tier-3 text-xs">Release failed: {releaseError}</p>
      )}
      <ol className="space-y-2">
      {actions.map((entry, idx) => {
        const style = stepStyle[entry.step] || {
          color: "text-soc-text",
          label: entry.step,
        };
        return (
          <li
            key={`${entry.logged_at}-${idx}`}
            className="flex items-start gap-3 text-xs"
          >
            <span className="text-soc-muted font-mono shrink-0 w-16">
              {formatTime(entry.logged_at)}
            </span>
            <span
              className={`${style.color} font-bold uppercase tracking-wider shrink-0 w-32`}
            >
              {style.label}
            </span>
            <span className="text-soc-muted shrink-0 w-20 italic">
              {entry.status}
            </span>
            <span className="text-soc-text">{entry.detail}</span>
          </li>
        );
      })}
      </ol>
    </div>
  );
}
