// Renders /audit entries newest-first plus a 'Verify chain' button.
// The audit log entries are records of Decision objects appended over time.

import { useEffect, useState, useCallback } from "react";
import { getAuditLog, verifyAuditChain } from "../api/engine";

const tierBadge = {
  1: "bg-tier-1 text-black",
  2: "bg-tier-2 text-black",
  3: "bg-tier-3 text-black",
};

function shortId(id) {
  if (!id) return "—";
  // dec-<uuid> → dec-<first8>
  const parts = id.split("-");
  if (parts.length < 2) return id;
  return `${parts[0]}-${parts[1].slice(0, 8)}`;
}

// Small button that shows a shortened ID, the full ID on hover (browser tooltip),
// and copies the full ID to the clipboard on click. Flashes "copied" briefly
// so the user knows it worked. Falls back gracefully if the clipboard API
// isn't available (e.g. on http:// without a secure context).
function CopyableId({ id }) {
  const [copied, setCopied] = useState(false);

  if (!id) return <span className="text-soc-muted">—</span>;

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API not available — silently no-op. The hover tooltip
      // still shows the full ID so the user can select-and-copy manually.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={`${id}\n(click to copy)`}
      className="font-mono text-soc-muted hover:text-soc-accent transition-colors cursor-pointer"
    >
      {copied ? (
        <span className="text-tier-1">copied ✓</span>
      ) : (
        shortId(id)
      )}
    </button>
  );
}

function formatTime(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
  } catch {
    return iso;
  }
}

export default function AuditTimeline({ refreshKey }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [verifyState, setVerifyState] = useState(null); // null | "checking" | {ok, error}

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const log = await getAuditLog();
      setEntries(log);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload, refreshKey]);

  async function handleVerify() {
    setVerifyState("checking");
    try {
      const result = await verifyAuditChain();
      setVerifyState(result);
    } catch (err) {
      setVerifyState({ ok: false, error: err.message });
    }
  }

  // Newest entries at the top — log is appended in chronological order.
  const reversed = [...entries].reverse();

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <span className="text-soc-muted text-xs">
          {entries.length} {entries.length === 1 ? "entry" : "entries"}
        </span>

        <button
          type="button"
          onClick={handleVerify}
          className="text-xs px-2 py-1 border border-soc-border bg-soc-panel hover:bg-soc-panel/70 rounded text-soc-text"
        >
          Verify chain
        </button>

        <button
          type="button"
          onClick={reload}
          className="text-xs px-2 py-1 border border-soc-border bg-soc-panel hover:bg-soc-panel/70 rounded text-soc-text"
        >
          Refresh
        </button>

        {verifyState === "checking" && (
          <span className="text-soc-muted text-xs">checking…</span>
        )}
        {verifyState && verifyState !== "checking" && verifyState.ok && (
          <span className="text-tier-1 text-xs font-bold">CHAIN OK</span>
        )}
        {verifyState && verifyState !== "checking" && !verifyState.ok && (
          <span className="text-tier-3 text-xs font-bold">
            CHAIN BROKEN: {verifyState.error}
          </span>
        )}
      </div>

      {loading && entries.length === 0 && (
        <p className="text-soc-muted text-xs">Loading audit log…</p>
      )}
      {error && <p className="text-tier-3 text-xs">Error: {error}</p>}
      {!loading && !error && entries.length === 0 && (
        <p className="text-soc-muted text-xs">
          Audit log is empty. Classify an alert to populate it.
        </p>
      )}

      {entries.length > 0 && (
        <div className="border border-soc-border rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-soc-panel">
              <tr className="text-soc-muted text-left">
                <th className="px-3 py-2 font-normal">Time</th>
                <th className="px-3 py-2 font-normal">Tier</th>
                <th className="px-3 py-2 font-normal">Action</th>
                <th className="px-3 py-2 font-normal">Asset</th>
                <th className="px-3 py-2 font-normal">Alert</th>
                <th className="px-3 py-2 font-normal">Decision ID</th>
              </tr>
            </thead>
            <tbody>
              {reversed.map((entry, idx) => {
                const d = entry.decision || entry;
                return (
                  <tr
                    key={d.decision_id || idx}
                    className="border-t border-soc-border hover:bg-soc-panel/40"
                  >
                    <td className="px-3 py-2 font-mono text-soc-muted">
                      {formatTime(d.decided_at)}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`${tierBadge[d.tier] || "bg-soc-muted"} px-1.5 py-0.5 rounded text-[10px] font-bold`}
                      >
                        T{d.tier}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-soc-accent">
                      {d.action}
                    </td>
                    <td className="px-3 py-2 font-mono text-soc-text">
                      {d.asset_id}
                    </td>
                    <td className="px-3 py-2 font-mono text-soc-muted">
                      {d.alert_id}
                    </td>
                    <td className="px-3 py-2 font-mono text-soc-muted">
                      <CopyableId id={d.decision_id} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}