// Ported from life-critical-orchestration/frontend/src/components/AuditTimeline.jsx —
// renders the engine's durable hash-chained audit log newest-first, plus a
// "Verify chain" button.
import React, { useCallback, useEffect, useState } from 'react';
import { apiGetAuditLog, apiVerifyAuditChain } from '../../../services/lifeCriticalApi';
import type { AuditEntry } from '../../../services/lifeCriticalApi';

const tierBadge: Record<number, string> = {
  1: 'bg-tier-1 text-black',
  2: 'bg-tier-2 text-black',
  3: 'bg-tier-3 text-black',
};

function shortId(id?: string): string {
  if (!id) return '—';
  const parts = id.split('-');
  if (parts.length < 2) return id;
  return `${parts[0]}-${parts[1].slice(0, 8)}`;
}

const CopyableId: React.FC<{ id?: string }> = ({ id }) => {
  const [copied, setCopied] = useState(false);
  if (!id) return <span className="text-soc-muted">—</span>;

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(id!);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable — the hover tooltip still shows the full id.
    }
  }

  return (
    <button type="button" onClick={handleCopy} title={`${id}\n(click to copy)`} className="font-mono text-soc-muted hover:text-soc-accent transition-colors cursor-pointer">
      {copied ? <span className="text-tier-1">copied ✓</span> : shortId(id)}
    </button>
  );
};

function formatTime(iso?: string): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  } catch {
    return iso;
  }
}

const SocAuditTimeline: React.FC<{ token: string; refreshKey?: string }> = ({ token, refreshKey }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verifyState, setVerifyState] = useState<null | 'checking' | { ok: boolean; error: string | null }>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { entries: log } = await apiGetAuditLog(token);
      setEntries(log);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, refreshKey]);

  async function handleVerify() {
    setVerifyState('checking');
    try {
      const result = await apiVerifyAuditChain(token);
      setVerifyState(result);
    } catch (err) {
      setVerifyState({ ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  }

  const reversed = [...entries].reverse();

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <span className="text-soc-muted text-xs">
          {entries.length} {entries.length === 1 ? 'entry' : 'entries'}
        </span>
        <button type="button" onClick={handleVerify} className="text-xs px-2 py-1 border border-soc-border bg-soc-panel hover:bg-soc-panel/70 rounded text-soc-text">
          Verify chain
        </button>
        <button type="button" onClick={reload} className="text-xs px-2 py-1 border border-soc-border bg-soc-panel hover:bg-soc-panel/70 rounded text-soc-text">
          Refresh
        </button>
        {verifyState === 'checking' && <span className="text-soc-muted text-xs">checking…</span>}
        {verifyState && verifyState !== 'checking' && verifyState.ok && <span className="text-tier-1 text-xs font-bold">CHAIN OK</span>}
        {verifyState && verifyState !== 'checking' && !verifyState.ok && (
          <span className="text-tier-3 text-xs font-bold">CHAIN BROKEN: {verifyState.error}</span>
        )}
      </div>

      {loading && entries.length === 0 && <p className="text-soc-muted text-xs">Loading audit log…</p>}
      {error && <p className="text-tier-3 text-xs">Error: {error}</p>}
      {!loading && !error && entries.length === 0 && <p className="text-soc-muted text-xs">Audit log is empty. Classify an alert to populate it.</p>}

      {entries.length > 0 && (
        <div className="border border-soc-border rounded overflow-hidden overflow-x-auto">
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
                const d = entry.decision;
                const f = entry.followup;
                return (
                  <tr key={`${d?.decision_id || f?.referenced_decision_id || 'entry'}-${idx}`} className="border-t border-soc-border hover:bg-soc-panel/40">
                    <td className="px-3 py-2 font-mono text-soc-muted whitespace-nowrap">{formatTime(d?.decided_at || f?.responded_at)}</td>
                    <td className="px-3 py-2">
                      {d ? (
                        <span className={`${tierBadge[d.tier] || 'bg-soc-muted'} px-1.5 py-0.5 rounded text-[10px] font-bold`}>T{d.tier}</span>
                      ) : (
                        <span className="bg-soc-muted px-1.5 py-0.5 rounded text-[10px] font-bold text-black">F</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-soc-accent">{d?.action || (f ? `${f.approved ? 'approved' : 'denied'} → ${f.final_action}` : '—')}</td>
                    <td className="px-3 py-2 font-mono text-soc-text">{d?.asset_id || f?.asset_id || '—'}</td>
                    <td className="px-3 py-2 font-mono text-soc-muted">{d?.alert_id || '—'}</td>
                    <td className="px-3 py-2 font-mono text-soc-muted">
                      <CopyableId id={d?.decision_id || f?.referenced_decision_id} />
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
};

export default SocAuditTimeline;
