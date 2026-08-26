// Ported from life-critical-orchestration/frontend/src/components/PendingApprovalTray.jsx —
// horizontal strip of assets currently awaiting clinician approval. Uses MediSIEM's
// own /pending-approvals proxy (already dedupes by asset + excludes resolved
// decisions server-side) rather than re-deriving it client-side from the full audit
// log, but renders identically to the original.
import React, { useCallback, useEffect, useState } from 'react';
import { apiGetPendingApprovals } from '../../../services/lifeCriticalApi';
import type { LifeCriticalDecisionItem } from '../../../services/lifeCriticalApi';

const SocPendingApprovalTray: React.FC<{
  token: string;
  refreshKey?: string;
  onSelectItem: (item: LifeCriticalDecisionItem) => void;
}> = ({ token, refreshKey, onSelectItem }) => {
  const [pending, setPending] = useState<LifeCriticalDecisionItem[]>([]);

  const reload = useCallback(async () => {
    try {
      const { pending: p } = await apiGetPendingApprovals(token);
      const sorted = [...p].sort((a, b) => new Date(b.decision.decided_at).getTime() - new Date(a.decision.decided_at).getTime());
      setPending(sorted);
    } catch {
      setPending([]);
    }
  }, [token]);

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, refreshKey]);

  if (pending.length === 0) return null;

  return (
    <div className="border-b border-tier-3 bg-tier-3/10 px-6 py-2">
      <div className="flex items-center gap-3">
        <span className="text-tier-3 text-[10px] uppercase tracking-wider font-bold shrink-0">Pending Clinician Approval</span>
        <span className="text-soc-muted text-xs shrink-0">
          {pending.length} {pending.length === 1 ? 'asset' : 'assets'}
        </span>

        <div className="flex gap-2 overflow-x-auto">
          {pending.map((item) => (
            <button
              key={item.decision.decision_id}
              type="button"
              onClick={() => onSelectItem(item)}
              className="border border-tier-3 bg-soc-panel hover:bg-soc-panel/70 rounded px-3 py-1.5 shrink-0 text-left transition-colors cursor-pointer"
            >
              <div className="flex items-baseline gap-2">
                <span className="font-mono font-bold text-soc-text text-xs">{item.decision.asset_id}</span>
                <span className="text-soc-muted text-[10px]">→ {item.decision.proposed_action_if_approved || 'isolate_host'}</span>
              </div>
              <div className="text-soc-muted text-[10px] font-mono">in monitored_mode • click to review</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SocPendingApprovalTray;
