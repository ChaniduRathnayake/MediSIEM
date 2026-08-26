// Ported from life-critical-orchestration/frontend/src/components/ClinicianDecisionPanel.jsx —
// SOC-side approve/deny override for Tier 3. Posts through MediSIEM's authenticated
// proxy (backend/routes/lifeCriticalOrchestration.js's /clinician-decision), which
// forwards to the same engine endpoint the real /clinician view would call.
import React, { useEffect, useState } from 'react';
import { apiGetClinicianDecisions, apiSubmitClinicianDecision } from '../../../services/lifeCriticalApi';
import type { LifeCriticalDecision, ClinicianFollowup } from '../../../services/lifeCriticalApi';

const SocClinicianDecisionPanel: React.FC<{
  token: string;
  decision: LifeCriticalDecision;
  onResolved: () => void;
}> = ({ token, decision, onResolved }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [existing, setExisting] = useState<ClinicianFollowup | null>(null);

  useEffect(() => {
    if (!decision?.asset_id) return;
    let cancelled = false;
    apiGetClinicianDecisions(token)
      .then(({ byDecisionId }) => {
        if (cancelled) return;
        const forAsset = Object.values(byDecisionId).filter((f) => f.asset_id === decision.asset_id);
        forAsset.sort((a, b) => (b.responded_at || '').localeCompare(a.responded_at || ''));
        setExisting(forAsset[0] || null);
      })
      .catch(() => {
        if (!cancelled) setExisting(null);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, decision?.asset_id, decision?.decision_id]);

  if (!decision || decision.tier !== 3) return null;

  async function handleClick(approved: boolean) {
    setBusy(true);
    setError(null);
    try {
      await apiSubmitClinicianDecision(token, decision.decision_id, approved);
      const { byDecisionId } = await apiGetClinicianDecisions(token);
      setExisting(byDecisionId[decision.decision_id] || null);
      onResolved();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (existing) {
    const approved = existing.approved;
    const labelClass = approved
      ? 'text-tier-3 border-tier-3 bg-tier-3/10'
      : 'text-tier-1 border-tier-1 bg-tier-1/10';
    return (
      <div className="mt-3 pt-3 border-t border-soc-border">
        <div className="text-[10px] uppercase tracking-wider text-soc-muted mb-2">Clinician response (recorded)</div>
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <span className={`${labelClass} px-2 py-0.5 rounded border font-bold uppercase tracking-wider`}>
            {approved ? 'Approved' : 'Denied'}
          </span>
          <span className="text-soc-muted">by</span>
          <span className="font-mono text-soc-text">{existing.clinician_id}</span>
          <span className="text-soc-muted">→ final action:</span>
          <span className="font-mono text-soc-accent">{existing.final_action}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-3 pt-3 border-t border-soc-border">
      <div className="text-[10px] uppercase tracking-wider text-soc-muted mb-2">Clinician decision</div>
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
      {error && <p className="mt-2 text-tier-3 text-xs">Error: {error}</p>}
    </div>
  );
};

export default SocClinicianDecisionPanel;
