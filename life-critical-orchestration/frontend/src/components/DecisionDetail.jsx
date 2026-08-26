// Structured view of an engine decision + the alert that produced it.
// Design goal: a viewer should be able to glance at this and understand
// which signal drove the decision.

import { useState } from "react";
import ShuffleActionsPanel from "./ShuffleActionsPanel";
import ClinicianDecisionPanel from "./ClinicianDecisionPanel";

const tierStyle = {
  1: { bg: "bg-tier-1", label: "TIER 1", desc: "Disruptive containment" },
  2: { bg: "bg-tier-2", label: "TIER 2", desc: "Monitored Mode" },
  3: { bg: "bg-tier-3", label: "TIER 3", desc: "Clinician approval" },
};

const bandLabel = {
  non_critical: "non-critical",
  clinical_support: "clinical support",
  life_critical: "LIFE-CRITICAL",
};

function Field({ label, value, mono = true, accent = false }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-soc-muted mb-0.5">
        {label}
      </div>
      <div
        className={[
          mono ? "font-mono" : "",
          accent ? "text-soc-accent" : "text-soc-text",
          "text-sm break-words",
        ].join(" ")}
      >
        {value ?? <span className="text-soc-muted">—</span>}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="border border-soc-border rounded bg-soc-panel">
      <div className="px-3 py-2 border-b border-soc-border">
        <h3 className="text-[10px] uppercase tracking-wider text-soc-muted">
          {title}
        </h3>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

export default function DecisionDetail({ alert, decision, busy, error }) {
  const [actionsRefreshKey, setActionsRefreshKey] = useState(0);
  if (!alert) {
    return (
      <p className="text-soc-muted text-sm">
        Select an alert from the feed to classify it.
      </p>
    );
  }

  if (busy) {
    return <p className="text-soc-muted text-sm">Classifying…</p>;
  }

  if (error) {
    return <p className="text-tier-3 text-sm">Engine error: {error}</p>;
  }

  if (!decision) return null;

  const tier = tierStyle[decision.tier];
  const cc = alert.clinical_context || {};
  const asset = alert.asset || {};
  const threat = alert.threat || {};

  return (
    <div className="space-y-4">
      {/* Headline: tier + action */}
      <div className="flex items-center gap-3">
        <span className={`${tier.bg} text-black font-bold text-sm px-3 py-1.5 rounded`}>
          {tier.label}
        </span>
        <span className="text-soc-muted text-xs">{tier.desc}</span>
        <span className="text-soc-muted">→</span>
        <span className="text-soc-accent font-mono font-bold text-sm">
          {decision.action}
        </span>
        {decision.fail_safe_applied && (
          <span className="ml-auto text-[10px] uppercase tracking-wider bg-tier-3/20 text-tier-3 border border-tier-3 px-2 py-0.5 rounded">
            fail-safe applied
          </span>
        )}
      </div>

      {/* Rationale — the human-readable 'why' */}
      <Section title="Rationale">
        <p className="text-soc-text text-sm leading-relaxed">
          {decision.rationale}
        </p>
      </Section>

      {/* Tier 3 special case: show the proposed action and what's already happening */}
      {decision.tier === 3 && (
        <Section title="Tier 3 — Two-phase Flow">
          <div className="space-y-2 text-sm">
            <div className="flex items-start gap-2">
              <span className="text-tier-2 font-bold text-xs uppercase shrink-0 mt-0.5">
                Now:
              </span>
              <span className="text-soc-text">
                Asset placed in <span className="font-mono text-soc-accent">monitored_mode</span> by the playbook (deep telemetry + shadow auditing + zero interference).
              </span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-tier-3 font-bold text-xs uppercase shrink-0 mt-0.5">
                Pending:
              </span>
              <span className="text-soc-text">
                Approval request dispatched to clinician.
                If approved → escalate to{" "}
                <span className="font-mono text-soc-accent">
                  {decision.proposed_action_if_approved}
                </span>
                .
                If denied → stay in{" "}
                <span className="font-mono text-soc-accent">monitored_mode</span>{" "}
                (FR-06).
              </span>
            </div>
          </div>
          <ClinicianDecisionPanel
            decision={decision}
            onResolved={() => setActionsRefreshKey((k) => k + 1)}
          />
        </Section>
      )}

      {/* Engine internals — what the engine actually 'saw' */}
      <Section title="Engine Internals">
        <div className="grid grid-cols-2 gap-4">
          <Field
            label="Effective score (engine-read)"
            value={decision.effective_criticality_score}
          />
          <Field
            label="Effective band"
            value={
              decision.effective_criticality
                ? bandLabel[decision.effective_criticality]
                : null
            }
            accent={decision.effective_criticality === "life_critical"}
          />
          <Field
            label="Extreme threat?"
            value={decision.extreme_threat ? "yes" : "no"}
            accent={decision.extreme_threat}
          />
          <Field label="Matched rule" value={decision.matched_rule} />
        </div>
      </Section>

      {/* Shuffle playbook actions — what the SOAR sim did in response.
          Reveals the §4.3 Monitored Mode three-component definition at
          runtime: deep telemetry + shadow auditing + zero interference.
          For Tier 3, also shows the clinician dispatch and any response. */}
      <Section title="Shuffle Playbook Actions">
        <ShuffleActionsPanel
          decisionId={decision.decision_id}
          assetId={decision.asset_id}
          refreshKey={actionsRefreshKey}
        />
      </Section>

      {/* Alert context — what the analyst sees about the asset and threat */}
      <div className="grid grid-cols-2 gap-4">
        <Section title="Asset">
          <div className="space-y-2">
            <Field label="Asset ID" value={asset.asset_id} />
            <Field label="Hostname" value={asset.hostname} />
            <Field label="Device category" value={asset.device_category} />
            <Field label="Department" value={asset.department} />
          </div>
        </Section>

        <Section title="Threat">
          <div className="space-y-2">
            <Field label="Category" value={threat.category} />
            <Field label="CVSS" value={threat.cvss_score} />
            <Field label="Technical severity" value={threat.technical_severity} />
            <Field label="SIEM rule" value={alert.source?.rule_description} mono={false} />
          </div>
        </Section>
      </div>

      {/* Display-only clinical metadata — engine ignores; we surface for analysts */}
      <Section title="Clinical Metadata (display only — engine does not act on these)">
        <div className="grid grid-cols-4 gap-4">
          <Field label="cc_score (input)" value={cc.criticality_score} />
          <Field label="Patient dependency" value={cc.patient_dependency} />
          <Field label="Time sensitivity" value={cc.time_sensitivity} />
          <Field label="Shift" value={cc.shift} />
        </div>
      </Section>

      {/* Provenance footer */}
      <div className="text-[10px] text-soc-muted font-mono pt-2 border-t border-soc-border">
        decision_id: {decision.decision_id} • decided_at: {decision.decided_at}
      </div>
    </div>
  );
}