"""
Security-vs-Life classifier — the rules that drive every decision.

The classifier is deliberately rule-based and deterministic. No ML, no
probabilities, no opacity. Same input always produces same output, and every
decision is fully explainable via the matched_rule field on the Decision.

Decision logic (v1.2 — CAS-driven, CVSS retired from decision-making):

  IF criticality_score < 5  (non_critical asset):
      Tier 1 — pick action by CAS band:
          cas < 5   → log_only
          cas < 8   → block_port
          else      → isolate_host
  ELIF threat is extreme  (cas >= 8 OR category in extreme set):
      Tier 3 — await_clinician_approval (proposed: isolate_host)
  ELSE:
      Tier 2 — monitored_mode

"Extreme" threat is defined as cas_score >= EXTREME_CAS_THRESHOLD (8.0) OR
threat.category in EXTREME_THREAT_CATEGORIES. Thresholds are named
constants so they can be tuned without hunting through the code. Note the
Tier 1 top band and the Tier 3 extreme trigger share this same 8.0 cutoff
by design (the spec's cas_score >= 0.80 on its native 0-1 scale) — it's one
severity threshold applied differently depending on whether the asset is
protected, not two independent numbers.

v1.1 change: threat.cvss_score is no longer read anywhere in this module.
MediSIEM's CAAP-blended cas_score (technical risk + attack exploitability +
time context, not just raw attack-type severity) is the only numeric
severity signal the classifier consults; technical_severity remains the
categorical fallback for producers with neither score. cvss_score is still
accepted on the schema and echoed back for display (see docs/alert-schema.md),
it just no longer drives any decision.

Fail-safe: if criticality_score is missing or invalid, the classifier
substitutes score=10 / band=life_critical and flags fail_safe_applied=True.
This matches the documented schema rule (docs/alert-schema.md): when in
doubt, never disrupt patient care.
"""

from typing import Optional, Tuple
from ..models.alert import Alert
from ..models.decision import Decision, Tier, CriticalityBand
from .rationale import build_rationale


# Tunable constants — change in one place, not scattered through the code.
EXTREME_CAS_THRESHOLD = 8.0
EXTREME_THREAT_CATEGORIES = {"ransomware", "active_exploitation"}

# CAS band thresholds used to pick Tier 1 actions (0-10 scale). Mirrors the
# spec's 0-1 scale (cas < 0.50 → log_only, 0.50 <= cas < 0.80 → block_port,
# cas >= 0.80 → isolate_host) times 10.
CAS_LOW_MAX = 5.0    # cas < 5.0 → log_only
CAS_MEDIUM_MAX = 8.0 # cas < 8.0 → block_port

# Criticality score thresholds (v1.0: 1–10 scale).
PROTECTED_SCORE_MIN = 5         # cc_score >= 5 → protected (clinical_support or life_critical)
LIFE_CRITICAL_SCORE_MIN = 8     # cc_score >= 8 → life_critical band
FAIL_SAFE_SUBSTITUTE_SCORE = 10 # used when cc_score is missing/invalid


# ---------- Helpers (small, focused, easy to test) ----------

def _resolve_criticality(alert: Alert) -> Tuple[int, CriticalityBand, bool]:
    """
    Determine the effective criticality score and band of the alert's asset.

    Returns (effective_score, band, fail_safe_applied).

    Resolution order:
      1. Use clinical_context.criticality_score if present and in range (1–10).
         Map it to a band per the v1.0 thresholds.
      2. Apply the fail-safe (score=10, band=life_critical) and flag it.

    The Pydantic model already enforces ge=1 / le=10, so out-of-range values
    are caught at parse time. We still defensively check for None here so the
    fail-safe is obvious in the code path that produces a Decision.
    """
    score = alert.clinical_context.criticality_score

    if score is None:
        return FAIL_SAFE_SUBSTITUTE_SCORE, "life_critical", True

    band: CriticalityBand
    if score >= LIFE_CRITICAL_SCORE_MIN:
        band = "life_critical"
    elif score >= PROTECTED_SCORE_MIN:
        band = "clinical_support"
    else:
        band = "non_critical"

    return score, band, False


def _is_extreme_threat(alert: Alert) -> bool:
    """A threat is extreme if its numeric severity clears the threshold, OR
    its category is a hard override — whichever fires first.

    Numeric severity, in preference order:
      1. cas_score >= EXTREME_CAS_THRESHOLD, when the producer supplies one
         (MediSIEM's CAAP-blended score — folds in technical risk, attack
         exploitability, and time context, not just raw attack-type
         severity). This is the only numeric signal the classifier reads;
         cvss_score is never consulted, even when present.
      2. technical_severity == "critical", when no cas_score is present
         (a producer sending only the categorical field is still telling us
         the threat is in the extreme band).

    Category hard override (independent of which numeric signal was used,
    or whether one was available at all): a known-dangerous category always
    escalates, even if the numeric score landed just under threshold. This
    is deliberate — "when in doubt, never disrupt patient care" extended to
    "never let a scoring edge case suppress a known-dangerous category."
    """
    threat = alert.threat

    if threat.cas_score is not None:
        numeric_extreme = threat.cas_score >= EXTREME_CAS_THRESHOLD
    else:
        numeric_extreme = threat.technical_severity == "critical"

    category_extreme = bool(threat.category and threat.category.lower() in EXTREME_THREAT_CATEGORIES)

    return numeric_extreme or category_extreme


# Common Wazuh / firewall field names for a network destination indicator.
# The mapper forwards Wazuh's `data` block verbatim as threat.indicators, so we
# look for the destination under the names real integrations actually emit.
_DEST_KEYS = ("dst_ip", "dstip", "dest_ip", "destination_ip", "destination", "dst")
_DPORT_KEYS = ("dst_port", "dstport", "dest_port", "destination_port")


def _extract_block_target(alert: Alert) -> Tuple[Optional[str], Optional[list]]:
    """Pull the malicious destination (+ port) the SIEM flagged, if any.

    Reads threat.indicators (the forwarded Wazuh data block). Returns
    (dest, ports) where either may be None. This is what makes a graded block
    target a *detected* address rather than a hardcoded one.
    """
    indicators = alert.threat.indicators or {}
    if not isinstance(indicators, dict):
        return None, None

    dest: Optional[str] = None
    for key in _DEST_KEYS:
        val = indicators.get(key)
        if isinstance(val, str) and val.strip():
            dest = val.strip()
            break

    ports: Optional[list] = None
    for key in _DPORT_KEYS:
        val = indicators.get(key)
        if isinstance(val, bool):
            continue  # bools are ints in Python — never a port
        if isinstance(val, int):
            ports = [val]
            break
        if isinstance(val, str) and val.strip().isdigit():
            ports = [int(val.strip())]
            break

    return dest, ports


def _pick_tier1_action(alert: Alert) -> Tuple[str, str]:
    """
    For a non-critical asset, pick the appropriate Tier 1 action by CAS band.
    cvss_score is never read here — technical_severity is the only fallback
    for a producer that hasn't supplied a cas_score.

    Returns (action, matched_rule_suffix).

    Band mapping (0-10 scale):
      cas < 5.0           → log_only
      5.0 <= cas < 8.0    → block_port
      cas >= 8.0          → isolate_host
      (no cas_score)      → fall back to technical_severity, same bands

    For non-critical assets the engine will always pick *some* disruptive
    action; the only question is how aggressive. When in doubt about
    severity, default to isolate_host (most cautious for the wider network,
    safe for non-critical assets).
    """
    threat = alert.threat

    if threat.cas_score is not None:
        cas = threat.cas_score
        if cas < CAS_LOW_MAX:
            return "log_only", "low_cas"
        if cas < CAS_MEDIUM_MAX:
            return "block_port", "medium_cas"
        return "isolate_host", "high_or_extreme_cas"

    # Fall back to categorical severity using the same band structure
    sev = threat.technical_severity
    if sev == "low":
        return "log_only", "low_severity"
    if sev == "medium":
        return "block_port", "medium_severity"
    if sev in ("high", "critical"):
        return "isolate_host", "high_or_critical_severity"

    # No severity signal at all — be cautious and fully contain
    return "isolate_host", "no_severity_signal"


# ---------- The classifier itself ----------

def classify(alert: Alert) -> Decision:
    """
    Apply the rules to an alert and produce a Decision.

    This is the single entry point to the engine's decision logic. Everything
    upstream (FastAPI, message queues) and downstream (audit log, Shuffle
    integration) goes through this function.
    """
    score, band, fail_safe_applied = _resolve_criticality(alert)
    extreme = _is_extreme_threat(alert)
    # F-1.5: the SIEM-flagged malicious destination (if any). Computed up front
    # so the F-4 selector can branch on it.
    block_dest, block_ports = _extract_block_target(alert)

    proposed_action_if_approved = None  # only set for Tier 3

    # ----- RULE 1: Non-critical asset (cc_score < 5) → Tier 1, graduated by CVSS -----
    if band == "non_critical":
        action, action_suffix = _pick_tier1_action(alert)
        tier = Tier.TIER_1
        matched_rule = f"RULE_1_non_critical_{action_suffix}"

    # ----- RULE 2: Protected asset + extreme threat → Tier 3 -----
    elif extreme:
        tier = Tier.TIER_3
        action = "await_clinician_approval"
        matched_rule = "RULE_2_protected_extreme"
        # Tier 3 is a two-phase flow: Monitored Mode is applied immediately
        # by the playbook; if the clinician approves, the asset escalates
        # to isolate_host. If denied, it stays in Monitored Mode (FR-06).
        proposed_action_if_approved = "isolate_host"

    # ----- RULE 3: Protected asset + non-extreme threat → Tier 2 -----
    # F-4 selector: if the SIEM flagged a malicious/unfamiliar destination,
    # apply the least-disruptive graded containment — throttle that one flow —
    # alongside Monitored Mode. With no actionable destination, Monitored Mode
    # alone. (Dropping/isolating are never auto-selected; they are escalations.)
    else:
        tier = Tier.TIER_2
        if block_dest:
            action = "throttle"
            matched_rule = "RULE_3_protected_throttle_flagged_flow"
        else:
            action = "monitored_mode"
            matched_rule = "RULE_3_protected_monitored_mode"

    # If the fail-safe was applied, prefix the rule name so audit consumers
    # can spot it without reading the boolean.
    if fail_safe_applied:
        matched_rule = f"FAIL_SAFE_then_{matched_rule}"

    rationale = build_rationale(
        alert=alert,
        effective_score=score,
        effective_band=band,
        extreme_threat=extreme,
        tier=tier,
        action=action,
        fail_safe_applied=fail_safe_applied,
        proposed_action_if_approved=proposed_action_if_approved,
    )

    return Decision(
        alert_id=alert.alert_id,
        asset_id=alert.asset.asset_id,
        tier=tier,
        action=action,
        rationale=rationale,
        matched_rule=matched_rule,
        fail_safe_applied=fail_safe_applied,
        effective_criticality=band,
        effective_criticality_score=score,
        extreme_threat=extreme,
        proposed_action_if_approved=proposed_action_if_approved,
        block_dest=block_dest,
        block_ports=block_ports,
    )
