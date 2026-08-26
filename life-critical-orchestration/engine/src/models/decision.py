"""
Models for the decision engine's output.

A Decision is what the engine produces for each alert: a tier (1, 2, or 3),
a recommended action, a rationale string, and metadata for audit logging.

Tier 3 is a two-phase flow with a critical safety property: the asset is
in Monitored Mode throughout the entire flow.

  Phase A (engine + playbook, milliseconds): the engine emits
  `await_clinician_approval` and the Shuffle playbook does TWO things in
  parallel — applies Monitored Mode to the asset immediately, AND dispatches
  the approval request to the clinician. The asset is non-disruptively
  contained from the moment Tier 3 fires.

  Phase B (clinician decision, seconds to minutes): the clinician responds.
  - Approve  → escalate from Monitored Mode to `isolate_host`.
  - Deny     → stay in Monitored Mode (no state change; FR-06 fail-safe).

The engine surfaces what it would propose if approved via
`proposed_action_if_approved`. The engine never executes Phase B itself —
that belongs to the Shuffle clinician workflow, which calls back into the
audit log to record the final outcome.
"""

from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional, Literal, List
from uuid import uuid4
from pydantic import BaseModel, Field


class Tier(IntEnum):
    """Response tier — the central classification of the framework.

    Tier assignment is gated by asset criticality (cc_score band):

    - cc_score < 5 (non_critical) → always Tier 1.
      The asset is not clinically protected; the engine picks the most
      appropriate disruptive action by CVSS band (log_only / block_port /
      isolate_host).

    - cc_score >= 5 (clinical_support OR life_critical) → Tier 2 or Tier 3.
      The asset is clinically protected. Tier 2 (Monitored Mode) is the
      default; Tier 3 (clinician approval) is reserved for extreme threats
      (CVSS >= 9 OR category in {ransomware, active_exploitation}).
    """
    TIER_1 = 1  # Non-critical asset → graduated disruptive containment by CVSS
    TIER_2 = 2  # Protected asset, non-extreme threat → Monitored Mode
    TIER_3 = 3  # Protected asset, extreme threat → clinician approval


# Action vocabulary. Kept as a Literal (not Enum) so the JSON output is a plain
# string and easy for the SOC dashboard / Shuffle playbooks to consume.
Action = Literal[
    "log_only",                 # Tier 1, low CVSS — note and move on
    "block_port",               # Tier 1, medium CVSS — narrow disruptive containment
    "isolate_host",             # Tier 1/Tier 3-approved — full disruptive containment
    "monitored_mode",           # Tier 2 — non-disruptive observation
    "await_clinician_approval", # Tier 3 — escalation to human-in-the-loop
    # F-4 graded responses (Life-Critical Response Layer):
    "throttle",                 # slow a SIEM-flagged flow (auto, Tier 2)
    "selective_block",          # drop a flagged flow entirely (manual/escalation)
    "quarantine",               # wall device to the clinical-only segment
]


# The criticality band the engine derived from criticality_score.
# Engine-emitted (we control its values), so we tighten to a Literal for
# type safety on dashboards and audit consumers.
CriticalityBand = Literal["non_critical", "clinical_support", "life_critical"]


class Decision(BaseModel):
    """The engine's response to a single alert."""

    decision_id: str = Field(default_factory=lambda: f"dec-{uuid4()}")
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    alert_id: str           # Echoes the input alert_id for traceability
    asset_id: str           # Echoes the affected asset

    tier: Tier
    action: Action
    rationale: str          # Human-readable "why this tier"

    matched_rule: str       # Internal — which classifier rule fired
    fail_safe_applied: bool = False  # True if the engine had to default missing data

    # The clinical criticality band the engine actually used (after any fail-safe).
    # Surfaced in audit logs and on the dashboard so consumers see exactly what
    # the engine "saw" when it decided.
    effective_criticality: Optional[CriticalityBand] = None

    # The numeric score the engine actually used (after any fail-safe).
    # Lets dashboards display "engine read score: 7" alongside the band.
    effective_criticality_score: Optional[int] = Field(default=None, ge=1, le=10)

    # Whether the threat qualified as extreme (CVSS >= 9 OR category in
    # {ransomware, active_exploitation}). Provides transparency into the
    # Tier 2 / Tier 3 split for protected assets.
    extreme_threat: bool = False

    # For Tier 3 only: what the engine would propose to do once a clinician
    # approves. Always "isolate_host" in the current logic. None for Tier 1
    # and Tier 2 (no proposal — the action field already says what happens).
    #
    # NOTE on Tier 3 semantics: while waiting for the clinician's response,
    # the asset IS in Monitored Mode (applied immediately by the playbook
    # in parallel with the approval request). This field is what the
    # *approved* path would escalate to. If a clinician denies, no state
    # change is needed — the asset stays in Monitored Mode per FR-06.

    proposed_action_if_approved: Optional[Action] = None

    # F-1.5: the malicious network destination the SIEM actually flagged,
    # carried through from the alert's indicators (dst_ip / dst_port). A graded
    # response like `selective_block` consumes these to cut exactly the flow the
    # detection identified — never a hardcoded IP. Both are None when the alert
    # carried no network indicator. Populating them here does NOT by itself
    # choose selective_block (that is the F-4 selector's job); it just makes the
    # detected target available to whatever response is chosen.
    block_dest: Optional[str] = None
    block_ports: Optional[List[int]] = None
