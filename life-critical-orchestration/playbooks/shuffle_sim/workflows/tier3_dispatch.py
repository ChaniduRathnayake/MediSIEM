"""
Tier 3 dispatch workflow — clinician approval routing.

When the engine emits a Tier 3 decision, this workflow does TWO things in
parallel (the Phase A semantic from the Decision model docstring):

  1. Apply Monitored Mode immediately — by re-using monitored_mode.run().
     The asset is non-disruptively contained from the moment Tier 3 fires;
     there is no unprotected gap while we wait for the clinician.

  2. Dispatch the approval request to the clinician — in production this
     would be a Twilio SMS, a push notification, or a hospital-internal
     paging system. For PP1 it's logged as a 'dispatched' action.

The Phase B follow-up (clinician approves / denies) is handled by the
HTTP callback /clinician-decision on this sim's server, which then calls
back into the *engine's* /clinician-decision endpoint to seal the audit log.

In a real Shuffle deployment these two halves would be a single workflow
with a "Wait for webhook" node. For PP1 they're split across run() (sent
when the engine pushes the decision) and the HTTP handler in server.py
(invoked when the dashboard's approve/deny button is clicked).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from action_log import ActionLog, get_log
from workflows import monitored_mode


WORKFLOW_NAME = "tier3_dispatch"

# In production this would point at a real clinician notification service.
# For PP1 we just log the URL we *would* call.
CLINICIAN_ENDPOINT = os.getenv(
    "CLINICIAN_ENDPOINT",
    "https://clinician-pager.example/internal/notify",
)

# Mirror server.py's flag so the recorded deny-path text matches what actually
# happened. Quarantine is off by default (see server.py for the rationale);
# when off, a denied Tier 3 asset stays in Monitored Mode, not quarantined.
ENABLE_QUARANTINE = os.getenv("ENABLE_QUARANTINE", "false").strip().lower() in (
    "1", "true", "yes", "on",
)


def run(decision: Dict[str, Any], log: ActionLog | None = None) -> List[Dict[str, Any]]:
    """Run the Tier 3 dispatch flow (Phase A only).

    Phase A runs the Monitored Mode workflow first (so the asset is contained),
    then records the clinician dispatch action. Phase B is an HTTP callback,
    handled in server.py.

    Returns the combined list of action entries that were appended.
    """
    log = log or get_log()
    decision_id = decision.get("decision_id", "<unknown>")
    asset_id = decision.get("asset_id", "<unknown>")

    # ----- Phase A.1: Monitored Mode applied immediately -----
    # Critical safety property: the asset is in Monitored Mode from the
    # very first millisecond of Tier 3, NOT only after the clinician decides.
    written = monitored_mode.run(decision, log=log)

    # ----- Phase A.2: Clinician approval dispatched -----
    proposed = decision.get("proposed_action_if_approved", "isolate_host")
    rationale_excerpt = (decision.get("rationale") or "")[:200]

    written.append(log.record(
        decision_id=decision_id,
        asset_id=asset_id,
        workflow=WORKFLOW_NAME,
        step="clinician_dispatch",
        status="dispatched",
        detail=(
            f"Approval request sent to clinician for {asset_id}. "
            f"Proposed escalation if approved: {proposed}. "
            "Asset remains in Monitored Mode while awaiting decision."
        ),
        extra={
            "endpoint": CLINICIAN_ENDPOINT,
            "proposed_action_if_approved": proposed,
            "rationale_excerpt": rationale_excerpt,
            # PP1: the actual notification is simulated. PP2: this would
            # contain the real Twilio / push notification message ID.
            "notification_id": f"sim-{decision_id}",
        },
    ))

    return written


def record_clinician_response(
    *,
    decision_id: str,
    asset_id: str,
    approved: bool,
    clinician_id: str,
    log: ActionLog | None = None,
) -> Dict[str, Any]:
    """Record the clinician's response (Phase B) in the action log.

    The HTTP handler in server.py is responsible for *also* notifying the
    engine via its /clinician-decision endpoint. This function only writes
    the playbook-side record.

    Returns the action entry that was written.
    """
    log = log or get_log()
    if approved:
        detail = (
            f"Clinician {clinician_id} APPROVED the disruptive escalation on {asset_id}. "
            "Workflow will execute isolate_host."
        )
        status = "approved"
    else:
        if ENABLE_QUARANTINE:
            detail = (
                f"Clinician {clinician_id} DENIED the disruptive escalation on {asset_id}. "
                "Asset stays quarantined on the clinical-only segment (contained; "
                "clinical telemetry preserved) per FR-06 fail-safe."
            )
        else:
            detail = (
                f"Clinician {clinician_id} DENIED the disruptive escalation on {asset_id}. "
                "Asset stays in Monitored Mode (non-disruptive containment; clinical "
                "telemetry preserved) per FR-06 fail-safe."
            )
        status = "denied"

    return log.record(
        decision_id=decision_id,
        asset_id=asset_id,
        workflow=WORKFLOW_NAME,
        step="clinician_response",
        status=status,
        detail=detail,
        extra={"clinician_id": clinician_id, "approved": approved},
    )
