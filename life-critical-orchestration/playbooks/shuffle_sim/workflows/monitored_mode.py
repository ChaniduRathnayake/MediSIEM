"""
Monitored Mode workflow — the §4.3 showpiece of the proposal.

When the engine emits a Tier 2 decision OR the Monitored phase of a Tier 3
decision, this workflow records the three components of Monitored Mode as
defined in the proposal section 4.3:

  1. Deep Telemetry Collection — increase log verbosity / packet capture
  2. Shadow Auditing            — flag the asset for behavioural baseline diff
  3. Zero Interference          — assert that no traffic is blocked, no config locked

In production, each step would call out to real systems (Wazuh's manager API
to bump rule levels, the shadow-audit pipeline, the network-policy controller).
For PP1 they are *recorded* as actions in the action log — i.e. the playbook
*structure* is real, the side effects are simulated.

The workflow is a single function so the entire "what does Monitored Mode
mean" answer lives in one place — easy to read, easy to demo.
"""

from __future__ import annotations

from typing import Any, Dict, List

from action_log import ActionLog, get_log


WORKFLOW_NAME = "monitored_mode"


def run(decision: Dict[str, Any], log: ActionLog | None = None) -> List[Dict[str, Any]]:
    """Run all three Monitored Mode steps for the given decision.

    Args:
        decision: the engine's Decision payload (as a dict). Must include
                  decision_id and asset_id at minimum.
        log:      action log to write to. Defaults to the shared one.

    Returns the list of action entries that were appended (for tests).
    """
    log = log or get_log()
    decision_id = decision.get("decision_id", "<unknown>")
    asset_id = decision.get("asset_id", "<unknown>")

    written: List[Dict[str, Any]] = []

    # ----- Component 1: Deep Telemetry Collection -----
    written.append(log.record(
        decision_id=decision_id,
        asset_id=asset_id,
        workflow=WORKFLOW_NAME,
        step="deep_telemetry",
        status="triggered",
        detail=(
            f"Raised log verbosity to verbose+pcap on {asset_id}. "
            "Capturing every packet and system call for the SOC."
        ),
        extra={
            # In production these would be the actual API responses from
            # whatever the agent or network tap is. For the sim, surface
            # the shape so PP2 can see what's expected.
            "verbosity_level": "verbose",
            "packet_capture": True,
            "duration_minutes": 60,
        },
    ))

    # ----- Component 2: Shadow Auditing -----
    written.append(log.record(
        decision_id=decision_id,
        asset_id=asset_id,
        workflow=WORKFLOW_NAME,
        step="shadow_auditing",
        status="triggered",
        detail=(
            f"Started behavioural diff for {asset_id} against its 'known good' "
            "clinical baseline. Deviations will be flagged to the SOC."
        ),
        extra={
            "baseline": "clinical_baseline_v1",
            "diff_window_seconds": 300,
        },
    ))

    # ----- Component 3: Zero Interference -----
    # This is a positive assertion — explicitly stating what we are NOT doing.
    # Critical for the safety story: the audit log proves no traffic was
    # blocked and no configurations were touched.
    written.append(log.record(
        decision_id=decision_id,
        asset_id=asset_id,
        workflow=WORKFLOW_NAME,
        step="zero_interference",
        status="asserted",
        detail=(
            f"Confirmed: no traffic blocked, no configuration locked on {asset_id}. "
            "Device retains 100% of its native clinical functionality."
        ),
        extra={
            "blocked_ports": [],
            "config_locks": [],
            "native_functionality_preserved": True,
        },
    ))

    return written
