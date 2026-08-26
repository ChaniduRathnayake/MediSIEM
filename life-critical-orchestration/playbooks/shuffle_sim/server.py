"""
Shuffle SOAR simulator — FastAPI entry point.

This service is the local PP1 stand-in for a real Shuffle workflow runner.
The engine pushes decisions to /playbook/run; this service routes each
decision to the matching workflow module (monitored_mode or tier3_dispatch)
and records every step in the action log.

Endpoints:
  GET  /health                — liveness probe + sim metadata
  POST /playbook/run          — accept a Decision payload, run the matching workflow
  GET  /actions               — read recent actions (newest first)
  GET  /actions/by-decision   — filter actions to a specific decision_id
  POST /clinician-decision    — Phase B: clinician approves/denies a Tier 3
                                request. Records playbook-side action AND
                                calls back into the engine's audit log.

Run locally:
    cd playbooks/shuffle_sim
    uvicorn server:app --reload --port 8002

Then visit http://localhost:8002/docs.

Why a Python sim (and not a real Shuffle export):
  Real Shuffle workflows are visual graphs built in the Shuffle UI. Demoing
  them means screen-recording a browser, which fights against the project's
  terminal/SOC-console aesthetic. A Python sim runs anywhere, prints clean
  log lines, and can be smoke-tested without any infra. The exported
  Shuffle workflow JSON in playbooks/shuffle_export/ documents the *real*
  path for PP2 — same way infra/wazuh/integrator-config.md documents the
  real Wazuh integrator path.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from action_log import get_log
from workflows import monitored_mode, tier3_dispatch
import enforcement
import push


# ---------- Config ----------

ENGINE_URL = os.getenv("ENGINE_URL", "http://localhost:8000")
ENGINE_CALLBACK_ENDPOINT = f"{ENGINE_URL}/clinician-decision"
SIM_VERSION = "0.1.0"

# Micro-segmentation (quarantine) is OPTIONAL and OFF by default. It requires a
# site-specific clinical-only segment definition — which clinical peers a device
# must keep reaching — that only hospital staff / asset-discovery tooling can
# supply. Until that input exists, Tier 3 contains via Monitored Mode alone.
# Set ENABLE_QUARANTINE=true to re-enable the F-3 micro-segmentation path.
ENABLE_QUARANTINE = os.getenv("ENABLE_QUARANTINE", "false").strip().lower() in (
    "1", "true", "yes", "on",
)


# ---------- App ----------

app = FastAPI(
    title="Shuffle SOAR Simulator",
    description=(
        "Local PP1 simulator for the Shuffle workflow runner. Receives "
        "decisions from the engine, runs the matching playbook (Monitored "
        "Mode or Tier 3 Dispatch), and records every step."
    ),
    version=SIM_VERSION,
)

# Permissive CORS so the dashboard can poll /actions directly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Schemas ----------

class ClinicianDecisionRequest(BaseModel):
    """Phase B request body: the clinician's approve/deny response."""
    decision_id: str
    asset_id: str
    approved: bool
    clinician_id: str = Field(default="clinician-on-call")


class PushSubscribeRequest(BaseModel):
    """A device registering to receive on-call push notifications."""
    subscriber_id: str
    subscription: Dict[str, Any]
    label: str = Field(default="")


class OnCallRequest(BaseModel):
    """Set (or clear, with null) who is currently on-call."""
    subscriber_id: Optional[str] = None


# ---------- Endpoints ----------

@app.get("/health")
def health() -> Dict[str, Any]:
    log = get_log()
    return {
        "status": "ok",
        "service": "shuffle-sim",
        "version": SIM_VERSION,
        "actions_logged": len(log.all()),
        "engine_url": ENGINE_URL,
        "push": {**push.config_status(), **push.get_store().snapshot()},
    }


@app.post("/playbook/run", status_code=status.HTTP_200_OK)
def playbook_run(decision: Dict[str, Any]) -> Dict[str, Any]:
    """Receive a Decision payload, route to the matching workflow.

    Routing is by `action`:
      - monitored_mode             → workflows.monitored_mode.run()
      - await_clinician_approval   → workflows.tier3_dispatch.run()
      - log_only / block_port / isolate_host → no playbook (Tier 1 actions
        are executed inline by the engine's downstream enforcement; the sim
        records a marker entry for visibility)

    The engine fires this as a background task; we return quickly with the
    list of actions that ran, but the engine doesn't wait on the response.
    """
    if not isinstance(decision, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision payload must be a JSON object.",
        )

    action = decision.get("action")
    if not action:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision payload missing required 'action' field.",
        )

    log = get_log()

    if action == "monitored_mode":
        written = monitored_mode.run(decision, log=log)
        workflow = monitored_mode.WORKFLOW_NAME
    elif action == "await_clinician_approval":
        written = tier3_dispatch.run(decision, log=log)
        # Tier 3 parallel containment. Monitored Mode is ALWAYS applied by
        # tier3_dispatch.run() above (non-disruptive, needs no topology
        # knowledge). Quarantine (F-3 micro-segmentation) is an optional
        # stronger containment, gated behind ENABLE_QUARANTINE because it
        # requires a site-specific clinical-only segment definition. Off by
        # default: the device is held in Monitored Mode while awaiting the
        # clinician. If approved -> isolate; if denied -> stays in Monitored
        # Mode (or quarantined, when the flag is on).
        if ENABLE_QUARANTINE:
            q = enforcement.quarantine(
                decision.get("asset_id", "<unknown>"),
                decision_id=decision.get("decision_id", "<unknown>"),
                reason="tier3_quarantine_parallel",
                log=log,
            )
            written.append(q["entry"])
        workflow = tier3_dispatch.WORKFLOW_NAME
        # Workstream E: page the on-call clinician's device. tier3_dispatch
        # already recorded the (simulated) "clinician_dispatch" step; this
        # turns that step into a real Web Push to whoever is on-call. The
        # send is best-effort and only reaches the single active on-call
        # subscriber — nothing here blocks or raises.
        push_result = push.notify_on_call(decision)
        written.append(log.record(
            decision_id=decision.get("decision_id", "<unknown>"),
            asset_id=decision.get("asset_id", "<unknown>"),
            workflow=tier3_dispatch.WORKFLOW_NAME,
            step="clinician_push",
            status="sent" if push_result.get("ok") else "skipped",
            detail=(
                f"Web Push to on-call device ({push_result.get('subscriber_id')})."
                if push_result.get("ok")
                else f"Push not sent: {push_result.get('reason') or push_result.get('error') or 'unavailable'}."
            ),
            extra=push_result,
        ))
    elif action == "isolate_host":
        # Real enforcement: cut the device at the network boundary. For the
        # emulated device (ICU-VENT-003) this is a real docker network
        # disconnect that the heartbeat-logger will measure as downtime;
        # for non-device assets it records a simulated isolation.
        result = enforcement.isolate(
            decision.get("asset_id", "<unknown>"),
            decision_id=decision.get("decision_id", "<unknown>"),
            reason="tier1_isolate_host",
            log=log,
        )
        written = [result["entry"]]
        workflow = enforcement.WORKFLOW_NAME
    elif action == "selective_block":
        # F-1: surgical containment — drop only the malicious flow, keep the
        # clinical protocols (MQTT 1883, HL7 2575) open. The engine's F-4
        # selector will populate block_dest / block_ports; until then this
        # path is exercised by the harness and the /enforcement endpoint.
        result = enforcement.selective_block(
            decision.get("asset_id", "<unknown>"),
            dest=decision.get("block_dest", ""),
            dports=decision.get("block_ports"),
            decision_id=decision.get("decision_id", "<unknown>"),
            reason="selective_block",
            log=log,
        )
        written = [result["entry"]]
        workflow = enforcement.WORKFLOW_NAME
    elif action == "throttle":
        # F-2/F-4: rate-limit the flagged flow AND run Monitored Mode (deep
        # telemetry) alongside. Throttle is scoped to block_dest, so clinical
        # traffic stays in the full-speed default class.
        written = monitored_mode.run(decision, log=log)
        result = enforcement.throttle(
            decision.get("asset_id", "<unknown>"),
            dest=decision.get("block_dest", ""),
            rate=decision.get("throttle_rate", "1mbit"),
            decision_id=decision.get("decision_id", "<unknown>"),
            reason="throttle",
            log=log,
        )
        written.append(result["entry"])
        workflow = enforcement.WORKFLOW_NAME
    elif action == "quarantine":
        # F-3: micro-segmentation — move the device onto the clinical-only
        # segment (broker + receiver), cutting every non-clinical path.
        result = enforcement.quarantine(
            decision.get("asset_id", "<unknown>"),
            decision_id=decision.get("decision_id", "<unknown>"),
            reason="quarantine",
            log=log,
        )
        written = [result["entry"]]
        workflow = enforcement.WORKFLOW_NAME
    else:
        # log_only / block_port — record a marker entry so the dashboard
        # shows the sim saw the decision; no network side effect is needed.
        written = [log.record(
            decision_id=decision.get("decision_id", "<unknown>"),
            asset_id=decision.get("asset_id", "<unknown>"),
            workflow="tier1_enforcement",
            step=action,
            status="executed",
            detail=f"Tier 1 action {action} executed by downstream enforcement.",
            extra={},
        )]
        workflow = "tier1_enforcement"

    return {
        "workflow": workflow,
        "actions_run": len(written),
        "entries": written,
    }


@app.get("/actions")
def get_actions(limit: int = 100) -> List[Dict[str, Any]]:
    """Return up to `limit` most recent action entries, newest first."""
    return get_log().recent(limit=limit)


@app.get("/actions/by-decision")
def get_actions_by_decision(decision_id: str) -> List[Dict[str, Any]]:
    """Return all action entries for a specific decision, oldest first."""
    return get_log().by_decision(decision_id)

@app.get("/actions/by-asset")
def get_actions_by_asset(asset_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Return all action entries for a specific asset, oldest first.
    
    Used by the dashboard so re-classifying an alert (which mints a fresh
    decision_id) still surfaces prior playbook activity and clinician
    responses on the same physical asset.
    """
    log = get_log()
    matches = [e for e in log.all() if e.get("asset_id") == asset_id]
    return matches[-limit:] if limit > 0 else matches


@app.post("/clinician-decision", status_code=status.HTTP_200_OK)
async def clinician_decision(req: ClinicianDecisionRequest) -> Dict[str, Any]:
    """Phase B: the clinician has approved or denied a Tier 3 escalation.

    Two things happen here:
      1. Record the response in the action log so the playbook-side audit
         is complete.
      2. Notify the engine so it can write its own follow-up audit entry
         (engine's audit log is the durable, hash-chained source of truth).

    This split mirrors what a real Shuffle workflow would do: receive the
    webhook from the clinician's UI, then call back into upstream systems.
    """
    log = get_log()

    # 1) Playbook-side record
    playbook_entry = tier3_dispatch.record_clinician_response(
        decision_id=req.decision_id,
        asset_id=req.asset_id,
        approved=req.approved,
        clinician_id=req.clinician_id,
        log=log,
    )

    # 1b) On APPROVAL, execute the real disruptive action the clinician
    #     authorised: isolate the device at the network boundary. On denial
    #     we do nothing — the asset stays in Monitored Mode (FR-06).
    enforcement_result = None
    if req.approved:
        enforcement_result = enforcement.isolate(
            req.asset_id,
            decision_id=req.decision_id,
            reason="tier3_clinician_approved",
            log=log,
        )

    # 2) Notify the engine. Best-effort: if the engine is briefly unavailable
    # we still want the playbook-side record to land (the dashboard would
    # otherwise show a half-state). We log the engine response back into
    # the action log for traceability.
    engine_status: Optional[int] = None
    engine_error: Optional[str] = None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                ENGINE_CALLBACK_ENDPOINT,
                json={
                    "decision_id": req.decision_id,
                    "approved": req.approved,
                    "clinician_id": req.clinician_id,
                },
            )
            engine_status = resp.status_code
            if resp.status_code >= 400:
                engine_error = f"Engine returned {resp.status_code}: {resp.text[:200]}"
    except httpx.RequestError as exc:
        engine_error = f"Could not reach engine at {ENGINE_CALLBACK_ENDPOINT}: {exc}"

    if engine_error:
        log.record(
            decision_id=req.decision_id,
            asset_id=req.asset_id,
            workflow="tier3_dispatch",
            step="engine_callback",
            status="failed",
            detail=engine_error,
            extra={"engine_status": engine_status},
        )

    return {
        "playbook_entry": playbook_entry,
        "enforcement": enforcement_result,
        "engine_callback": {
            "ok": engine_error is None,
            "status": engine_status,
            "error": engine_error,
        },
    }

@app.post("/enforcement/release", status_code=status.HTTP_200_OK)
def enforcement_release(asset_id: str) -> Dict[str, Any]:
    """Reconnect an isolated device to its network (reset between runs)."""
    return enforcement.release(asset_id, log=get_log())


@app.post("/enforcement/selective-block", status_code=status.HTTP_200_OK)
def enforcement_selective_block(
    asset_id: str, dest: str, dports: Optional[str] = None
) -> Dict[str, Any]:
    """F-1: surgically drop the device's traffic to `dest`, keeping clinical flows open.

    `dports` is an optional comma-separated port list (e.g. "443,8443"); omit to
    block all traffic to `dest`.
    """
    ports: Optional[List[int]] = None
    if dports:
        try:
            ports = [int(p) for p in dports.split(",") if p.strip()]
        except ValueError:
            ports = None
    return enforcement.selective_block(
        asset_id, dest=dest, dports=ports,
        decision_id="manual-selective-block", log=get_log(),
    )


@app.post("/enforcement/restore-flows", status_code=status.HTTP_200_OK)
def enforcement_restore_flows(asset_id: str) -> Dict[str, Any]:
    """Clear all selective blocks on the device (flush LCA_BLOCK; reset between runs)."""
    return enforcement.restore_flows(asset_id, log=get_log())


@app.post("/enforcement/throttle", status_code=status.HTTP_200_OK)
def enforcement_throttle(asset_id: str, dest: str, rate: str = "1mbit") -> Dict[str, Any]:
    """F-2: rate-limit the device's traffic to `dest` at `rate`; clinical stays full-speed."""
    return enforcement.throttle(
        asset_id, dest=dest, rate=rate, decision_id="manual-throttle", log=get_log(),
    )


@app.post("/enforcement/unthrottle", status_code=status.HTTP_200_OK)
def enforcement_unthrottle(asset_id: str) -> Dict[str, Any]:
    """Remove all traffic shaping on the device (reset between runs)."""
    return enforcement.unthrottle(asset_id, decision_id="manual-unthrottle", log=get_log())


@app.post("/enforcement/quarantine", status_code=status.HTTP_200_OK)
def enforcement_quarantine(asset_id: str) -> Dict[str, Any]:
    """F-3: move the device onto the clinical-only segment (block lateral movement)."""
    return enforcement.quarantine(asset_id, decision_id="manual-quarantine", log=get_log())


@app.post("/enforcement/unquarantine", status_code=status.HTTP_200_OK)
def enforcement_unquarantine(asset_id: str) -> Dict[str, Any]:
    """Return the device to its general network (undo quarantine; reset between runs)."""
    return enforcement.release_quarantine(asset_id, decision_id="manual-unquarantine", log=get_log())


# ---------- Web Push (Workstream E) ----------

@app.get("/push/config")
def push_config() -> Dict[str, Any]:
    """Public config the frontend needs to subscribe.

    Returns the VAPID public (application server) key plus whether push is
    actually configured. The private key never leaves the server.
    """
    return {
        **push.config_status(),
        "vapid_public_key": push.VAPID_PUBLIC_KEY,
        **push.get_store().snapshot(),
    }


@app.post("/push/subscribe", status_code=status.HTTP_200_OK)
def push_subscribe(req: PushSubscribeRequest) -> Dict[str, Any]:
    """Register (or refresh) a device's push subscription."""
    entry = push.get_store().upsert(req.subscriber_id, req.subscription, label=req.label)
    return {"ok": True, "subscriber_id": entry["subscriber_id"], **push.get_store().snapshot()}


@app.post("/push/unsubscribe", status_code=status.HTTP_200_OK)
def push_unsubscribe(req: OnCallRequest) -> Dict[str, Any]:
    """Remove a device's subscription (also clears on-call if it held it)."""
    removed = push.get_store().remove(req.subscriber_id or "")
    return {"ok": True, "removed": removed, **push.get_store().snapshot()}


@app.get("/push/on-call")
def get_on_call() -> Dict[str, Any]:
    """Who is currently on-call (the only device that will be paged)."""
    return push.get_store().snapshot()


@app.post("/push/on-call", status_code=status.HTTP_200_OK)
def set_on_call(req: OnCallRequest) -> Dict[str, Any]:
    """Set the active on-call device (or clear it with a null subscriber_id).

    Only the on-call subscriber receives Tier 3 pushes — this is the
    operational rotation control until a real login + schedule lands.
    """
    store = push.get_store()
    if req.subscriber_id and req.subscriber_id not in {
        s["subscriber_id"] for s in store.snapshot()["subscribers"]
    }:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown subscriber_id — subscribe this device before going on-call.",
        )
    store.set_on_call(req.subscriber_id)
    return {"ok": True, **store.snapshot()}


@app.post("/push/test", status_code=status.HTTP_200_OK)
def push_test() -> Dict[str, Any]:
    """Send a test push to the on-call device (verifies the full path)."""
    result = push.notify_on_call({
        "asset_id": "TEST-DEVICE",
        "decision_id": "test",
        "rationale": "Test notification — the on-call push path is working.",
        "proposed_action_if_approved": "isolate_host",
    })
    return result
