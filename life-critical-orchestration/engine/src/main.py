"""
Decision Engine — FastAPI entry point.

Endpoints:
  GET  /health             — simple liveness check
  POST /decide             — classify an enriched alert, return a Decision
  GET  /audit              — read the audit log (newest last)
  GET  /audit/verify       — verify the audit log's hash chain
  GET  /alerts/recent      — peek at recently classified alerts (ring buffer,
                             newest first). Lets the dashboard show alerts
                             injected via the enrichment shim.
  POST /clinician-decision — Phase B of the Tier 3 two-phase flow. Records
                             the clinician's approve/deny response as a
                             follow-up audit entry. Called by the Shuffle
                             playbook (or directly by the dashboard during
                             PP1) once a clinician acts on a Tier 3 alert.

The engine optionally pushes every Decision to a Shuffle workflow runner
when SHUFFLE_WEBHOOK_URL is set. The push is fire-and-forget so /decide
never waits on Shuffle. If the variable is unset the engine works exactly
as before.

Run locally:
    uvicorn src.main:app --reload --port 8000

Then visit http://localhost:8000/docs for interactive API docs.
"""

import os
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .models.alert import Alert
from .models.decision import Decision
from .decision import classify
from .audit import AuditLogger


logger = logging.getLogger("engine")


# ---------- App + audit log setup ----------

app = FastAPI(
    title="Life-Critical-Aware Decision Engine",
    description=(
        "Security-vs-Life orchestration engine. Classifies enriched alerts "
        "into Tier 1 (disruptive), Tier 2 (Monitored Mode), or Tier 3 "
        "(clinician approval required)."
    ),
    version="0.1.0",
)

# Permissive CORS so the React dashboard (different port in dev) can call us.
# In production this should be locked down to known origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Audit log path — env var override allows tests/CI to point elsewhere.
AUDIT_LOG_PATH = os.getenv(
    "AUDIT_LOG_PATH",
    str(Path(__file__).resolve().parent.parent / "data" / "audit_log.jsonl"),
)
audit = AuditLogger(AUDIT_LOG_PATH)


# Ring buffer of recently classified alerts. Keeps the last N alerts the
# engine has seen, paired with their decision, so the dashboard can show
# shim-injected alerts that didn't come from the bundled stub feed.
# Intentionally in-memory only — this is a read-side cache, not a record.
# The audit log remains the durable source of truth.
RECENT_ALERTS_BUFFER_SIZE = int(os.getenv("RECENT_ALERTS_BUFFER_SIZE", "50"))
_recent_alerts: Deque[Dict] = deque(maxlen=RECENT_ALERTS_BUFFER_SIZE)


# ---------- Shuffle integration (optional, fire-and-forget) ----------
#
# When SHUFFLE_WEBHOOK_URL is set, every Decision is POSTed to it as a
# background task after /decide returns. This is the integration point
# for the Shuffle SOAR sim (playbooks/shuffle_sim/) at PP1, and the real
# Shuffle webhook URL at PP2 — same contract either way.
#
# The push is intentionally non-blocking: if Shuffle is down or slow, the
# engine still returns the decision to its caller without delay. A failed
# push is logged but never raises.
SHUFFLE_WEBHOOK_URL = os.getenv("SHUFFLE_WEBHOOK_URL", "").strip()
SHUFFLE_PUSH_TIMEOUT = float(os.getenv("SHUFFLE_PUSH_TIMEOUT", "3.0"))


def _push_to_shuffle(decision_payload: Dict) -> None:
    """POST a decision to the Shuffle webhook. Best-effort, never raises.

    Runs as a FastAPI BackgroundTask so /decide can return immediately
    without waiting for Shuffle to acknowledge.
    """
    if not SHUFFLE_WEBHOOK_URL:
        return
    try:
        with httpx.Client(timeout=SHUFFLE_PUSH_TIMEOUT) as client:
            client.post(SHUFFLE_WEBHOOK_URL, json=decision_payload)
    except Exception as exc:  # noqa: BLE001 — best-effort, swallow + log
        logger.warning(
            "Shuffle push to %s failed: %s",
            SHUFFLE_WEBHOOK_URL,
            exc,
        )


# ---------- Endpoints ----------

@app.get("/health")
def health() -> dict:
    """Simple liveness probe. Used by Docker and the dashboard."""
    return {"status": "ok", "service": "decision-engine", "version": "0.1.0"}


@app.post("/decide", response_model=Decision, status_code=status.HTTP_200_OK)
def decide(alert: Alert, background_tasks: BackgroundTasks) -> Decision:
    """
    Classify a single enriched alert into a response tier.

    The alert must conform to docs/alert-schema.md. Pydantic validates this
    automatically; malformed input returns a 422 with a helpful message.

    If SHUFFLE_WEBHOOK_URL is configured, the resulting Decision is also
    pushed to Shuffle as a background task — fire-and-forget, so the
    response to the caller never waits on Shuffle.
    """
    decision = classify(alert)
    audit.append(decision)
    # Keep a copy of the inbound alert + decision so /alerts/recent can
    # surface this on the dashboard without the dashboard needing direct
    # access to the audit log's full alert payload.
    decision_payload = decision.model_dump(mode="json")
    _recent_alerts.append({
        "alert": alert.model_dump(mode="json"),
        "decision": decision_payload,
    })
    # Fire-and-forget push to Shuffle. No-op if SHUFFLE_WEBHOOK_URL is unset.
    background_tasks.add_task(_push_to_shuffle, decision_payload)
    return decision


@app.get("/alerts/recent")
def recent_alerts(limit: int = 50) -> List[Dict]:
    """Return recently classified alerts, newest first.

    Backed by an in-memory ring buffer; resets when the engine restarts.
    Used by the dashboard to surface alerts injected via the enrichment
    shim (i.e. ones that didn't come from the bundled stub feed).
    """
    if limit <= 0:
        return []
    items = list(_recent_alerts)
    items.reverse()  # newest first
    return items[:limit]


@app.get("/audit", response_model=List[dict])
def audit_log() -> List[dict]:
    """Return the full audit log, oldest entries first."""
    return list(audit.read_all())


@app.get("/audit/verify")
def audit_verify() -> dict:
    """Verify the audit log's hash chain. Returns ok + optional error message."""
    ok, error = audit.verify_chain()
    if not ok:
        # 200 with ok=false is intentional: the API call succeeded; what failed
        # is the integrity check. Treating this as 5xx would be misleading.
        return {"ok": False, "error": error}
    return {"ok": True, "error": None}


# ---------- Clinician decision callback (Phase B of Tier 3) ----------

class ClinicianDecisionRequest(BaseModel):
    """Phase B: a clinician's approve/deny response to a Tier 3 decision.

    Posted by the Shuffle playbook (or the dashboard during PP1) once a
    clinician has acted on the approval request that was dispatched in
    Phase A.
    """
    decision_id: str = Field(..., description="The original Tier 3 decision_id")
    approved: bool
    clinician_id: str = Field(default="clinician-on-call")


def _find_original_decision(decision_id: str) -> Optional[Dict]:
    """Walk the audit log to locate the original Decision entry by id.

    Returns the full audit entry, or None if no matching decision is found.
    Used by /clinician-decision to validate that the referenced decision
    actually exists before writing a follow-up.
    """
    for entry in audit.read_all():
        decision = entry.get("decision")
        if decision and decision.get("decision_id") == decision_id:
            return entry
    return None


@app.post("/clinician-decision", status_code=status.HTTP_200_OK)
def clinician_decision(req: ClinicianDecisionRequest) -> Dict:
    """Record a clinician's response to a Tier 3 escalation request.

    This is Phase B of the two-phase Tier 3 flow described in the Decision
    model docstring. The original Tier 3 Decision entry is left untouched
    (it's the immutable record of what the engine decided); this endpoint
    appends a follow-up entry to the chain capturing the clinician outcome:

      - approved=True   → the response would escalate to isolate_host.
      - approved=False  → no state change; asset stays in Monitored Mode
                          per FR-06 fail-safe.

    Idempotency: this endpoint does NOT enforce single-response-per-decision
    by design. A clinician revising their decision (rare but possible) is a
    real-world scenario; the audit chain captures every such transition. The
    dashboard surfaces only the most recent follow-up per decision_id.
    """
    original = _find_original_decision(req.decision_id)
    if original is None:
        # 404 keeps the contract honest — we won't fabricate a follow-up
        # for a decision that never existed.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No decision with id {req.decision_id} found in audit log.",
        )

    original_decision = original.get("decision", {})
    final_action = (
        original_decision.get("proposed_action_if_approved", "isolate_host")
        if req.approved
        else "monitored_mode"
    )

    payload = {
        "kind": "clinician_response",
        "referenced_decision_id": req.decision_id,
        "asset_id": original_decision.get("asset_id"),
        "approved": req.approved,
        "clinician_id": req.clinician_id,
        "final_action": final_action,
        "responded_at": datetime.now(timezone.utc).isoformat(),
        # Echo the original action so audit consumers can see the
        # before/after on a single screen without re-walking the log.
        "original_action": original_decision.get("action"),
    }

    entry = audit.append_followup(payload)

    return {
        "ok": True,
        "entry": entry,
        "final_action": final_action,
    }


# ---------- Convenience: latest clinician follow-up per decision ----------

@app.get("/clinician-decisions")
def clinician_decisions() -> Dict[str, Dict]:
    """Return the most-recent clinician follow-up for each decision_id.

    Shape:
      { "<decision_id>": { ...followup payload... }, ... }

    The dashboard uses this to show whether a Tier 3 alert has been
    resolved (and how) without having to filter the entire audit log
    client-side.
    """
    latest: Dict[str, Dict] = {}
    for entry in audit.read_all():
        followup = entry.get("followup")
        if not followup or followup.get("kind") != "clinician_response":
            continue
        ref = followup.get("referenced_decision_id")
        if ref:
            # Last-write-wins; audit.read_all yields oldest-first, so the
            # final iteration overwrites prior entries for the same id.
            latest[ref] = {**followup, "entry_hash": entry.get("entry_hash")}
    return latest
