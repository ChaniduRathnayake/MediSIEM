"""
Web Push notifications — reach the on-call clinician's phone/desktop.

Workstream E. The Tier 3 dispatch step in tier3_dispatch.py is the moment a
clinician needs to be paged; this module is the real notification channel
behind that step. Instead of the pending approval only being visible if
someone happens to have /clinician open, we push it out to the device of
whoever is *currently on-call* — arriving even when no tab is open.

Design notes
------------
- **Only the active on-call person buzzes.** Devices subscribe (each with a
  stable, client-generated `subscriber_id`), but a push is only sent to the
  one subscriber flagged on-call. The rotation is operational for now — the
  toggle on /clinician sets who's on-call — with a clean seam to swap in a
  real login + schedule later without touching this layer.

- **Standard Web Push (VAPID).** The sim POSTs the encrypted payload to the
  browser vendor's push service (FCM / Mozilla / etc.), which delivers it to
  the device. That means the device is reachable even off the LAN and with
  the browser closed, but it also means the *sim* needs outbound internet to
  the push service — pure air-gapped LAN delivery isn't possible with the
  web push standard. Serving the app itself stays local (mkcert HTTPS).

- **Defensive, like the rest of the sim.** If pywebpush isn't installed or
  VAPID keys aren't configured, this module degrades to a no-op that logs a
  reason — the sim still runs and the dashboard/clinician flow is unaffected.

Config (environment variables)
------------------------------
  VAPID_PUBLIC_KEY   base64url application server key (the frontend needs this)
  VAPID_PRIVATE_KEY  base64url raw private key (pywebpush signs with this)
  VAPID_SUBJECT      contact URI for the push service (default mailto:)

Generate a keypair with:  python generate_vapid.py
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pywebpush is an optional dependency — degrade gracefully if absent.
    from pywebpush import webpush, WebPushException  # type: ignore
    _PYWEBPUSH_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    webpush = None  # type: ignore
    WebPushException = Exception  # type: ignore
    _PYWEBPUSH_AVAILABLE = False


# ---------- Config ----------

VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:oncall@hospital.local").strip()

DEFAULT_STORE_PATH = Path(__file__).resolve().parent / "data" / "push_store.json"


def is_configured() -> bool:
    """True when web push can actually be sent (library + keys present)."""
    return bool(_PYWEBPUSH_AVAILABLE and VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY)


def config_status() -> Dict[str, Any]:
    """Human-readable reason string for /health and debugging."""
    if not _PYWEBPUSH_AVAILABLE:
        reason = "pywebpush not installed (pip install -r requirements.txt)"
    elif not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        reason = "VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not set (run generate_vapid.py)"
    else:
        reason = "ok"
    return {"configured": is_configured(), "reason": reason}


# ---------- Subscription + on-call store ----------

class PushStore:
    """Subscriptions keyed by subscriber_id, plus a single on-call pointer.

    Persisted as one JSON file so subscriptions and the on-call selection
    survive a sim restart (same durability philosophy as action_log.py).
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.getenv("PUSH_STORE_PATH", DEFAULT_STORE_PATH))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._subs: Dict[str, Dict[str, Any]] = {}
        self._on_call: Optional[str] = None
        self._load()

    # ----- persistence -----

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self._subs = data.get("subscriptions", {}) or {}
        self._on_call = data.get("on_call")

    def _flush(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"subscriptions": self._subs, "on_call": self._on_call}, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.path)

    # ----- writes -----

    def upsert(self, subscriber_id: str, subscription: Dict[str, Any], label: str = "") -> Dict[str, Any]:
        entry = {
            "subscriber_id": subscriber_id,
            "subscription": subscription,
            "label": label or subscriber_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._subs[subscriber_id] = entry
            self._flush()
        return entry

    def remove(self, subscriber_id: str) -> bool:
        with self._lock:
            existed = self._subs.pop(subscriber_id, None) is not None
            if self._on_call == subscriber_id:
                self._on_call = None
            self._flush()
        return existed

    def remove_by_endpoint(self, endpoint: str) -> None:
        with self._lock:
            drop = [sid for sid, e in self._subs.items()
                    if e.get("subscription", {}).get("endpoint") == endpoint]
            for sid in drop:
                self._subs.pop(sid, None)
                if self._on_call == sid:
                    self._on_call = None
            if drop:
                self._flush()

    def set_on_call(self, subscriber_id: Optional[str]) -> None:
        with self._lock:
            # Clearing, or setting to a subscriber we actually know about.
            self._on_call = subscriber_id if (subscriber_id in self._subs) else None
            if subscriber_id and subscriber_id not in self._subs:
                # Setting on-call for an unknown subscriber is a no-op we
                # surface rather than silently accept.
                pass
            self._flush()

    # ----- reads -----

    def on_call_id(self) -> Optional[str]:
        return self._on_call

    def on_call_subscription(self) -> Optional[Dict[str, Any]]:
        if not self._on_call:
            return None
        entry = self._subs.get(self._on_call)
        return entry.get("subscription") if entry else None

    def snapshot(self) -> Dict[str, Any]:
        return {
            "count": len(self._subs),
            "on_call": self._on_call,
            "subscribers": [
                {"subscriber_id": e["subscriber_id"], "label": e.get("label", ""),
                 "on_call": e["subscriber_id"] == self._on_call}
                for e in self._subs.values()
            ],
        }


_store: Optional[PushStore] = None


def get_store() -> PushStore:
    global _store
    if _store is None:
        _store = PushStore()
    return _store


# ---------- Sending ----------

def send_web_push(subscription: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Send one push. Best-effort: never raises. Prunes dead subscriptions."""
    if not is_configured():
        return {"ok": False, "skipped": True, "reason": config_status()["reason"]}
    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps(payload),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_SUBJECT},
        )
        return {"ok": True}
    except WebPushException as exc:  # type: ignore
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        # 404 / 410 mean the subscription is gone — prune it so we don't keep
        # trying to reach a device that has unsubscribed or reset.
        if status_code in (404, 410):
            get_store().remove_by_endpoint(subscription.get("endpoint", ""))
            return {"ok": False, "pruned": True, "status": status_code}
        return {"ok": False, "status": status_code, "error": str(exc)[:200]}
    except Exception as exc:  # pragma: no cover - unexpected transport errors
        return {"ok": False, "error": str(exc)[:200]}


def notify_on_call(decision: Dict[str, Any]) -> Dict[str, Any]:
    """Push a Tier 3 approval request to the active on-call device only.

    Called from server.py after the tier3_dispatch workflow runs. Returns a
    small status dict recorded in the action log for traceability.
    """
    store = get_store()
    on_call = store.on_call_id()
    if not on_call:
        return {"ok": False, "skipped": True, "reason": "no one is on-call"}
    subscription = store.on_call_subscription()
    if not subscription:
        return {"ok": False, "skipped": True, "reason": "on-call subscriber has no subscription"}

    asset_id = decision.get("asset_id", "unknown asset")
    proposed = decision.get("proposed_action_if_approved", "isolate_host")
    rationale = (decision.get("rationale") or "")[:120]
    payload = {
        "title": f"Tier 3 approval needed — {asset_id}",
        "body": rationale or f"Approve to {proposed}; deny keeps Monitored Mode.",
        "asset_id": asset_id,
        "decision_id": decision.get("decision_id", ""),
        "url": "/clinician",
        "tag": f"tier3-{asset_id}",
    }
    result = send_web_push(subscription, payload)
    result["subscriber_id"] = on_call
    return result
