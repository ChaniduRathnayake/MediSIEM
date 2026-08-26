// ClinicianView — the real, human-in-the-loop approval interface.
//
// This is the PP2 replacement for the SOC-operator stub that used to live
// inline in the dashboard (ClinicianDecisionPanel). It is a standalone
// route (served at /clinician) rather than a panel embedded in the SOC
// console, because a clinician is not a SOC analyst: they need a small,
// mobile-friendly screen that answers one question — "is anything waiting
// on me right now?" — with tap targets big enough to use one-handed, on a
// ward, in a hurry.
//
// It talks to the exact same engine endpoints the SOC dashboard uses
// (GET /audit, GET /clinician-decisions, and submitClinicianDecision, which
// posts to the Shuffle sim's /clinician-decision so approval triggers the
// *real* enforcement action — see playbooks/shuffle_sim/enforcement.py).
// No new backend surface was needed for this view.
//
// Safety-relevant note: approving here is no longer symbolic. On
// ICU-VENT-003 it performs a real `docker network disconnect` on the
// device container. Denying leaves the asset in Monitored Mode (FR-06) —
// nothing happens, which is deliberately the lower-friction action here.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  checkHealth,
  getAuditLog,
  getClinicianDecisions,
  submitClinicianDecision,
} from "../api/engine";
import {
  disablePush,
  enablePush,
  getOnCall,
  getPushConfig,
  getSubscriberId,
  pushSupported,
  sendTestPush,
  setOnCall,
} from "../api/push";

const POLL_INTERVAL_MS = 3000;
const RESOLVED_DISPLAY_MS = 15000; // how long a resolved card stays visible before it drops off
const PAGE_TITLE = "Clinician Approvals";

// --- In-page alert cues: chime + tab-title flash ---
// Fully local — no push service, no OS notification, no internet needed. This
// is what grabs attention when the console is open; the Web Push notification
// is the complementary "reaches you when the tab is closed" path. A short
// synthesized two-tone chime avoids shipping an audio asset. Browser autoplay
// policy requires a user gesture before audio can play, so unlockAlertAudio()
// is called from the on-call / enable taps (both are gestures).
let _alertAudioCtx = null;

function unlockAlertAudio() {
  try {
    if (!_alertAudioCtx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (AC) _alertAudioCtx = new AC();
    }
    if (_alertAudioCtx && _alertAudioCtx.state === "suspended") {
      _alertAudioCtx.resume();
    }
  } catch {
    /* audio not available — cues degrade to the visual flash only */
  }
}

function playChime() {
  unlockAlertAudio(); // make sure a context exists / is resuming
  const ctx = _alertAudioCtx;
  if (!ctx) return;
  const emit = () => {
    const now = ctx.currentTime;
    // Two ascending notes — an "attention" ping, not an alarm.
    [880, 1174.66].forEach((freq, i) => {
      const t = now + i * 0.18;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(0.35, t + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.22);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + 0.24);
    });
  };
  // Resume can be async right after a gesture; play once it's running.
  if (ctx.state === "running") emit();
  else ctx.resume().then(emit).catch(() => {});
}

function formatWaiting(decidedAt) {
  if (!decidedAt) return "";
  const ms = Date.now() - new Date(decidedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "";
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  if (mins > 0) return `waiting ${mins}m ${secs}s`;
  return `waiting ${secs}s`;
}

function StatusDot({ status }) {
  const color =
    status === "online" ? "bg-tier-1" : status === "offline" ? "bg-tier-3" : "bg-soc-muted";
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
}

// A pending request, awaiting a tap.
function PendingCard({ item, onDecide, busyId }) {
  const busy = busyId === item.decision_id;
  return (
    <div className="border border-tier-3 bg-soc-panel rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-mono font-bold text-soc-text text-base">
            {item.asset_id}
          </div>
          <div className="text-soc-muted text-xs mt-0.5">
            {formatWaiting(item.decided_at)}
          </div>
        </div>
        <span className="shrink-0 text-[10px] uppercase tracking-wider font-bold text-tier-3 border border-tier-3 rounded px-2 py-0.5">
          Tier 3
        </span>
      </div>

      <p className="text-soc-text text-sm leading-relaxed">{item.rationale}</p>

      <div className="text-xs text-soc-muted">
        If approved →{" "}
        <span className="font-mono text-soc-accent">
          {item.proposed_action_if_approved || "isolate_host"}
        </span>
        . This will disconnect the device from its network.
      </div>

      <div className="grid grid-cols-2 gap-3 pt-1">
        <button
          type="button"
          disabled={busy}
          onClick={() => onDecide(item, false)}
          className="py-4 rounded-lg border-2 border-tier-1 text-tier-1 bg-tier-1/5 font-bold uppercase tracking-wide text-sm active:bg-tier-1/20 disabled:opacity-40"
        >
          Deny
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => onDecide(item, true)}
          className="py-4 rounded-lg border-2 border-tier-3 text-tier-3 bg-tier-3/5 font-bold uppercase tracking-wide text-sm active:bg-tier-3/20 disabled:opacity-40"
        >
          Approve
        </button>
      </div>
      {busy && (
        <p className="text-center text-soc-muted text-xs">recording your decision…</p>
      )}
    </div>
  );
}

// A just-resolved request, showing what actually happened (real vs
// simulated enforcement), so the clinician gets confirmation rather than
// a button that silently vanishes.
function ResolvedCard({ item }) {
  const approved = item.approved;
  const enf = item.enforcement;
  return (
    <div
      className={[
        "rounded-lg p-4 border",
        approved ? "border-tier-3 bg-tier-3/5" : "border-tier-1 bg-tier-1/5",
      ].join(" ")}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono font-bold text-soc-text">{item.asset_id}</span>
        <span
          className={[
            "text-[10px] uppercase tracking-wider font-bold px-2 py-0.5 rounded border",
            approved ? "text-tier-3 border-tier-3" : "text-tier-1 border-tier-1",
          ].join(" ")}
        >
          {approved ? "Approved" : "Denied"}
        </span>
      </div>
      {approved && enf && (
        <p className="text-soc-muted text-xs mt-2">
          {enf.mode === "real"
            ? "Device isolated at the network boundary — telemetry stream stopped."
            : "Isolation recorded (simulated — no live device bound)."}
        </p>
      )}
      {!approved && (
        <p className="text-soc-muted text-xs mt-2">
          Asset stays in Monitored Mode. No action taken.
        </p>
      )}
    </div>
  );
}

// Notifications + on-call control. Subscribing registers this device to
// receive Web Push; the on-call toggle decides whether *this* device is the
// one that actually gets paged — only the active on-call device buzzes.
function NotificationsControl() {
  const mySubscriberId = getSubscriberId();
  const supported = pushSupported();
  const [subscribedHere, setSubscribedHere] = useState(false);
  const [serverConfigured, setServerConfigured] = useState(null); // null = unknown
  const [snapshot, setSnapshot] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [testMsg, setTestMsg] = useState(null);

  const mineOnCall = snapshot?.on_call === mySubscriberId;
  const someoneElseOnCall = snapshot?.on_call && snapshot.on_call !== mySubscriberId;
  const otherLabel =
    someoneElseOnCall &&
    (snapshot.subscribers?.find((s) => s.subscriber_id === snapshot.on_call)?.label ||
      snapshot.on_call);

  const refresh = useCallback(async () => {
    const snap = await getOnCall();
    if (snap) setSnapshot(snap);
  }, []);

  useEffect(() => {
    if (!supported) return undefined;
    let alive = true;
    (async () => {
      try {
        const cfg = await getPushConfig();
        if (alive) setServerConfigured(!!cfg.configured);
      } catch {
        if (alive) setServerConfigured(false);
      }
      try {
        const reg = await navigator.serviceWorker.getRegistration();
        const sub = reg && (await reg.pushManager.getSubscription());
        if (alive) setSubscribedHere(!!sub && Notification.permission === "granted");
      } catch {
        /* ignore */
      }
      refresh();
    })();
    const id = setInterval(refresh, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [supported, refresh]);

  async function handleEnable() {
    unlockAlertAudio(); // this tap is a user gesture — unlock the chime
    setBusy(true);
    setErr(null);
    try {
      await enablePush();
      setSubscribedHere(true);
      await refresh();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleToggleOnCall() {
    unlockAlertAudio(); // user gesture — unlock the chime for later alerts
    setBusy(true);
    setErr(null);
    setTestMsg(null);
    try {
      if (mineOnCall) {
        await setOnCall(null); // step down — nobody on-call
      } else {
        if (!subscribedHere) {
          await enablePush(); // subscribing is a prerequisite for being paged
          setSubscribedHere(true);
        }
        await setOnCall(mySubscriberId); // take over on-call
      }
      await refresh();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleTest() {
    unlockAlertAudio();
    playChime(); // immediate local sound — this click is a user gesture
    setBusy(true);
    setErr(null);
    setTestMsg(null);
    try {
      const r = await sendTestPush();
      setTestMsg(
        r.ok ? "Chime played + test push sent — watch for the toast." : `Push not sent: ${r.reason || r.error || "unavailable"}`
      );
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleDisable() {
    setBusy(true);
    setErr(null);
    try {
      await disablePush();
      setSubscribedHere(false);
      await refresh();
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!supported) {
    return (
      <div className="border border-soc-border bg-soc-panel rounded-lg p-3 text-xs text-soc-muted">
        This browser can’t receive push notifications. On iPhone, add this page to
        the Home Screen first, then reopen it.
      </div>
    );
  }

  return (
    <div className="border border-soc-border bg-soc-panel rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-[10px] uppercase tracking-wider text-soc-muted">Notifications</h2>
        {subscribedHere && (
          <span className="text-[10px] text-tier-1 uppercase tracking-wider">
            this device subscribed ✓
          </span>
        )}
      </div>

      {serverConfigured === false && (
        <p className="text-tier-2 text-xs">
          Push isn’t configured on the server yet — set the VAPID keys and restart the sim.
        </p>
      )}

      {/* On-call toggle — the headline control. Only the on-call device buzzes. */}
      <button
        type="button"
        disabled={busy}
        onClick={handleToggleOnCall}
        className={[
          "w-full py-4 rounded-lg font-bold uppercase tracking-wide text-sm border-2 disabled:opacity-40",
          mineOnCall
            ? "border-tier-1 text-tier-1 bg-tier-1/10 active:bg-tier-1/20"
            : "border-soc-accent text-soc-accent bg-soc-accent/5 active:bg-soc-accent/15",
        ].join(" ")}
      >
        {mineOnCall ? "You are ON-CALL — tap to step down" : "Go on-call on this device"}
      </button>

      <p className="text-xs text-soc-muted">
        {mineOnCall
          ? "Tier 3 approvals will buzz this device."
          : someoneElseOnCall
          ? `Currently on-call: ${otherLabel}. Going on-call here takes over.`
          : "No one is on-call — approvals won’t page anyone until someone goes on-call."}
      </p>

      <div className="flex items-center gap-3 text-xs">
        {!subscribedHere && (
          <button
            type="button"
            disabled={busy}
            onClick={handleEnable}
            className="text-soc-accent underline disabled:opacity-40"
          >
            Enable on this device
          </button>
        )}
        {subscribedHere && (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={handleTest}
              className="text-soc-accent underline disabled:opacity-40"
            >
              Send test
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={handleDisable}
              className="text-soc-muted underline disabled:opacity-40"
            >
              Unsubscribe
            </button>
          </>
        )}
      </div>

      {testMsg && <p className="text-xs text-soc-muted">{testMsg}</p>}
      {err && (
        <p className="text-tier-3 text-xs border border-tier-3 rounded px-2 py-1 bg-tier-3/10">
          {err}
        </p>
      )}
    </div>
  );
}

export default function ClinicianView() {
  const [engineStatus, setEngineStatus] = useState("checking");
  const [pending, setPending] = useState([]);
  const [resolved, setResolved] = useState([]); // [{...decision fields, approved, enforcement, resolvedAt}]
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState(null);

  const reload = useCallback(async () => {
    try {
      const [log, resolutions] = await Promise.all([
        getAuditLog(),
        getClinicianDecisions().catch(() => ({})),
      ]);

      const resolutionByAsset = new Map();
      for (const r of Object.values(resolutions || {})) {
        if (!r?.asset_id) continue;
        const prior = resolutionByAsset.get(r.asset_id);
        if (!prior || (r.responded_at || "") > (prior.responded_at || "")) {
          resolutionByAsset.set(r.asset_id, r);
        }
      }

      const awaiting = log
        .map((entry) => entry.decision || entry)
        .filter((d) => d.action === "await_clinician_approval")
        .filter((d) => !resolutionByAsset.has(d.asset_id));

      // Dedupe by asset, keep the most recent request per asset.
      const byAsset = new Map();
      for (const d of awaiting) byAsset.set(d.asset_id, d);
      const dedupedPending = Array.from(byAsset.values()).sort(
        (a, b) => new Date(b.decided_at) - new Date(a.decided_at)
      );

      setPending(dedupedPending);
      setError(null);
    } catch (err) {
      setError(err.message || String(err));
    }
  }, []);

  useEffect(() => {
    checkHealth()
      .then(() => setEngineStatus("online"))
      .catch(() => setEngineStatus("offline"));
    reload();
    const id = setInterval(() => {
      checkHealth()
        .then(() => setEngineStatus("online"))
        .catch(() => setEngineStatus("offline"));
      reload();
    }, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [reload]);

  // Drop resolved cards off the screen after a while so the view doesn't
  // accumulate confirmations forever during a long shift.
  useEffect(() => {
    if (resolved.length === 0) return undefined;
    const id = setTimeout(() => {
      setResolved((prev) => prev.filter((r) => Date.now() - r.resolvedAt < RESOLVED_DISPLAY_MS));
    }, 1000);
    return () => clearTimeout(id);
  }, [resolved]);

  // Chime once per new approval, but only while the tab is actually visible —
  // browsers suspend audio in hidden/background tabs, so a timer-driven chime
  // can't play there (only a direct click like "Send test" can). If a request
  // lands while the tab is backgrounded, the flashing title + OS toast cover
  // it, and the chime fires the moment the clinician switches back to the tab.
  const chimedIds = useRef(new Set());
  useEffect(() => {
    const ackAndChime = () => {
      if (document.visibilityState !== "visible") return;
      const hasUnchimed = pending.some((p) => !chimedIds.current.has(p.decision_id));
      // Forget ids that are no longer pending, so a resolved-then-refired
      // asset chimes again next time.
      chimedIds.current = new Set(
        pending.map((p) => p.decision_id).filter((id) => chimedIds.current.has(id))
      );
      if (hasUnchimed) {
        for (const p of pending) chimedIds.current.add(p.decision_id);
        playChime();
      }
    };
    ackAndChime();
    document.addEventListener("visibilitychange", ackAndChime);
    return () => document.removeEventListener("visibilitychange", ackAndChime);
  }, [pending]);

  // Flash the tab title while anything is waiting, so a backgrounded tab still
  // signals "something needs you". Restores the moment the queue clears.
  useEffect(() => {
    if (pending.length === 0) {
      document.title = PAGE_TITLE;
      return undefined;
    }
    let on = false;
    const id = setInterval(() => {
      on = !on;
      document.title = on
        ? `🔴 (${pending.length}) approval${pending.length > 1 ? "s" : ""} waiting`
        : PAGE_TITLE;
    }, 1000);
    return () => {
      clearInterval(id);
      document.title = PAGE_TITLE;
    };
  }, [pending.length]);

  // Autoplay policy: audio can't start until the user interacts. Unlock on the
  // first tap/click anywhere, in case the clinician never touches the toggle.
  useEffect(() => {
    const unlock = () => unlockAlertAudio();
    window.addEventListener("pointerdown", unlock, { once: true });
    return () => window.removeEventListener("pointerdown", unlock);
  }, []);

  async function handleDecide(item, approved) {
    setBusyId(item.decision_id);
    setError(null);
    // Optimistically pull it out of the pending list so a double-tap can't
    // fire twice while the request is in flight.
    setPending((prev) => prev.filter((p) => p.decision_id !== item.decision_id));
    try {
      const result = await submitClinicianDecision({
        decisionId: item.decision_id,
        assetId: item.asset_id,
        approved,
      });
      setResolved((prev) => [
        {
          decision_id: item.decision_id,
          asset_id: item.asset_id,
          approved,
          enforcement: result?.enforcement || null,
          resolvedAt: Date.now(),
        },
        ...prev,
      ]);
    } catch (err) {
      setError(err.message || String(err));
      // Put it back so the clinician can retry.
      setPending((prev) => [item, ...prev]);
    } finally {
      setBusyId(null);
      reload();
    }
  }

  return (
    <div className="min-h-screen bg-soc-bg font-mono text-soc-text">
      <header className="border-b border-soc-border bg-soc-panel px-4 py-3 flex items-center justify-between sticky top-0 z-10">
        <div>
          <h1 className="text-soc-accent text-base font-bold leading-tight">
            Clinician Approvals
          </h1>
          <span className="text-soc-muted text-[10px]">R26-CS-008 • PP2</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <StatusDot status={engineStatus} />
          <span className="text-soc-muted uppercase">{engineStatus}</span>
        </div>
      </header>

      <main className="max-w-md mx-auto px-4 py-4 space-y-4">
        <NotificationsControl />

        {error && (
          <p className="text-tier-3 text-xs border border-tier-3 rounded px-3 py-2 bg-tier-3/10">
            {error}
          </p>
        )}

        {engineStatus === "offline" && (
          <p className="text-soc-muted text-sm text-center py-8">
            Engine unreachable. Nothing to show until it's back online.
          </p>
        )}

        {engineStatus !== "offline" && pending.length === 0 && resolved.length === 0 && (
          <p className="text-soc-muted text-sm text-center py-12">
            Nothing waiting on you right now.
          </p>
        )}

        {pending.length > 0 && (
          <div className="space-y-3">
            <h2 className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-soc-muted">
              <span className="inline-block w-2 h-2 rounded-full bg-tier-3 animate-pulse" />
              Awaiting your decision ({pending.length})
            </h2>
            {pending.map((item) => (
              <PendingCard
                key={item.decision_id}
                item={item}
                onDecide={handleDecide}
                busyId={busyId}
              />
            ))}
          </div>
        )}

        {resolved.length > 0 && (
          <div className="space-y-2">
            <h2 className="text-[10px] uppercase tracking-wider text-soc-muted">
              Just now
            </h2>
            {resolved.map((r) => (
              <ResolvedCard key={`${r.decision_id}-${r.resolvedAt}`} item={r} />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
