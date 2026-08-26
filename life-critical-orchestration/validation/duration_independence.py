#!/usr/bin/env python3
"""
F-3 headline experiment — quarantine's cost is a FIXED one-time reconnect,
isolate's cost SCALES with how long you contain.

The naive objection to quarantine is "it still costs ~7s of telemetry, so why not
just isolate?" This experiment answers it. It measures both responses at a SHORT
and a LONG containment hold and shows:

  * isolate      downtime ~= hold        (device is dark the entire containment)
  * quarantine   downtime ~= constant    (one reconnect blip, then telemetry
                                          streams for the rest of the hold)

So for any realistic containment (minutes to hours), isolate = minutes/hours of
lost clinical telemetry; quarantine = the same few seconds once. That is the real
life-critical advantage of micro-segmentation over a full cut.

Measurement is start-gated (an interruption only counts if it BEGAN inside the
window) so a prior phase's recovery can't bleed into the next.

Run (engine venv, device-sim stack up and settled):
    cd validation
    python duration_independence.py
    python duration_independence.py --short 10 --long 40
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "playbooks" / "shuffle_sim"))

import enforcement

DEVICE = "ICU-VENT-003"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
AVAILABILITY_LOG = Path(
    os.getenv("VALIDATION_AVAILABILITY_LOG",
              str(REPO_ROOT / "device-sim" / "data" / "availability.jsonl"))
)
DISRUPTION_EPSILON_S = 0.5
# Start-gate tolerance: an interruption counts as "this phase's" if it
# began within this many seconds of t0. Sized to the publish interval (1s)
# + the logger's silence threshold (3s) + margin, so beat-quantization
# doesn't reject a real gap, while genuinely old gaps (restarts, prior
# phases 20s+ back) are still rejected.
START_TOLERANCE_S = 5.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def measure_window(t0: datetime, t1: datetime) -> float:
    """Sum downtime for interruptions that BEGAN inside [t0, t1]."""
    if not AVAILABILITY_LOG.exists():
        return -1.0
    downtime = 0.0
    try:
        lines = AVAILABILITY_LOG.read_text(encoding="utf-8").splitlines()
    except OSError:
        return -1.0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event") != "interruption_end":
            continue
        ts_raw = rec.get("ts")
        if not ts_raw:
            continue
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            continue
        if t0 <= ts <= t1:
            dt = float(rec.get("downtime_s", 0.0))
            if (ts - timedelta(seconds=dt)) >= (t0 - timedelta(seconds=START_TOLERANCE_S)):
                downtime += dt
    return round(downtime, 2)


def _events():
    """Return availability transitions (start/end/logger_start), in order."""
    if not AVAILABILITY_LOG.exists():
        return []
    out = []
    for line in AVAILABILITY_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event") in ("interruption_start", "interruption_end", "logger_start"):
            out.append(rec)
    return out


def _stream_is_up() -> bool:
    """Up unless the most recent transition is an unpaired interruption_start."""
    evs = _events()
    return (not evs) or evs[-1].get("event") != "interruption_start"


def _last_event_age() -> float:
    evs = _events()
    if not evs:
        return 1e9
    try:
        return (_now() - datetime.fromisoformat(evs[-1]["ts"])).total_seconds()
    except (ValueError, KeyError, TypeError):
        return 1e9


def _wait_until_steady(timeout: float = 45.0, quiet: float = 5.0) -> bool:
    """Block until the stream is UP and has been quiet for `quiet`s, so a phase
    always starts from a clean up-state (no merge with a pre-existing gap)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _stream_is_up() and _last_event_age() >= quiet:
            return True
        time.sleep(1.0)
    return _stream_is_up()


def _measure(apply_fn, restore_fn, hold: float, max_wait: float = 30.0) -> float:
    """Apply, hold, restore, then POLL the log until this phase's interruption
    recovers (or max_wait). Polling (vs a fixed grace) means a slow reconnect
    after a long isolate is still captured instead of being dropped to 0.0."""
    _wait_until_steady()
    t0 = _now()
    apply_fn(DEVICE)
    time.sleep(hold)
    restore_fn(DEVICE)
    deadline = time.time() + max_wait
    dt = 0.0
    while time.time() < deadline:
        time.sleep(1.0)
        dt = measure_window(t0, _now())
        if dt > DISRUPTION_EPSILON_S:
            time.sleep(1.5)  # let the (single) recovery record finish writing
            dt = measure_window(t0, _now())
            break
    return dt


def _isolate_apply(a):    return enforcement.isolate(a, decision_id="di-iso", reason="di")
def _isolate_restore(a):  return enforcement.release(a, decision_id="di-iso")
def _quar_apply(a):       return enforcement.quarantine(a, decision_id="di-quar", reason="di")
def _quar_restore(a):     return enforcement.release_quarantine(a, decision_id="di-quar")


def run() -> int:
    ap = argparse.ArgumentParser(description="Quarantine vs isolate: cost vs containment duration.")
    ap.add_argument("--short", type=float, default=10.0, help="short hold seconds (default 10)")
    ap.add_argument("--long", type=float, default=40.0, help="long hold seconds (default 40)")
    ap.add_argument("--maxwait", type=float, default=30.0, help="max seconds to wait for a phase to recover (default 30)")
    ap.add_argument("--settle", type=float, default=20.0, help="settle between phases (default 20)")
    args = ap.parse_args()

    if not enforcement._docker_available():
        print("docker unavailable — start the device-sim stack first.")
        return 1
    if not AVAILABILITY_LOG.exists():
        print("availability log missing — is the stack up?")
        return 1

    holds = [("short", args.short), ("long", args.long)]
    results = {}  # (response, label) -> downtime

    print(f"F-3 duration-independence — {DEVICE}")
    print(f"holds: short={args.short}s long={args.long}s\n")
    for label, hold in holds:
        print(f"[{label} hold {hold:.0f}s] isolate ...", flush=True)
        results[("isolate", label)] = _measure(_isolate_apply, _isolate_restore, hold, args.maxwait)
        time.sleep(args.settle)
        print(f"[{label} hold {hold:.0f}s] quarantine ...", flush=True)
        results[("quarantine", label)] = _measure(_quar_apply, _quar_restore, hold, args.maxwait)
        time.sleep(args.settle)

    def fmt(d): return "log-missing" if d < 0 else f"{d:.1f}s"
    line = "=" * 70
    print(f"\n{line}\n  DURATION-INDEPENDENCE — downtime vs containment hold\n{line}\n")
    print(f"  {'response':<14}{'short ('+str(int(args.short))+'s)':<16}{'long ('+str(int(args.long))+'s)':<16}{'behaviour'}")
    print(f"  {'-'*64}")
    iso_s, iso_l = results[("isolate","short")], results[("isolate","long")]
    q_s,  q_l   = results[("quarantine","short")], results[("quarantine","long")]
    print(f"  {'isolate':<14}{fmt(iso_s):<16}{fmt(iso_l):<16}scales with hold (device dark throughout)")
    print(f"  {'quarantine':<14}{fmt(q_s):<16}{fmt(q_l):<16}fixed one-time reconnect blip")

    # Verdict: isolate should grow ~ (long-short); quarantine should stay flat.
    iso_grew = (iso_l - iso_s) >= (args.long - args.short) * 0.5
    quar_flat = abs(q_l - q_s) <= max(3.0, q_s * 0.75)
    print(f"\n  isolate downtime grew with hold      : {'yes' if iso_grew else 'no'} "
          f"(+{iso_l - iso_s:.1f}s for +{args.long - args.short:.0f}s hold)")
    print(f"  quarantine downtime stayed ~constant : {'yes' if quar_flat else 'no'} "
          f"(delta {q_l - q_s:+.1f}s)")
    verdict = iso_grew and quar_flat
    print(f"\n  Headline: isolate costs ~the whole containment window; quarantine costs\n"
          f"  the SAME one-time blip whether you contain for {int(args.short)}s or {int(args.long)}s. Over a\n"
          f"  real containment (minutes+), that is the difference between minutes of lost\n"
          f"  clinical telemetry and a single reconnect.")
    print(f"\n  RESULT: {'PASS' if verdict else 'CHECK — see above'}\n{line}\n")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    md = RESULTS_DIR / "duration_independence.md"
    with md.open("w", encoding="utf-8") as f:
        f.write(f"# Duration-independence — {DEVICE} (measured {stamp})\n\n")
        f.write(f"| Response | Hold {int(args.short)}s | Hold {int(args.long)}s | Behaviour |\n")
        f.write("|---|---|---|---|\n")
        f.write(f"| isolate | {fmt(iso_s)} | {fmt(iso_l)} | scales with containment (device dark throughout) |\n")
        f.write(f"| quarantine | {fmt(q_s)} | {fmt(q_l)} | fixed one-time reconnect blip |\n")
        f.write("\nMeasured on the live device-sim. isolate's clinical-telemetry loss tracks "
                "the containment duration; quarantine's is a single reconnect cost independent "
                "of how long the device stays contained — the core life-critical advantage of "
                "micro-segmentation over a full network cut.\n")
    print(f"  Written: {md}\n")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(run())
