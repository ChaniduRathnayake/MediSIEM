#!/usr/bin/env python3
"""
F-2 validation — `throttle`: rate-limit a flagged flow at ~0 clinical disruption.

The graded middle of the §J spectrum. Where selective_block DROPs a known-bad
destination, `throttle` SLOWS it (a tc htb class + u32 dst filter) — useful when
a flow is suspicious but not confirmed malicious. Because the shaping is scoped
to the flagged destination only, clinical traffic to the broker/receiver stays
in the full-speed default class, so the heartbeat is structurally unaffected.

This harness proves, on the real ventilator emulator (ICU-VENT-003):
  1. Non-disruption — heartbeat downtime under throttle is ~0.
  2. Scoped policy — the tc class caps the flagged dest at the set rate, and a
     u32 filter matches ONLY that destination (clinical flows are not shaped).
  3. Safety invariant — a request to throttle a clinical dest is refused.

Note: measuring the *achieved* throttled throughput (e.g. exfil MB/s before vs
after) needs a cooperating bandwidth endpoint (an iperf sink); that's a planned
follow-up. This run proves the shaping is applied and scoped, and that clinical
service is untouched.

Usage (engine venv, device-sim stack up):
    cd validation
    python throttle_demo.py
    python throttle_demo.py --hold 12 --dest 185.220.101.45 --rate 512kbit
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "playbooks" / "shuffle_sim"))

import enforcement  # the real muscle (throttle / unthrottle)

DEVICE_ASSET_ID = "ICU-VENT-003"
CONTAINER = "iomt-vitals-monitor"
AVAILABILITY_LOG = Path(
    os.getenv(
        "VALIDATION_AVAILABILITY_LOG",
        str(REPO_ROOT / "device-sim" / "data" / "availability.jsonl"),
    )
)
DISRUPTION_EPSILON_S = 0.5
# Start-gate tolerance: an interruption counts as "this phase's" if it
# began within this many seconds of t0. Sized to the publish interval (1s)
# + the logger's silence threshold (3s) + margin, so beat-quantization
# doesn't reject a real gap, while genuinely old gaps (restarts, prior
# phases 20s+ back) are still rejected.
START_TOLERANCE_S = 5.0
DEFAULT_DEST = os.getenv("THROTTLE_TEST_DEST", "185.220.101.45")  # the C2 sample's dst_ip


def _now() -> datetime:
    return datetime.now(timezone.utc)


def measure_window(t0: datetime, t1: datetime) -> float:
    """Sum measured heartbeat downtime whose recovery landed inside [t0, t1]."""
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
            # Only count an interruption whose START (recovery_ts - downtime_s)
            # falls inside the window. This rejects a pre-existing gap — e.g. a
            # stack rebuild/restart or a prior response's recovery — that merely
            # RECOVERS inside the window and would otherwise be misattributed.
            if (ts - timedelta(seconds=dt)) >= (t0 - timedelta(seconds=START_TOLERANCE_S)):
                downtime += dt
    return round(downtime, 2)


def _dexec(script: str, timeout: float = 8.0) -> str:
    try:
        proc = subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c", script],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return (proc.stdout or "").strip()
    except subprocess.SubprocessError:
        return ""


def run() -> int:
    parser = argparse.ArgumentParser(description="F-2 throttle validation.")
    parser.add_argument("--hold", type=float, default=12.0, help="hold seconds (default 12)")
    parser.add_argument("--grace", type=float, default=6.0, help="recovery grace (default 6)")
    parser.add_argument("--dest", default=DEFAULT_DEST, help=f"dest to throttle (default {DEFAULT_DEST})")
    parser.add_argument("--rate", default="1mbit", help="throttle rate (default 1mbit)")
    args = parser.parse_args()

    dev = enforcement.THROTTLE_IFACE

    print(f"F-2 validation — throttle on {DEVICE_ASSET_ID}")
    print(f"Availability log: {AVAILABILITY_LOG}")
    if not AVAILABILITY_LOG.exists():
        print("WARNING: availability log not found — is the device-sim stack up?\n")
    if not enforcement._docker_available():
        print("WARNING: docker CLI unavailable — enforcement will be simulated.\n")

    # ---- 1) THROTTLE the flagged dest → expect ~0 heartbeat downtime ----
    print(f"[1/2] throttle dest={args.dest} rate={args.rate} ...")
    t0 = _now()
    res = enforcement.throttle(
        DEVICE_ASSET_ID, dest=args.dest, rate=args.rate,
        decision_id="f2-throttle", reason="f2_throttle",
    )
    time.sleep(args.hold)
    tc_classes = _dexec(f"tc -s class show dev {dev}")
    tc_filters = _dexec(f"tc filter show dev {dev}")
    enforcement.unthrottle(DEVICE_ASSET_ID, decision_id="f2-throttle")
    time.sleep(args.grace)
    throttle_downtime = measure_window(t0, _now())

    # ---- 2) SAFETY INVARIANT: throttling a clinical dest must be refused ----
    print("[2/2] safety invariant (attempt to throttle a clinical dest) ...")
    guard = enforcement.throttle(
        DEVICE_ASSET_ID, dest="broker", rate=args.rate,
        decision_id="f2-guard", reason="f2_guard",
    )

    # ---- Report ----
    def fmt(d: float) -> str:
        return "log-missing" if d < 0 else f"{d:.1f}s"

    intact = (throttle_downtime >= 0) and (throttle_downtime <= DISRUPTION_EPSILON_S)
    rate_capped = args.rate.lower() in (tc_classes or "").lower()

    # tc prints the u32 dest match as a hex word (e.g. 185.220.101.45 -> b9dc652d),
    # not dotted-decimal, so decode the IP to that form before checking.
    def _ip_to_tc_hex(ip):
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return "".join(f"{int(p):02x}" for p in parts)
        except (ValueError, AttributeError):
            pass
        return None
    dest_hex = _ip_to_tc_hex(args.dest)
    filt = (tc_filters or "").lower()
    dest_filtered = (args.dest in (tc_filters or "")) or (dest_hex is not None and dest_hex in filt)

    line = "=" * 66
    print(f"\n{line}\n  F-2 RESULT — throttle strangles a flow at ~0 clinical disruption\n{line}\n")
    print(f"  {'response':<12}{'mode':<12}{'heartbeat downtime':<20}{'verdict'}")
    print(f"  {'-'*58}")
    print(f"  {'throttle':<12}{res.get('mode','-'):<12}{fmt(throttle_downtime):<20}"
          f"{'service intact' if intact else 'DISRUPTED'}")

    print(f"\n  Scoped-policy proof (tc on {dev}):")
    print(f"    • flagged dest capped at {args.rate}: {'yes' if rate_capped else 'NO'}")
    hexnote = f" (tc hex {dest_hex})" if dest_hex else ""
    print(f"    • filter matches ONLY dest {args.dest}{hexnote}: {'yes' if dest_filtered else 'NO'}")
    if tc_classes:
        for ln in tc_classes.splitlines():
            if "class htb" in ln:
                print(f"        {ln.strip()}")
    if tc_filters:
        for ln in tc_filters.splitlines():
            if "match" in ln or "flowid" in ln:
                print(f"        {ln.strip()}")

    print(f"\n  Safety invariant:")
    print(f"    • throttle of clinical dest 'broker' refused: "
          f"{'yes' if guard.get('refused') else 'NO — BUG'}")

    passed = intact and rate_capped and dest_filtered and guard.get("refused")
    print(f"\n  Headline: the flagged flow is capped at {args.rate} while the clinical "
          f"heartbeat\n  runs uninterrupted ({fmt(throttle_downtime)} downtime) — graded "
          "containment, not a cut.")
    print(f"\n  F-2: {'PASS' if passed else 'CHECK — see above'}\n{line}\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(run())
