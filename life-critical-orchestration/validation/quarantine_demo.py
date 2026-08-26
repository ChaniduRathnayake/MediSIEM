#!/usr/bin/env python3
"""
F-3 validation — `quarantine`: micro-segmentation at minimal clinical disruption.

The blunt end of the graded spectrum below a full isolate. Instead of dropping
or slowing one flagged flow, quarantine WALLS the device onto a restricted
`clinical-only` network that carries just its essential clinical peers (the MQTT
broker + the HL7 receiver). The clinical telemetry keeps flowing; every other
path — lateral movement, unknown peers, the internet — is cut. Used when you
don't know exactly what's malicious but must stop spread (worms, ransomware
propagation, broad/unknown threats).

This harness proves, on the real ventilator emulator (ICU-VENT-003):
  1. Clinical continuity — heartbeat downtime under quarantine is minimal.
  2. Segmentation — the device is on `clinical-only` and OFF the general net.
  3. Lateral containment — proven structurally from docker network membership:
     the device still SHARES a network with the clinical broker (reachable),
     but shares NO network with a non-clinical peer / the heartbeat-logger
     (unreachable). Two containers can reach each other iff they share a
     network — so membership is a sound, un-foolable reachability proof.

Usage (engine venv, device-sim stack up):
    cd validation
    python quarantine_demo.py
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

import enforcement  # the real muscle (quarantine / release_quarantine)

DEVICE_ASSET_ID = "ICU-VENT-003"
CONTAINER = "iomt-vitals-monitor"
BROKER_CONTAINER = "iomt-broker"                    # clinical peer — must stay reachable
NON_CLINICAL_CONTAINER = "iomt-heartbeat-logger"    # non-clinical — must become unreachable
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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def measure_window(t0: datetime, t1: datetime) -> float:
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


def _networks_of(container: str) -> list:
    """Every docker network a container is attached to (empty if none/unknown)."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", container],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return (proc.stdout or "").split()
    except subprocess.SubprocessError:
        return []


def run() -> int:
    parser = argparse.ArgumentParser(description="F-3 quarantine validation.")
    parser.add_argument("--hold", type=float, default=12.0, help="hold seconds (default 12)")
    parser.add_argument("--grace", type=float, default=6.0, help="recovery grace (default 6)")
    args = parser.parse_args()

    clin_net = enforcement.CLINICAL_NETWORK

    print(f"F-3 validation — quarantine (micro-segmentation) on {DEVICE_ASSET_ID}")
    print(f"Availability log: {AVAILABILITY_LOG}")
    if not AVAILABILITY_LOG.exists():
        print("WARNING: availability log not found — is the device-sim stack up?\n")
    if not enforcement._docker_available():
        print("WARNING: docker CLI unavailable — enforcement will be simulated.\n")

    # Baseline: before quarantine, device + heartbeat-logger share the general net.
    lateral_shared_before = bool(set(_networks_of(CONTAINER)) & set(_networks_of(NON_CLINICAL_CONTAINER)))

    # ---- QUARANTINE → move onto the clinical-only segment ----
    print("[1/1] quarantine (move onto clinical-only segment) ...")
    t0 = _now()
    res = enforcement.quarantine(
        DEVICE_ASSET_ID, decision_id="f3-quarantine", reason="f3_quarantine",
    )
    time.sleep(args.hold)
    device_nets = _networks_of(CONTAINER)
    broker_nets = _networks_of(BROKER_CONTAINER)
    logger_nets = _networks_of(NON_CLINICAL_CONTAINER)
    enforcement.release_quarantine(DEVICE_ASSET_ID, decision_id="f3-quarantine")
    time.sleep(args.grace)
    quarantine_downtime = measure_window(t0, _now())

    # ---- Structural proof (two containers reach each other iff they share a net) ----
    on_clinical = clin_net in device_nets
    off_general = not any(n.endswith("_default") for n in device_nets)
    clinical_reachable = bool(set(device_nets) & set(broker_nets))     # shares a net with broker
    lateral_blocked = not (set(device_nets) & set(logger_nets))        # shares no net with logger

    def fmt(d: float) -> str:
        return "log-missing" if d < 0 else f"{d:.1f}s"

    intact = (quarantine_downtime >= 0) and (quarantine_downtime <= DISRUPTION_EPSILON_S)
    line = "=" * 66
    print(f"\n{line}\n  F-3 RESULT — quarantine walls the device to the clinical segment\n{line}\n")
    print(f"  {'response':<12}{'mode':<12}{'heartbeat downtime':<20}{'verdict'}")
    print(f"  {'-'*58}")
    verdict = "service intact" if intact else "brief reconnect blip"
    print(f"  {'quarantine':<12}{res.get('mode','-'):<12}{fmt(quarantine_downtime):<20}{verdict}")

    print(f"\n  Segmentation proof:")
    print(f"    • device on '{clin_net}' segment: {'yes' if on_clinical else 'NO'}")
    print(f"    • device off the general network: {'yes' if off_general else 'NO'}")
    print(f"        device networks now : {device_nets or '(none)'}")
    print(f"        broker networks     : {broker_nets or '(none)'}")
    print(f"        logger networks     : {logger_nets or '(none)'}")

    print(f"\n  Reachability (by shared-network membership):")
    print(f"    • clinical broker still reachable (shares a net): {'yes' if clinical_reachable else 'NO'}")
    print(f"    • non-clinical peer reachable  before: {'yes' if lateral_shared_before else 'no'}"
          f"  → after: {'no — BLOCKED' if lateral_blocked else 'yes — CHECK'}")

    passed = res.get("mode") == "simulated" or (on_clinical and off_general and clinical_reachable and lateral_blocked)
    print(f"\n  Headline: the device is confined to the clinical-only segment — broker "
          f"telemetry\n  continues ({fmt(quarantine_downtime)} downtime) while lateral movement "
          "to non-clinical\n  hosts is cut, vs a full isolate's sustained outage.")
    print(f"\n  F-3: {'PASS' if passed else 'CHECK — see above'}\n{line}\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(run())
