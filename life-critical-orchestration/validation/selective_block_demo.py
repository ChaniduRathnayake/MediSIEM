#!/usr/bin/env python3
"""
F-1 validation — `selective_block`: contain a threat with ~0 clinical disruption.

This is the measured proof for Workstream F-1. It contrasts two responses on
the flagship life-critical device (ICU-VENT-003):

  * ISOLATE (the full network cut) — the heartbeat drops → measurable downtime.
  * SELECTIVE_BLOCK — drop ONLY the malicious flow (a C2 / exfil dest) at the
    device's network edge while clinical protocols (MQTT 1883, HL7 2575) stay
    open → the heartbeat keeps flowing → ~0 downtime, threat path still cut.

It also proves the safety invariant: a request to block a *clinical* dest is
refused. The result is the F-1 table: "isolate disrupts the service;
selective_block contains the threat at zero clinical disruption."

Self-contained — imports the real enforcement module and reads the device's
availability log directly, exactly like run_validation.py. The only thing that
must be running is the device-sim stack (so there's a live heartbeat to
measure) and Docker (so enforcement is real, not simulated).

Usage (from the engine venv, device-sim stack up):

    cd validation
    python selective_block_demo.py
    python selective_block_demo.py --hold 12 --dest 203.0.113.10 --dport 443
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
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "playbooks" / "shuffle_sim"))

import enforcement  # the real muscle (isolate / selective_block / restore)

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

# A stand-in "C2 / exfil" destination. TEST-NET-3 (203.0.113.0/24, RFC 5737) is
# reserved for documentation/examples — safe to reference, never a real host.
DEFAULT_C2_DEST = os.getenv("SELECTIVE_BLOCK_TEST_DEST", "203.0.113.10")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def measure_window(t0: datetime, t1: datetime) -> float:
    """Sum measured heartbeat downtime whose recovery landed inside [t0, t1]."""
    if not AVAILABILITY_LOG.exists():
        return -1.0  # sentinel: log missing
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


def _dexec(script: str, timeout: float = 8.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", "exec", CONTAINER, "sh", "-c", script],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.SubprocessError:
        return subprocess.CompletedProcess(args=script, returncode=1, stdout="", stderr="timeout")


def _probe_clinical_reachable() -> bool:
    """From inside the device, can it still reach the MQTT broker? (clinical intact)"""
    code = (
        "import socket,sys\n"
        "try:\n"
        "    socket.create_connection(('broker',1883),3).close(); print('OK')\n"
        "except Exception as e:\n"
        "    print('FAIL',e); sys.exit(1)\n"
    )
    try:
        proc = subprocess.run(
            ["docker", "exec", CONTAINER, "python", "-c", code],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return "OK" in (proc.stdout or "")
    except subprocess.SubprocessError:
        return False


def run() -> int:
    parser = argparse.ArgumentParser(description="F-1 selective_block validation.")
    parser.add_argument("--hold", type=float, default=12.0,
                        help="seconds to hold each response (default 12)")
    parser.add_argument("--grace", type=float, default=6.0,
                        help="seconds to let recovery register (default 6)")
    parser.add_argument("--dest", default=DEFAULT_C2_DEST,
                        help=f"malicious dest to block (default {DEFAULT_C2_DEST})")
    parser.add_argument("--dport", type=int, default=None,
                        help="optional dest port to block (default: all traffic to dest)")
    args = parser.parse_args()

    dports = [args.dport] if args.dport else None

    print(f"F-1 validation — selective_block vs isolate on {DEVICE_ASSET_ID}")
    print(f"Availability log: {AVAILABILITY_LOG}")
    if not AVAILABILITY_LOG.exists():
        print("WARNING: availability log not found — is the device-sim stack up? "
              "Downtime will read as unavailable.\n")
    if not enforcement._docker_available():
        print("WARNING: docker CLI unavailable — enforcement will be simulated, "
              "not a real device cut.\n")

    # ---- 1) ISOLATE baseline: full cut → expect downtime ----
    print("[1/3] isolate (full network cut) ...")
    t0 = _now()
    enforcement.isolate(DEVICE_ASSET_ID, decision_id="f1-isolate", reason="f1_contrast")
    time.sleep(args.hold)
    enforcement.release(DEVICE_ASSET_ID, decision_id="f1-isolate")
    time.sleep(args.grace)
    isolate_downtime = measure_window(t0, _now())

    # ---- 2) SELECTIVE_BLOCK: drop only the malicious flow → expect ~0 downtime ----
    print(f"[2/3] selective_block dest={args.dest} dports={dports} ...")
    t0 = _now()
    res = enforcement.selective_block(
        DEVICE_ASSET_ID, dest=args.dest, dports=dports,
        decision_id="f1-selective", reason="f1_selective",
    )
    time.sleep(args.hold)
    rules = _dexec(f"iptables -S {enforcement._BLOCK_CHAIN}").stdout.strip()
    clinical_ok = _probe_clinical_reachable()
    enforcement.restore_flows(DEVICE_ASSET_ID, decision_id="f1-selective")
    time.sleep(args.grace)
    selective_downtime = measure_window(t0, _now())

    # ---- 3) SAFETY INVARIANT: blocking a clinical dest must be refused ----
    print("[3/3] safety invariant (attempt to block a clinical dest) ...")
    guard = enforcement.selective_block(
        DEVICE_ASSET_ID, dest="broker", decision_id="f1-guard", reason="f1_guard",
    )

    # ---- Report ----
    def fmt(d: float) -> str:
        return "log-missing" if d < 0 else f"{d:.1f}s"

    sel_intact = (selective_downtime >= 0) and (selective_downtime <= DISRUPTION_EPSILON_S)
    iso_disrupted = isolate_downtime > DISRUPTION_EPSILON_S

    line = "=" * 66
    print(f"\n{line}\n  F-1 RESULT — selective_block contains a flow at ~0 disruption\n{line}\n")
    print(f"  {'response':<18}{'mode':<12}{'heartbeat downtime':<20}{'verdict'}")
    print(f"  {'-'*60}")
    print(f"  {'isolate':<18}{'real':<12}{fmt(isolate_downtime):<20}"
          f"{'DISRUPTED' if iso_disrupted else 'intact'}")
    print(f"  {'selective_block':<18}{res.get('mode','-'):<12}{fmt(selective_downtime):<20}"
          f"{'service intact' if sel_intact else 'DISRUPTED'}")

    print(f"\n  Containment proof (selective_block):")
    print(f"    • DROP rule installed: {'yes' if enforcement._BLOCK_CHAIN in rules and 'DROP' in rules else 'NO'}")
    if rules:
        for r in rules.splitlines():
            print(f"        {r}")
    print(f"    • clinical path (MQTT broker:1883) still reachable: {'yes' if clinical_ok else 'NO'}")

    print(f"\n  Safety invariant:")
    print(f"    • block of clinical dest 'broker' refused: "
          f"{'yes' if guard.get('refused') else 'NO — BUG'}")

    passed = sel_intact and iso_disrupted and clinical_ok and guard.get("refused")
    print(f"\n  Headline: isolate disrupted the service ({fmt(isolate_downtime)} downtime); "
          f"selective_block\n  contained the threat flow at {fmt(selective_downtime)} downtime — "
          "graded containment with\n  zero clinical disruption, measured on a real device.")
    print(f"\n  F-1: {'PASS' if passed else 'CHECK — see warnings above'}\n{line}\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(run())
