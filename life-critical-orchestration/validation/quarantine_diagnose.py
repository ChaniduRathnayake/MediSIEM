#!/usr/bin/env python3
"""
F-3 diagnosis — WHY does quarantine cost clinical downtime?

Hypothesis: connect-before-disconnect is correct at the docker layer, but when
the device leaves the general network its live MQTT socket dies, and on reconnect
it resolves `broker` to a STALE / general-network IP that isn't routable from the
clinical-only segment -> it cannot reconnect until release moves it back.

This probe times, from INSIDE the device, across the quarantine window:
  * what IP `broker` resolves to (vs broker's real IP on clinical-only)
  * whether a TCP connect to broker:1883 succeeds
so we can see exactly when/why clinical telemetry drops.

Run (engine venv, device-sim stack up):
    cd validation
    python quarantine_diagnose.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "playbooks" / "shuffle_sim"))

import enforcement  # quarantine / release_quarantine

DEVICE = "ICU-VENT-003"
CONTAINER = "iomt-vitals-monitor"
BROKER = "iomt-broker"
CLINICAL_NET = enforcement.CLINICAL_NETWORK


def _sh(args, timeout=8):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.SubprocessError as e:
        return "", str(e)


def broker_ip_on(net):
    out, _ = _sh([
        "docker", "inspect", "-f",
        "{{with index .NetworkSettings.Networks \"" + net + "\"}}{{.IPAddress}}{{end}}",
        BROKER,
    ])
    return out or "-"


def probe_from_device():
    """From inside the device: resolve broker, then TCP-connect broker:1883."""
    code = (
        "import socket\n"
        "try:\n"
        "    ip=socket.gethostbyname('broker')\n"
        "except Exception as e:\n"
        "    ip='RESOLVE_FAIL:%s'%e\n"
        "try:\n"
        "    s=socket.create_connection(('broker',1883),2); s.close(); tcp='OK'\n"
        "except Exception as e:\n"
        "    tcp='FAIL:%s'%type(e).__name__\n"
        "print(ip+'|'+tcp)\n"
    )
    out, err = _sh(["docker", "exec", CONTAINER, "python", "-c", code], timeout=8)
    return out or ("err:" + err)


def device_nets():
    return " ".join(enforcement._list_networks(CONTAINER)) or "-"


def main():
    if not enforcement._docker_available():
        print("docker unavailable — start the device-sim stack first.")
        return 1

    print(f"F-3 DIAGNOSIS — quarantine reconnect on {DEVICE}\n")
    print(f"clinical network : {CLINICAL_NET}")
    print(f"broker IP (general): {broker_ip_on(enforcement.DEFAULT_NETWORK)}")
    print(f"device nets (pre) : {device_nets()}")
    print(f"[baseline] device->broker: {probe_from_device()}\n")

    print(">> quarantine ...")
    enforcement.quarantine(DEVICE, decision_id="diag", reason="diag")
    print(f"broker IP (clinical): {broker_ip_on(CLINICAL_NET)}")
    print(f"device nets (post): {device_nets()}\n")

    print("  t(s)  device-resolves-broker | tcp:1883")
    print("  " + "-" * 52)
    t_start = time.time()
    for _ in range(9):  # ~18s of observation
        t = time.time() - t_start
        print(f"  {t:4.0f}  {probe_from_device()}")
        time.sleep(2)

    print("\n>> release_quarantine ...")
    enforcement.release_quarantine(DEVICE, decision_id="diag")
    time.sleep(2)
    print(f"device nets (final): {device_nets()}")
    print(f"[final] device->broker: {probe_from_device()}")

    print("\nRead: if resolve returns the general-net IP (or RESOLVE_FAIL) and tcp")
    print("FAILs while quarantined, the device is stuck on a stale broker address —")
    print("that's the reconnect gap. If resolve returns the clinical IP and tcp OKs,")
    print("the drop is pure MQTT reconnect-backoff instead.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
