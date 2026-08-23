# Multi-target version of attack_simulator.py (same folder) — instead of one
# --target at a time, sweeps EVERY VM device on the lab network through the
# same scenarios (ARP spoof / port scan / SYN flood / benign), pausing
# between targets, and saves a timestamped console log + JSON summary into
# this folder as demo/thesis evidence (same idea as
# MediSIEM_Attack_Simulation_Report.docx).
#
# Imports its attack primitives from attack_simulator.py rather than
# duplicating them — both files live in this folder together, so there's no
# portability reason to copy the code (contrast run_attack.sh, which only
# needs attack_simulator.py next to it).
#
# RUN ONLY IN AN ISOLATED LAB/VM NETWORK YOU OWN — spoofed ARP/SYN-flood/port-
# scan traffic on any other network is illegal without explicit authorization.
# Requires root/Administrator + scapy (pip install scapy).
#
# Target sources (pick one; default is the device map):
#   (default)              every real IP key in device_map.json — this repo's
#                           documented lab VM inventory
#   --device-map <path>    a different device_map.json-shaped file
#   --range <CIDR>         live ARP sweep, e.g. --range 192.168.16.0/24
#   --targets ip1,ip2,...  explicit list
#
# Usage:
#   sudo python multi_target_attack_simulator.py --scenario all
#   sudo python multi_target_attack_simulator.py --range 192.168.16.0/24 --scenario port_scan
#   sudo python multi_target_attack_simulator.py --targets 192.168.16.132,192.168.16.134

import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime

from scapy.all import ARP, Ether, srp, conf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_simulator import arp_spoof, port_scan, syn_flood, benign_traffic

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DEVICE_MAP = os.path.normpath(os.path.join(HERE, "..", "..", "ml-pipeline", "device_map.json"))
# Windows host running the Wazuh stack/Flask/backend/dashboard — DEMO_RUNBOOK.md
# is explicit: "just don't run the attack against the Windows host itself".
DEFAULT_EXCLUDE = {"192.168.16.1"}
DEFAULT_GATEWAY = "192.168.16.1"


def run_scenario(name: str, target: str, gateway: str, duration: int):
    if name == "arp_spoof":
        arp_spoof(target, gateway or DEFAULT_GATEWAY, duration)
    elif name == "port_scan":
        port_scan(target)
    elif name == "syn_flood":
        syn_flood(target)
    elif name == "benign":
        benign_traffic(target, duration)
    else:
        raise ValueError(f"unknown scenario {name!r}")


# ── Multi-target orchestration ──

def check_privileges():
    if os.name == "nt":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            sys.exit("Raw socket traffic generation needs Administrator — re-run this terminal as Administrator.")
    elif os.geteuid() != 0:
        sys.exit("Raw socket traffic generation needs root — re-run with sudo.")


def load_targets_from_device_map(path: str, exclude: set):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    targets = [ip for ip in data.keys() if not ip.startswith("_") and ip not in exclude]
    return sorted(set(targets), key=lambda ip: tuple(int(p) for p in ip.split(".")))


def discover_live_hosts(cidr: str, exclude: set, timeout: int = 3):
    net = ipaddress.ip_network(cidr, strict=False)
    print(f"[discover] ARP-sweeping {net} (timeout {timeout}s) ...")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)), timeout=timeout, verbose=False)
    hosts = {rcv.psrc for _, rcv in ans if rcv.psrc not in exclude}
    return sorted(hosts, key=lambda ip: tuple(int(p) for p in ip.split(".")))


class Tee:
    """Duplicates writes to multiple streams — lets attack_simulator-style
    print() calls land in both the live console and the saved run log."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def stamp(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="CAAP lab multi-target attack simulator — runs attack scenarios against every VM device on the lab network in turn"
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--device-map", default=None, help=f"Path to a device_map.json-shaped file (default: {DEFAULT_DEVICE_MAP})")
    src.add_argument("--range", dest="cidr", default=None, help="CIDR to ARP-sweep for live hosts instead, e.g. 192.168.16.0/24")
    src.add_argument("--targets", default=None, help="Comma-separated explicit IP list instead")
    parser.add_argument("--scenario", choices=["arp_spoof", "port_scan", "syn_flood", "benign", "all"], default="all")
    parser.add_argument("--gateway", default=None, help=f"Gateway IP to spoof for arp_spoof (default {DEFAULT_GATEWAY})")
    parser.add_argument("--duration", type=int, default=15, help="Seconds for time-based scenarios (arp_spoof/benign)")
    parser.add_argument("--target-delay", type=int, default=5, help="Seconds to pause between targets")
    parser.add_argument("--exclude", default="", help="Comma-separated IPs to skip in addition to the default host exclusion")
    parser.add_argument("--out-dir", default=HERE, help="Where to save the run log + summary (default: this folder)")
    parser.add_argument("--yes", action="store_true", help="Skip the confirmation guard on a --range sweep that finds 20+ live hosts")
    args = parser.parse_args()

    check_privileges()
    conf.verb = 0

    exclude = set(DEFAULT_EXCLUDE)
    exclude.update(x.strip() for x in args.exclude.split(",") if x.strip())

    if args.cidr:
        targets = discover_live_hosts(args.cidr, exclude)
        if len(targets) > 20 and not args.yes:
            sys.exit(
                f"[safety] {len(targets)} live hosts found on {args.cidr} — that's a lot for a lab sweep.\n"
                f"Targets: {', '.join(targets)}\n"
                "Re-run with --yes once you've confirmed this range only contains VMs you own and control."
            )
    elif args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip() and t.strip() not in exclude]
    else:
        device_map_path = args.device_map or DEFAULT_DEVICE_MAP
        if not os.path.exists(device_map_path):
            sys.exit(f"No device map at {device_map_path} — pass --device-map, --range, or --targets.")
        targets = load_targets_from_device_map(device_map_path, exclude)

    if not targets:
        sys.exit("No targets resolved — nothing to attack.")

    os.makedirs(args.out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(args.out_dir, f"demo_run_{ts}.log")
    summary_path = os.path.join(args.out_dir, f"demo_run_{ts}_summary.json")

    summary = {"started_at": datetime.now().isoformat(), "scenario": args.scenario, "targets": []}

    real_stdout = sys.stdout
    with open(log_path, "a", encoding="utf-8") as log_file:
        sys.stdout = Tee(real_stdout, log_file)
        try:
            stamp("=== CAAP multi-target attack simulator ===")
            stamp(f"Targets ({len(targets)}): {', '.join(targets)}")
            stamp(f"Scenario: {args.scenario}  Duration/scenario: {args.duration}s  Delay between targets: {args.target_delay}s")

            for i, target in enumerate(targets, 1):
                stamp(f"--- [{i}/{len(targets)}] Target {target} ---")
                entry = {"ip": target, "started_at": datetime.now().isoformat(), "status": "ok"}
                try:
                    if args.scenario == "all":
                        for name in ("benign", "port_scan", "syn_flood", "arp_spoof"):
                            stamp(f"=== Scenario: {name} -> {target} ===")
                            run_scenario(name, target, args.gateway, args.duration)
                            time.sleep(2)
                    else:
                        run_scenario(args.scenario, target, args.gateway, args.duration)
                except Exception as exc:
                    stamp(f"!!! {target} failed: {exc}")
                    entry["status"] = "error"
                    entry["error"] = str(exc)
                entry["ended_at"] = datetime.now().isoformat()
                summary["targets"].append(entry)
                if i < len(targets):
                    time.sleep(args.target_delay)

            summary["ended_at"] = datetime.now().isoformat()
            stamp("=== Run complete ===")
        finally:
            sys.stdout = real_stdout

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"Saved console log to {log_path}")
    print(f"Saved run summary to {summary_path}")


if __name__ == "__main__":
    main()
