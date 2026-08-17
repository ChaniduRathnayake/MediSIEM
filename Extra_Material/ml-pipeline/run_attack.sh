#!/usr/bin/env bash
# Run on the ATTACKER VM during a CAAP live demo, targeting the victim VM's IP
# (the machine running run_victim_capture.sh). Thin wrapper around
# attack_simulator.py — see its docstring for the full scenario list and the
# isolated-network-only warning.
#
# Usage: sudo ./run_attack.sh <victim-vm-ip> [scenario]
#   scenario: arp_spoof | port_scan | syn_flood | benign | all (default: all)
set -euo pipefail

TARGET_IP="${1:?usage: sudo ./run_attack.sh <victim-vm-ip> [scenario]}"
SCENARIO="${2:-all}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Raw socket traffic generation needs root — re-run with sudo." >&2
  exit 1
fi

cd "$(dirname "$0")"
python3 attack_simulator.py --target "$TARGET_IP" --scenario "$SCENARIO"
