#!/usr/bin/env bash
# Run on the ATTACKER VM during a CAAP live demo — sweeps every VM device on
# the lab network instead of a single target. Thin wrapper around
# multi_target_attack_simulator.py; see its docstring for target sources,
# the scenario list, and the isolated-network-only warning.
#
# Usage:
#   sudo ./run_multi_attack.sh                            # every device in device_map.json, scenario=all
#   sudo ./run_multi_attack.sh --range 192.168.16.0/24     # live ARP sweep
#   sudo ./run_multi_attack.sh --targets 192.168.16.132,192.168.16.134 --scenario port_scan
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Raw socket traffic generation needs root — re-run with sudo." >&2
  exit 1
fi

cd "$(dirname "$0")"
python3 multi_target_attack_simulator.py "$@"
