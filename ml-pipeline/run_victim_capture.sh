#!/usr/bin/env bash
# Run on the VICTIM VM (e.g. the Ubuntu or RedHat box) during a CAAP live demo.
#
# Captures this VM's own network traffic, reconstructs the 45-column
# CICIoT2023/IoMT flow schema (live_feature_extractor.py), scores each flow
# through the real CAAP model, and indexes the result into caap-alerts on the
# Windows host's Wazuh Indexer (flow_consumer.py) — the SAME path
# backend/services/alertPipeline.js polls, so results show up on the SOC
# dashboard with a real CAS score within one poll interval (~5s).
#
# Usage:
#   sudo ./run_victim_capture.sh <iface> <windows-host-ip> [indexer-user] [indexer-pass]
#
# Find <iface> with: ip -brief link
# Find <windows-host-ip> on the Windows side with: ipconfig (use the adapter
# this VM's network is bridged/host-only to, NOT 127.0.0.1).
set -euo pipefail

IFACE="${1:?usage: sudo ./run_victim_capture.sh <iface> <windows-host-ip> [indexer-user] [indexer-pass]}"
HOST_IP="${2:?Windows host IP required — where Flask (:5001) and the Wazuh Indexer (:9200) are reachable}"
INDEXER_USER="${3:-admin}"
INDEXER_PASS="${4:?WAZUH_INDEXER_PASS required — same value as WAZUH_INDEXER_PASS in backend/.env on the host}"

if [[ "$EUID" -ne 0 ]]; then
  echo "Raw packet capture needs root — re-run with sudo." >&2
  exit 1
fi

OUT_DIR="./cicflowmeter_output"
mkdir -p "$OUT_DIR"

cd "$(dirname "$0")"

EXTRACTOR_PID=""
cleanup() {
  if [[ -n "$EXTRACTOR_PID" ]]; then
    kill "$EXTRACTOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "[1/2] starting live_feature_extractor.py on interface '$IFACE' -> $OUT_DIR ..."
python3 live_feature_extractor.py --iface "$IFACE" --out-dir "$OUT_DIR" &
EXTRACTOR_PID=$!
sleep 2
if ! kill -0 "$EXTRACTOR_PID" 2>/dev/null; then
  echo "live_feature_extractor.py exited immediately — check the interface name." >&2
  exit 1
fi

echo "[2/2] starting flow_consumer.py -> CAAP http://$HOST_IP:5001, Indexer https://$HOST_IP:9200 ..."
python3 flow_consumer.py \
  --flow-dir "$OUT_DIR" \
  --caap-url "http://$HOST_IP:5001" \
  --indexer-url "https://$HOST_IP:9200" \
  --indexer-user "$INDEXER_USER" \
  --indexer-pass "$INDEXER_PASS"
