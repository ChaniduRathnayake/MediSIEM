#!/usr/bin/env bash
#
# post_wazuh_alert.sh — fire a hand-crafted Wazuh alert through the pipe.
#
# Usage:
#   ./scripts/post_wazuh_alert.sh data/sample-wazuh-alerts/01-tier3-linac-ransomware.json
#   ./scripts/post_wazuh_alert.sh                # interactive picker if no arg
#
# Prerequisites:
#   - Decision engine running on :8000   (uvicorn engine/src.main:app --reload --port 8000)
#   - Enrichment shim running on :8001   (uvicorn enrichment/src.main:app --reload --port 8001)
#
# What it does:
#   1. POSTs the Wazuh-shape JSON to the shim's /wazuh-alert endpoint.
#   2. Shim looks up the agent in the asset registry, builds an engine v1.0
#      alert, forwards it to the engine.
#   3. Engine classifies, audit-logs, returns the Decision.
#   4. We pretty-print the round-trip so you can see tier + action + matched_rule.

set -euo pipefail

SHIM_URL="${SHIM_URL:-http://localhost:8001}"

# Pick the alert file -----------------------------------------------------
FILE="${1:-}"
if [[ -z "$FILE" ]]; then
    echo "No alert file given. Available samples:"
    ls -1 data/sample-wazuh-alerts/ 2>/dev/null || {
        echo "  (no data/sample-wazuh-alerts/ directory found — run from repo root)"
        exit 1
    }
    echo
    read -rp "Pick one (e.g. 01-tier3-linac-ransomware.json): " PICK
    FILE="data/sample-wazuh-alerts/$PICK"
fi

if [[ ! -f "$FILE" ]]; then
    echo "Error: $FILE not found." >&2
    exit 1
fi

# Health-check the shim ---------------------------------------------------
if ! curl -sf "$SHIM_URL/health" > /dev/null; then
    echo "Error: enrichment shim not reachable at $SHIM_URL" >&2
    echo "  Start it with:" >&2
    echo "    cd enrichment && uvicorn src.main:app --reload --port 8001" >&2
    exit 1
fi

# Fire the alert ----------------------------------------------------------
echo "==> POST $SHIM_URL/wazuh-alert  (payload: $FILE)"
echo

RESPONSE=$(curl -sS -X POST "$SHIM_URL/wazuh-alert" \
    -H "Content-Type: application/json" \
    --data-binary "@$FILE")

# Pretty-print with jq if available, otherwise raw JSON
if command -v jq > /dev/null; then
    echo "$RESPONSE" | jq '{
        registry_hit,
        decision: {
            tier: .decision.tier,
            action: .decision.action,
            asset: .enriched_alert.asset.asset_id,
            effective_score: .decision.effective_criticality_score,
            effective_band: .decision.effective_band,
            extreme_threat: .decision.extreme_threat,
            matched_rule: .decision.matched_rule
        }
    }'
else
    echo "$RESPONSE"
fi

echo
echo "==> Done. Audit log updated. Dashboard will reflect on next refresh."
