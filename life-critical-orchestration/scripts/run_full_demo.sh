#!/usr/bin/env bash
#
# run_full_demo.sh — fire every sample Wazuh alert through the full pipe
# in sequence, with brief pauses so a viewer can follow along.
#
# Pipeline exercised end-to-end:
#   Wazuh JSON → enrichment shim → engine /decide
#                                  → audit log
#                                  → background push to Shuffle sim
#                                  → playbook actions logged
#   (Tier 3 only) dashboard approve/deny → Shuffle sim
#                                        → engine /clinician-decision
#                                        → audit follow-up entry
#
# Prerequisites — all three services running:
#   - Engine on :8000
#       cd engine && uvicorn src.main:app --reload --port 8000
#       (set SHUFFLE_WEBHOOK_URL=http://localhost:8002/playbook/run before
#        starting if you want the engine to push decisions to the sim)
#   - Enrichment shim on :8001
#       cd enrichment && uvicorn src.main:app --reload --port 8001
#   - Shuffle SOAR sim on :8002
#       cd playbooks/shuffle_sim && uvicorn server:app --reload --port 8002
#
# Usage (from repo root):
#   ./scripts/run_full_demo.sh
#   ./scripts/run_full_demo.sh --pause 4    # custom pause between alerts
#   ./scripts/run_full_demo.sh --no-pause   # fire everything as fast as possible
#
# What it does NOT do:
#   - Drive the dashboard (the dashboard is a viewer; you click in it manually)
#   - Approve or deny Tier 3 alerts (do that from the dashboard's clinician panel,
#     or curl the engine's /clinician-decision endpoint by hand)

set -euo pipefail

# ---------- config ----------
ENGINE_URL="${ENGINE_URL:-http://localhost:8000}"
SHIM_URL="${SHIM_URL:-http://localhost:8001}"
SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:8002}"

PAUSE_SECONDS=3
case "${1:-}" in
  --pause)
    PAUSE_SECONDS="${2:-3}"
    ;;
  --no-pause)
    PAUSE_SECONDS=0
    ;;
esac

ALERTS_DIR="data/sample-wazuh-alerts"
if [[ ! -d "$ALERTS_DIR" ]]; then
  echo "Error: $ALERTS_DIR not found. Run from the repo root." >&2
  exit 1
fi

# ---------- ANSI colours (silenced if stdout is not a TTY) ----------
if [[ -t 1 ]]; then
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'
  C_AMBER=$'\033[33m'
  C_RED=$'\033[31m'
  C_OFF=$'\033[0m'
else
  C_DIM=""; C_BOLD=""; C_CYAN=""; C_GREEN=""; C_AMBER=""; C_RED=""; C_OFF=""
fi

banner() {
  echo
  echo "${C_BOLD}${C_CYAN}=== $* ===${C_OFF}"
}

# ---------- preflight ----------

banner "PREFLIGHT — checking services"

check() {
  local name="$1" url="$2"
  if curl -sf "$url/health" > /dev/null; then
    echo "  ${C_GREEN}●${C_OFF} $name reachable at $url"
    return 0
  else
    echo "  ${C_RED}●${C_OFF} $name NOT reachable at $url"
    return 1
  fi
}

ENGINE_OK=1; SHIM_OK=1; SHUFFLE_OK=1
check "engine" "$ENGINE_URL" || ENGINE_OK=0
check "enrichment shim" "$SHIM_URL" || SHIM_OK=0
check "shuffle sim" "$SHUFFLE_URL" || SHUFFLE_OK=0

if [[ $ENGINE_OK -eq 0 || $SHIM_OK -eq 0 ]]; then
  echo
  echo "${C_RED}Engine and shim must be running. Aborting.${C_OFF}" >&2
  exit 1
fi

if [[ $SHUFFLE_OK -eq 0 ]]; then
  echo
  echo "${C_AMBER}Shuffle sim is not running.${C_OFF} The engine will still"
  echo "classify alerts and the dashboard will work, but the 'Shuffle Playbook"
  echo "Actions' panel will be empty for this demo run."
  echo
  read -rp "Continue anyway? [y/N] " ans
  [[ "$ans" =~ ^[yY] ]] || exit 1
fi

# ---------- fire each alert ----------

ALERT_FILES=()
while IFS= read -r f; do
  ALERT_FILES+=("$f")
done < <(ls -1 "$ALERTS_DIR"/*.json | sort)

if [[ ${#ALERT_FILES[@]} -eq 0 ]]; then
  echo "Error: no JSON files in $ALERTS_DIR" >&2
  exit 1
fi

banner "FIRING ${#ALERT_FILES[@]} ALERTS through the pipe"

for FILE in "${ALERT_FILES[@]}"; do
  BASENAME="$(basename "$FILE")"
  echo
  echo "${C_BOLD}→ $BASENAME${C_OFF}"

  RESPONSE=$(curl -sS -X POST "$SHIM_URL/wazuh-alert" \
    -H "Content-Type: application/json" \
    --data-binary "@$FILE")

  if command -v jq > /dev/null; then
    TIER=$(echo "$RESPONSE" | jq -r '.decision.tier // "?"')
    ACTION=$(echo "$RESPONSE" | jq -r '.decision.action // "?"')
    ASSET=$(echo "$RESPONSE" | jq -r '.enriched_alert.asset.asset_id // "?"')
    RULE=$(echo "$RESPONSE" | jq -r '.decision.matched_rule // "?"')
    FAIL_SAFE=$(echo "$RESPONSE" | jq -r '.decision.fail_safe_applied // false')

    case "$TIER" in
      1) TIER_COLOUR="$C_GREEN";;
      2) TIER_COLOUR="$C_AMBER";;
      3) TIER_COLOUR="$C_RED";;
      *) TIER_COLOUR="$C_OFF";;
    esac

    echo "  ${TIER_COLOUR}TIER $TIER${C_OFF}  ${C_CYAN}$ACTION${C_OFF}  ${C_DIM}on${C_OFF} $ASSET"
    echo "  ${C_DIM}rule:${C_OFF} $RULE"
    if [[ "$FAIL_SAFE" == "true" ]]; then
      echo "  ${C_AMBER}fail-safe applied${C_OFF}"
    fi
  else
    echo "  $RESPONSE"
  fi

  if (( PAUSE_SECONDS > 0 )); then
    sleep "$PAUSE_SECONDS"
  fi
done

# ---------- summary ----------

banner "SUMMARY"

if command -v jq > /dev/null; then
  AUDIT_COUNT=$(curl -sf "$ENGINE_URL/audit" | jq 'length')
  echo "  audit log entries (total)     : ${C_BOLD}$AUDIT_COUNT${C_OFF}"

  if [[ $SHUFFLE_OK -eq 1 ]]; then
    SHUFFLE_ACTIONS=$(curl -sf "$SHUFFLE_URL/actions?limit=1000" | jq 'length')
    echo "  shuffle action log (in-ring)  : ${C_BOLD}$SHUFFLE_ACTIONS${C_OFF}"
  fi

  CHAIN_OK=$(curl -sf "$ENGINE_URL/audit/verify" | jq -r '.ok')
  if [[ "$CHAIN_OK" == "true" ]]; then
    echo "  audit chain integrity         : ${C_GREEN}OK${C_OFF}"
  else
    echo "  audit chain integrity         : ${C_RED}BROKEN${C_OFF}"
  fi

  PENDING=$(curl -sf "$ENGINE_URL/audit" | jq '[.[] | select(.decision.action == "await_clinician_approval")] | length')
  RESOLVED=$(curl -sf "$ENGINE_URL/clinician-decisions" | jq 'length')
  echo "  pending Tier 3 (lifetime)     : ${C_BOLD}$PENDING${C_OFF}  resolved: ${C_BOLD}$RESOLVED${C_OFF}"
fi

echo
echo "${C_DIM}Tip:${C_OFF} open the dashboard at ${C_CYAN}http://localhost:5173${C_OFF}"
echo "${C_DIM}    enable Live mode (top-right) to see alerts stream in.${C_OFF}"
echo "${C_DIM}    click any Tier 3 card and use the Approve/Deny buttons${C_OFF}"
echo "${C_DIM}    to drive Phase B of the two-phase flow.${C_OFF}"
