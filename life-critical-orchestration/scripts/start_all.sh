#!/usr/bin/env bash
# Starts every life-critical-orchestration service in one shot, instead of the
# four separate terminals DEMO.md walks through by hand:
#   engine (:8000) / enrichment shim (:8001) / shuffle sim (:8002) / dashboard
#
# Usage:
#   ./scripts/start_all.sh                # all four
#   ./scripts/start_all.sh --no-frontend  # skip the standalone dashboard —
#                                         # its UI is now also ported into
#                                         # MediSIEM's own Playbooks tab, and
#                                         # MediSIEM's frontend already claims
#                                         # the default Vite port (5173)
#
# Stop everything this script started:
#   ./scripts/stop_all.sh
#
# Safe to re-run: each service is skipped (not double-started) if its health
# endpoint already responds.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LOG_DIR="$HERE/.dev-logs"
mkdir -p "$LOG_DIR"

WITH_FRONTEND=1
for arg in "$@"; do
  [ "$arg" = "--no-frontend" ] && WITH_FRONTEND=0
done

# $1 = path to a venv dir (e.g. engine/.venv). Falls back to system python if
# the venv's own interpreter is missing or broken — e.g. a venv copied from a
# teammate's machine embeds an absolute path to THEIR python.exe, which won't
# resolve here. Confirmed necessary in practice on this checkout.
resolve_python() {
  local venv_python="$1/Scripts/python.exe"
  if [ -f "$venv_python" ] && "$venv_python" --version >/dev/null 2>&1; then
    echo "$venv_python"
  else
    echo "python"
  fi
}

already_up() {
  curl -sf -m 1 "$1" >/dev/null 2>&1
}

wait_healthy() {
  # $1 = health url, $2 = human name, for the status line
  for _ in $(seq 1 30); do
    if already_up "$1"; then
      echo "✅  $2 online ($1)"
      return 0
    fi
    sleep 1
  done
  echo "⚠️  $2 did not come up within 30s — check $LOG_DIR for its log"
  return 1
}

echo "=== life-critical-orchestration: starting services ==="

# --- Decision engine (:8000) ---
if already_up "http://localhost:8000/health"; then
  echo "✅  Decision engine already running (:8000)"
else
  ENGINE_PY="$(resolve_python "$ROOT/engine/.venv")"
  (
    cd "$ROOT/engine"
    SHUFFLE_WEBHOOK_URL="http://localhost:8002/playbook/run" \
      "$ENGINE_PY" -m uvicorn src.main:app --port 8000 --reload \
      > "$LOG_DIR/engine.log" 2>&1 &
    echo $! > "$LOG_DIR/engine.pid"
  )
  wait_healthy "http://localhost:8000/health" "Decision engine"
fi

# --- Enrichment shim (:8001) ---
if already_up "http://localhost:8001/health"; then
  echo "✅  Enrichment shim already running (:8001)"
else
  ENRICH_PY="$(resolve_python "$ROOT/enrichment/.venv")"
  (
    cd "$ROOT/enrichment"
    "$ENRICH_PY" -m uvicorn src.main:app --port 8001 --reload \
      > "$LOG_DIR/enrichment.log" 2>&1 &
    echo $! > "$LOG_DIR/enrichment.pid"
  )
  wait_healthy "http://localhost:8001/health" "Enrichment shim"
fi

# --- Shuffle SOAR sim (:8002) — shares the engine's venv, per its own setenv.sh ---
if already_up "http://localhost:8002/health"; then
  echo "✅  Shuffle sim already running (:8002)"
else
  SIM_PY="$(resolve_python "$ROOT/engine/.venv")"
  # VAPID keys are per-developer and gitignored (playbooks/shuffle_sim/setenv.sh).
  # Source them if present; push notifications just stay disabled if not — the
  # sim works fine either way, this only affects Tier 3 on-call web push.
  if [ -f "$ROOT/playbooks/shuffle_sim/setenv.sh" ]; then
    eval "$(grep -E '^export (VAPID_|ENGINE_URL)=' "$ROOT/playbooks/shuffle_sim/setenv.sh" || true)"
  fi
  (
    cd "$ROOT/playbooks/shuffle_sim"
    "$SIM_PY" -m uvicorn server:app --port 8002 --reload \
      > "$LOG_DIR/shuffle_sim.log" 2>&1 &
    echo $! > "$LOG_DIR/shuffle_sim.pid"
  )
  wait_healthy "http://localhost:8002/health" "Shuffle sim"
fi

# --- Standalone dashboard (optional) ---
if [ "$WITH_FRONTEND" = "1" ]; then
  if already_up "http://localhost:5174"; then
    echo "✅  Standalone dashboard already running (:5174)"
  else
    (
      cd "$ROOT/frontend"
      npm run dev -- --port 5174 --strictPort > "$LOG_DIR/frontend.log" 2>&1 &
      echo $! > "$LOG_DIR/frontend.pid"
    )
    echo "✅  Standalone dashboard starting on :5174 (bumped from Vite's default 5173 — MediSIEM's own frontend already uses that port)"
  fi
else
  echo "○  Standalone dashboard skipped (--no-frontend) — its UI is also available in MediSIEM's own Playbooks tab"
fi

echo "=== done — logs: $LOG_DIR — stop with: ./scripts/stop_all.sh ==="
