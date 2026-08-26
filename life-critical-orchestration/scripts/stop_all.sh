#!/usr/bin/env bash
# Stops everything start_all.sh started, using the PIDs it recorded.
# Safe to re-run — already-stopped services are just reported as such.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$HERE/.dev-logs"

for name in engine enrichment shuffle_sim frontend; do
  pid_file="$LOG_DIR/$name.pid"
  if [ ! -f "$pid_file" ]; then
    echo "○  No PID recorded for $name (already stopped, or started outside start_all.sh)"
    continue
  fi
  pid="$(cat "$pid_file")"
  # taskkill //T also kills uvicorn's --reload child watcher process, which a
  # plain `kill` on just the parent PID leaves orphaned on Windows.
  if taskkill //PID "$pid" //T //F >/dev/null 2>&1; then
    echo "✅  Stopped $name (pid $pid)"
  else
    echo "○  $name (pid $pid) was not running"
  fi
  rm -f "$pid_file"
done
