#!/usr/bin/env bash
# Local dev convenience for the decision engine.
# GITIGNORED — do not commit.
#
# Usage, from engine/:
#     source setenv.sh
#     uvicorn src.main:app --port 8000

# Resolve this script's own dir so the venv path works regardless of cwd.
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate the engine venv (Windows / Git Bash path).
source "$_here/.venv/Scripts/activate"

# Forward decisions to the Shuffle sim so Tier 3 pages the on-call device.
export SHUFFLE_WEBHOOK_URL=http://localhost:8002/playbook/run

echo "✓ venv active + SHUFFLE_WEBHOOK_URL set — start the engine with:  uvicorn src.main:app --port 8000"
